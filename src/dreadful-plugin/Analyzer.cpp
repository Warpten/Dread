#include "Analyzer.hpp"
#include "Dread/CRC/Engine.hpp"
#include "Dread/Reflection/ReflInfo.hpp"
#include "Dread/Utilities.hpp"

// dreadful-plugin-clang-base
#include <AST/Explorer.hpp>
#include <AST/Matchers.hpp>

// dreadful-plugin-ida-base
#include <IDA/API/Function.hpp>
#include <IDA/API.hpp>
#include <Utils/Exporter.hpp>

#include <hexrays.hpp>

// std
#include <cmath>
#include <span>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <vector>

// clang
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchersInternal.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Tooling/Tooling.h>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::ast_matchers::internal;

namespace {
    template <typename T>
    void ExecuteOne(ASTContext& context, Matcher<T> const& matcher, AST::Explorer::Callback&& action) {
        AST::Explorer explorer(context);
        explorer.AddMatcher(matcher, std::move(action));
        explorer.Run(clang::TK_IgnoreUnlessSpelledInSource);
    }
}

auto extractOffset(clang::AnnotateAttr* attribute) -> uint64_t {
    if (attribute == nullptr)
        return 0uLL;

	llvm::StringRef annotation{ attribute->getAnnotation() };
	if (!annotation.startswith("0x"))
		return 0uLL;

	uint64_t offsetValue = 0uLL;
	auto [ptr, ec] = std::from_chars(annotation.data() + 2, annotation.data() + annotation.size(), offsetValue, 16);
	if (ec != std::errc{})
		return 0uLL;

	return offsetValue;
};

auto extractOffset(const clang::Decl* decl) -> uint64_t {
	if (decl == nullptr)
		return 0uLL;

	return extractOffset(decl->getAttr<clang::AnnotateAttr>());
}

template <typename T>
auto Analyzer::Analyze(clang::ASTContext& context, const IDA::API::Function& functionInfo) -> T* {
    // Extract all callers. If there is more than one (or none), discard this function.
    std::vector<ea_t> callers = functionInfo.GetReferencesTo(XREF_FAR);
    if (callers.size() != 1)
        return nullptr;

    auto targetDecl = functionDecl(hasName(functionInfo.GetName()));
    auto scopeQuery = forFunction(targetDecl);

    auto optionallyCastExpr = [](llvm::StringRef const& bindName, auto&& query) {
        return anyOf(query, castExpr(query).bind(bindName));
    };

    auto propertyAssignmentQuery = traverse(TK_IgnoreUnlessSpelledInSource,
        binaryOperator(scopeQuery, hasOperatorName("="), hasOperands(
            unaryOperator(hasOperatorName("*"), hasUnaryOperand(
                optionallyCastExpr("castProp",
                    ignoringParens(
                        binaryOperator(hasOperatorName("+"), hasOperands(
                            optionallyCastExpr("castDeclRef", anyOf(
                                declRefExpr().bind("declRef"),
                                unaryOperator(hasOperatorName("&"), hasUnaryOperand(
                                    declRefExpr().bind("declRef")
                                ))
                            )),
                            integerLiteral().bind("offset")
                        ))
                    )
                )
            )),
            anyOf(
                custom_matchers::ignoringAnyConstruct(declRefExpr(to(varDecl().bind("value")))),
                ignoringParenCasts(integerLiteral().bind("value"))
            )
        ))
    );

    std::unique_ptr<T> storeInstance{ new (std::nothrow) T() };
    if (storeInstance == nullptr)
        return nullptr;

    namespace Types = Dread::Reflection::Types;

    // Step 1. Parse the constructor itself
    //      1.A. Find the vtable assignment. This query in particular will only match
    //           if the 'this' value got inlined in the call: https://i.imgur.com/YktoGSg.png
    ExecuteOne(context, traverse(TK_IgnoreUnlessSpelledInSource,
        binaryOperator(scopeQuery, hasOperatorName("="), hasOperands(
            declRefExpr(to(varDecl().bind("baseAddress"))),
            ignoringParenCasts(
                unaryOperator(hasOperatorName("&"), hasUnaryOperand(
                    declRefExpr(to(varDecl(hasAttr(attr::Annotate)).bind("vtable")))
                ))
            )
        )
    )), [&](const MatchFinder::MatchResult& result) {
        auto base = result.Nodes.getNodeAs<VarDecl>("baseAddress");
        auto vtable = result.Nodes.getNodeAs<VarDecl>("vtable");

        auto baseAddress = extractOffset(base);
        auto vtableAddress = extractOffset(vtable);

        if (!IDA::API::IsFunction(vtableAddress))
            return;

        storeInstance->ProcessProperty(0, PropertySemanticKind::RVA, vtableAddress);
        if (baseAddress != 0uLL)
            storeInstance->BaseAddress = baseAddress;
    });

    // 1.B. Look for all property assignments
    //      There are multiple possible syntaxes
    //      *(T*)((U*)&qword_ABCDEF + n) = ...; -- T* and U* casts are optional
    //      *(T*)((U*)a1 + n) = ...;
    //      LODWORD(qword_00005) = ...; // Macro expanded by clang, we don't need to bother!
    //      qword_000001 = ...; -- This syntax is only valid if we found an inlined base type
    ExecuteOne(context, traverse(TK_IgnoreUnlessSpelledInSource,
        binaryOperator(scopeQuery, hasOperatorName("="), hasOperands(
            anyOf(
                // *(T*)((U*)&qword_7101D02AF8 + N) = v7;
                // *(T*)((U*)a1 + N) = ...;
                unaryOperator(hasOperatorName("*"), hasUnaryOperand(
                    optionallyCastExpr("propCastExpr",
                        binaryOperator(
                            anyOf(
                                hasOperatorName("+"),
                                hasOperatorName("-"),
                            ),
                            hasOperands(
                                optionallyCastExpr("ofsCastExpr",
                                    anyOf(
                                        // &qword_7101D02AF8
                                        unaryOperator(hasOperatorName("&"), hasUnaryOperand(
                                            declRefExpr(to(varDecl().bind("valueOffset")))
                                        )),
                                        // local variable
                                        declRefExpr(
                                            to(varDecl().bind("valueOffset")),
                                            // Optionally negative indexed
                                            optionally(
                                                hasInitializer(
                                                    binaryOperator(hasOperatorName("+"), hasOperands(
                                                        declRefExpr(to(varDecl())),
                                                        integerLiteral().bind("shiftedOffset")
                                                    ))
                                                )
                                            )
                                        )
                                    )
                                ),
                                integerLiteral().bind("offset")
                            )
                        ).bind("binaryOperator")
                    )
                )),
                // qword_00001 = ...;
                // LODWORD(qword_000001) = ...;
                optionallyCastExpr("propCastExpr", 
                    declRefExpr(to(varDecl().bind("valueOffset")))
                ),
            ),
            anyOf(
                custom_matchers::ignoringAnyConstruct(
                    declRefExpr(to(varDecl(hasAttr(attr::Annotate)).bind("value")))
                ),
                ignoringParenCasts(integerLiteral().bind("value"))
            )
        )), [&](const MatchFinder::MatchResult& result) {
            auto valueOffset = result.Nodes.getNodeAs<Decl>("valueOffset");
            auto relativeOffset = result.Nodes.getNodeAs<IntegerLiteral>("offset");
            auto propCastExpr = result.Nodes.getNodeAs<ExplicitCastExpr>("propCastExpr");
            auto ofsCastExpr = result.Nodes.getNodeAs<ExplicitCastExpr>("ofsCastExpr");
            auto shiftedOffset = result.Nodes.getNodeAs<IntegerLiteral>("shiftedOffset");
            auto binaryOperator = result.Nodes.getNodeAs<BinaryOperator>("binaryOperator");

            size_t calculatedOffset = 0; //< In bytes

            if (valueOffset == nullptr) {
                calculatedOffset = relativeOffset->getValue().getZExtValue();
                if (propCastExpr != nullptr)
                    calculatedOffset *= context.getTypeInfo(ofsCastExpr->getTypeAsWritten()).Width / 8;
                else
                    calculatedOffset *= sizeof(uint64_t);
            } else if (storeInstance->BaseAddress != 0) {
                calculatedOffset = extractOffset(valueOffset) - storeInstance->BaseAddress;
            }

            // Make sure this is working
            if (binaryOperator->getOpcode() == BinaryOperator::Opcode::BO_Add) {
                if (shiftedOffset != nullptr)
                    calculatedOffset += shiftedOffset->getValue().getZExtValue();
            }
            else if (binaryOperator->getOpcode() == BinaryOperator::Opcode::BO_Sub) {
                assert(shiftedOffset != nullptr);
                calculatedOffset = shiftedOffset->getValue().getZExtValue() - calculatedOffset;
            }

            // Should never happen, but just for safekeeping
            if (calculatedOffset == 0)
                return;

            if (auto integerLit = result.Nodes.getNodeAs<IntegerLiteral>("value")) {
                auto valueTypeInfo = [&]() -> std::optional<TypeInfo> {
                    if (propCastExpr == nullptr)
                        return std::nullopt;

                    return context.getTypeInfo(propCastExpr->getTypeAsWritten());
                }();
                auto rawValue = integerLit->getValue();

                // TODO: Check if my sleep deprived brain messed up endianness here.

                size_t bitCount = valueTypeInfo.has_value()
                    ? valueTypeInfo->Width
                    : 64;

                size_t segmentWidth = valueTypeInfo->has_value()
                    ? std::min(valueTypeInfo->Width, 64)
                    : 64;

                for (size_t bitIndex = 0; bitIndex < bitCount; bitIndex += segmentWidth) {
                    size_t partValue = rawValue.extractBitsAsZExtValue(
                        std::min(segmentWidth, bitCount - bitIndex),
                        bitIndex
                    );

                    auto byteOffset = (bitCount - bitIndex) / segmentWidth - 1;

                    storeInstance->ProcessProperty(
                        calculatedOffset + byteOffset,
                        PropertySemanticKind::IntegerLiteral,
                        partValue
                    );
                }
            } else if (auto rvaLit = result.Nodes.getNodeAs<Decl>("value")) {
                storeInstance->ProcessProperty(calculatedOffset, PropertySemanticKind::RVA, extractOffset(rvaLit));
            }
        }
    );

    // Step 2. Parse the constructor call.
    IDA::API::Function callerFunctionInfo { callers.front() };
    std::string callerPseudocode = GetPseudocode(callerFunctionInfo);
    ParsePseudoCode([&](ASTContext& context) {
        ExecuteOne(context,
            storeInstance->MakeConstructorQuery(targetDecl),
            [&](const MatchFinder::MatchResult& result) {
                storeInstance->ProcessConstructorQuery(result);
            }
        );
    }, callerPseudocode);

    // Release ownership of the pointer so it can be encapsulated.
    return storeInstance.release();
}

// Explicitely instanciate the templates for the compiler.
template Dread::Reflection::CType::Store* 
    Analyzer::Analyze<Dread::Reflection::CType::Store>(clang::ASTContext&, const IDA::API::Function&);

auto Analyzer::Identify(IDA::API::Function const& functionInfo) -> Dread::Reflection::CType::Store* {
    std::string assembledPseudocode = GetPseudocode(functionInfo);

    auto scopeQuery = forFunction(hasName(functionInfo.GetName()));

    return ParsePseudoCode([&](clang::ASTContext& context) {
        Dread::Reflection::CType::Store* dynTypedStore = nullptr;

        ExecuteOne(context, callExpr(
            scopeQuery,
            custom_matchers::crcCallExpr(),
            hasArgument(0, traverse(TK_IgnoreUnlessSpelledInSource, stringLiteral().bind("stringLiteral")))
        ),
        [&](const MatchFinder::MatchResult& result) {
            auto stringLiteral = result.Nodes.getNodeAs<clang::StringLiteral>("stringLiteral");

            static constexpr Dread::CRC::DefaultEngine checksumEngine;
            switch (checksumEngine(stringLiteral->getString())) {
                case checksumEngine("bool"):
                case checksumEngine("float"):
                case checksumEngine("double"):
                    // ^^^ Unverified / Verified vvv
                case checksumEngine("unsigned char"):
                case checksumEngine("unsigned short"):
                case checksumEngine("unsigned long"):
                case checksumEngine("unsigned long long"):
                    // ^^^ Unsure if this should be a fallthrough
                    [[fallthrough]];
                case checksumEngine(Dread::Reflection::CType::Name):
                    dynTypedStore = Analyze<Dread::Reflection::CType::Store>(context, functionInfo);
                    break;
                case checksumEngine(Dread::Reflection::CEnumType::Name):
                    dynTypedStore = Analyze<Dread::Reflection::CEnumType::Store>(context, functionInfo);
                    break;
                case checksumEngine(Dread::Reflection::CFlagsetType::Name):
                    dynTypedStore = Analyze<Dread::Reflection::CFlagsetType::Store>(context, functionInfo);
                    break;
                case checksumEngine(Dread::Reflection::CPointerType::Name):
                    dynTypedStore = Analyze<Dread::Reflection::CPointerType::Store>(context, functionInfo);
                    break;
                case checksumEngine(Dread::Reflection::CCollectionType::Name):
                    dynTypedStore = Analyze<Dread::Reflection::CCollectionType::Store>(context, functionInfo);
                    break;
                case checksumEngine(Dread::Reflection::CClass::Name):
                    dynTypedStore = Analyze<Dread::Reflection::CClass::Store>(context, functionInfo);
                    break;
                default:
                    IDA::API::Message("(Dread) Unknown reflection object type '{}' found at {:016x}", 
                        std::string_view{ stringLiteral->getString() }, functionInfo.GetAddress());
                    break;
            }
        });

        return dynTypedStore;
    }, assembledPseudocode);
}

// -------------------------------------------------------

std::string Analyzer::GetPseudocode(const IDA::API::Function& functionInfo) const {
    std::stringstream strm;
    Utils::Exporter exporter(strm);
    exporter.Run(functionInfo, [](tinfo_t& argType) {
        argType = tinfo_t{ BTF_UINT64 };
    });

    return strm.str();
}

template <typename... Ts>
uint64_t SelectFirstOffset(const Decl* arg, Ts&&... args) {
    uint64_t value = extractOffset(arg);
    if (value != 0)
        return value;

    if constexpr (sizeof...(Ts) == 0)
        return 0uLL;
    else
        return SelectFirstOffset(std::forward<Ts&&>(args)...);
}

void Analyzer::HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) {
#if _DEBUG
    llvm::SmallVector<char, 128> Message;
    info.FormatDiagnostic(Message);

    IDA::API::Message("(Dread) {}.\n", std::string_view{ Message.data(), Message.size() });
#endif
}
