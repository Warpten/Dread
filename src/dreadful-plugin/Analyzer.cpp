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

    // Step 1. Parse the constructor itself.
    // 1.A. Main parse query
    ExecuteOne(context, propertyAssignmentQuery, [&](const MatchFinder::MatchResult& result) {
        auto offset = result.Nodes.getNodeAs<IntegerLiteral>("offset");
        auto declRef = result.Nodes.getNodeAs<DeclRefExpr>("declRef");
        auto castDeclRef = result.Nodes.getNodeAs<CStyleCastExpr>("castDeclRef");
        auto castProp = result.Nodes.getNodeAs<CStyleCastExpr>("castProp");

        auto instanceAttr = declRef->getDecl()->getAttr<AnnotateAttr>();
        // if (instanceAttr != nullptr && storeInstance->Instance == 0)
        //     storeInstance->Instance = extractOffset(instanceAttr);

        uint64_t propertyOffset = offset->getValue().getLimitedValue(std::numeric_limits<uint64_t>::max());
        if (castDeclRef != nullptr)
            propertyOffset *= context.getTypeInfo(castDeclRef->getTypeAsWritten()).Width / 8;
        else
            propertyOffset *= sizeof(uint64_t);

        if (auto integerLit = result.Nodes.getNodeAs<IntegerLiteral>("value")) {
            // If the target type of the cast expression is provided, retrieve the value limited to it;
            // otherwise, it's going to be uint64 (because the argument itself is uint64).
            uint64_t maxValue = std::numeric_limits<uint64_t>::max();

            if (castProp != nullptr) {
                uint64_t typeWidth = context.getTypeInfo(castProp->getTypeAsWritten()).Width;

                // Special handling for 128 bits values; split as 2x64.
                if (typeWidth == 128) {
                    // Note: endianness of the Switch is little endian
                    uint64_t loPart = integerLit->getValue().extractBitsAsZExtValue(64, 0);
                    uint64_t hiPart = integerLit->getValue().extractBitsAsZExtValue(64, 64);

                    storeInstance->ProcessProperty(propertyOffset,
                        Types::PropertySemanticKind::IntegerLiteral, hiPart);
                    storeInstance->ProcessProperty(propertyOffset + sizeof(uint64_t),
                        Types::PropertySemanticKind::IntegerLiteral, loPart);

                    return;
                }

                // 1 << 64 would overflow, thankfully the default value is alread ULLONG_MAX
                if (typeWidth < 64)
                    maxValue = (1uLL << typeWidth) - 1;
            }

            storeInstance->ProcessProperty(propertyOffset,
                Types::PropertySemanticKind::IntegerLiteral,
                integerLit->getValue().getLimitedValue(maxValue)
            );
        }
        else if (auto valueVarDecl = result.Nodes.getNodeAs<VarDecl>("value")) {
            auto annotationAttribute = valueVarDecl->getAttr<clang::AnnotateAttr>();
            if (annotationAttribute == nullptr)
                return;

            storeInstance->ProcessProperty(propertyOffset,
                Types::PropertySemanticKind::RVA,
                extractOffset(annotationAttribute)
            );
        }
    });

    // 1.B. Some will be negative indexed
    //      TODO: Find them, identify the type of the variable, identify the shifted offset, and recalculate the value

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
