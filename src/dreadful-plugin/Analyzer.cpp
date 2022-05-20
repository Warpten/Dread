#include "Analyzer.hpp"

// dreadful-ast-parser
#include <AST/Explorer.hpp>

// dreadful-plugin-ida-base
#include <IDA/API/Function.hpp>
#include <IDA/API.hpp>
#include <Utils/Exporter.hpp>

#include <hexrays.hpp>

// std
#include <span>
#include <type_traits>
#include <unordered_map>
#include <vector>

// clang
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchersInternal.h>
#include <clang/Tooling/Tooling.h>

using namespace clang;
namespace matchers = clang::ast_matchers;

auto extractOffset(clang::AnnotateAttr* attribute) -> uint64_t {
	llvm::StringRef annotation{ attribute->getAnnotation() };
	if (!annotation.startswith("0x"))
		return 0uLL;

	uint64_t offsetValue = 0uLL;
	auto [ptr, ec] = std::from_chars(annotation.data() + 2, annotation.data() + annotation.size(), offsetValue, 16);
	if (ec != std::errc{})
		return 0uLL;

	return offsetValue;
};

const matchers::internal::VariadicDynCastAllOfMatcher<clang::Expr, clang::RecoveryExpr> recoveryExpr;

auto Analyzer::ProcessReflectionObjectConstruction(IDA::API::Function const& functionInfo)
    -> ReflInfo
{
	std::string assembledPseudocode = [&] {
		std::stringstream strm;
		Utils::Exporter exporter(strm);
		exporter.Run(functionInfo, [](tinfo_t& argType) {
			argType = tinfo_t{ BTF_VOID };
        });

		return strm.str();
	}();

    return ParsePseudoCode([this, &functionInfo](clang::ASTContext& context) -> ReflInfo {
        return this->ProcessReflectionObjectConstruction(context, functionInfo);
    }, assembledPseudocode);
}

auto Analyzer::ProcessReflectionObjectConstruction(clang::ASTContext& context, IDA::API::Function const& functionInfo)
    -> ReflInfo
{
	ReflInfo reflInfo;
    // Scope query segment to limit results to the function being decompiled
    //   Probably overkill, but just in case plugins/defs.h does wonky stuff.
	auto scopeQuery = matchers::forFunction(matchers::hasName(functionInfo.GetName()));
    AST::Explorer matchFinder(context);
    matchFinder.AddMatcher(
        matchers::callExpr(
            scopeQuery,
            matchers::hasArgument(0, matchers::hasDescendant(matchers::stringLiteral().bind("stringLiteral"))),
            matchers::hasArgument(1, matchers::hasDescendant(matchers::integerLiteral().bind("integerLiteral")))
        ),
        [&](const matchers::MatchFinder::MatchResult& result) {
            auto stringLiteral = result.Nodes.getNodeAs<clang::StringLiteral>("stringLiteral");
            auto integerLiteral = result.Nodes.getNodeAs<clang::IntegerLiteral>("integerLiteral");

            if (stringLiteral->getByteLength() != integerLiteral->getValue())
                return;

            reflInfo.Name = stringLiteral->getBytes();
        }
    );

    //< Handle vtable assignment.
    matchFinder.AddMatcher(
        matchers::binaryOperator(
            scopeQuery,
            matchers::hasOperatorName("="),
            matchers::hasOperands(
                matchers::declRefExpr().bind("this"),
                matchers::cStyleCastExpr(matchers::hasSourceExpression(
                    matchers::unaryOperator(matchers::declRefExpr().bind("declRef"))
                ))
            )
        ),
        [&](const matchers::MatchFinder::MatchResult& result) {
            auto instance = result.Nodes.getNodeAs<clang::DeclRefExpr>("this");
            auto declRef = result.Nodes.getNodeAs<clang::DeclRefExpr>("declRef");

            const clang::ValueDecl* instanceDeclaration = declRef->getDecl();
            if (clang::AnnotateAttr* annotationAttribute = instanceDeclaration->getAttr<clang::AnnotateAttr>())
                reflInfo.Self = extractOffset(annotationAttribute);

            const clang::ValueDecl* vtableDeclaration = declRef->getDecl();
            if (clang::AnnotateAttr* annotationAttribute = vtableDeclaration->getAttr<clang::AnnotateAttr>())
                reflInfo.Properties[0x00] = extractOffset(annotationAttribute);
        }
    );

    auto optionallyCastExpr = [](std::string_view castBind, auto&& query) {
        return matchers::anyOf(
            query,
            matchers::castExpr(matchers::hasSourceExpression(query)).bind(castBind)
        );
    };

    matchFinder.AddMatcher(
        matchers::binaryOperator(
	        matchers::hasOperatorName("="),
	        matchers::hasOperands(
		        matchers::unaryOperator(
			        matchers::hasOperatorName("*"),
			        matchers::hasUnaryOperand(
                        optionallyCastExpr("castProp", 
							matchers::ignoringParens(
								matchers::binaryOperator(
									matchers::hasOperatorName("+"),
									matchers::hasOperands(
                                        optionallyCastExpr("castDeclRef",
                                            matchers::anyOf(
											    matchers::declRefExpr().bind("declRef"),
                                                matchers::unaryOperator(
                                                    matchers::hasOperatorName("&"),
                                                    matchers::hasUnaryOperand(
                                                        matchers::declRefExpr().bind("declRef")
                                                    )
                                                )
                                            )
										),
										matchers::ignoringParenCasts(
											matchers::integerLiteral().bind("offset")
										)
									)
								)
							)
				        )
			        )
		        ),
		        matchers::anyOf(
			        matchers::ignoringParenCasts(
				        matchers::cxxMemberCallExpr(
					        matchers::has(
						        matchers::memberExpr(
							        matchers::has(
								        matchers::materializeTemporaryExpr(
									        matchers::has(
										        matchers::castExpr(
											        matchers::hasSourceExpression(
												        matchers::cxxConstructExpr(
													        matchers::hasArgument(0,
														        matchers::ignoringParenCasts(
															        matchers::declRefExpr().bind("value")
														        )
													        )
												        )
											        )
										        )
									        )
								        )
							        )
						        )
					        )
				        )
			        ),
			        matchers::ignoringParenCasts(
				        matchers::integerLiteral().bind("value")
			        )
		        )
	        )
        ),
        [&](const matchers::MatchFinder::MatchResult& result) {
            auto offset = result.Nodes.getNodeAs<clang::IntegerLiteral>("offset");
            auto value = result.Nodes.getNodeAs<clang::Expr>("value");
            auto declRef = result.Nodes.getNodeAs<clang::DeclRefExpr>("declRef");
            auto castDeclRef = result.Nodes.getNodeAs<clang::CStyleCastExpr>("castDeclRef");
            auto castProp = result.Nodes.getNodeAs<clang::CStyleCastExpr>("castProp");

            auto instanceAttr = declRef->getDecl()->getAttr<clang::AnnotateAttr>();
            if (instanceAttr != nullptr && reflInfo.Self == 0)
                reflInfo.Self = extractOffset(instanceAttr);

            uint64_t propertyOffset = offset->getValue().getLimitedValue(std::numeric_limits<uint64_t>::max());
            if (castDeclRef != nullptr)
                propertyOffset *= context.getTypeInfo(castDeclRef->getTypeAsWritten()).Width / 8;
            else
                propertyOffset *= sizeof(uint64_t);

            if (auto integerLit = clang::dyn_cast<clang::IntegerLiteral>(value)) {
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

                        reflInfo.Properties[propertyOffset + sizeof(uint64_t)] = loPart;
                        reflInfo.Properties[propertyOffset] = hiPart;

                        return;
                    }

                    // 1 << 64 would overflow
                    // Thankfully the default value is alread ULLONG_MAX
                    if (typeWidth < 64)
                        maxValue = (1uLL << typeWidth) - 1;
                }

                reflInfo.Properties[propertyOffset] = integerLit->getValue().getLimitedValue(maxValue);
            }
            else if (auto valueRef = clang::dyn_cast<clang::DeclRefExpr>(value)) {
                // If it's a declaration reference, check for our annotation on the referenced symbol;
                //   if there isn't, then it's likely assigning to some variable, and we probably don't
                //   care.
                auto value = valueRef->getDecl();

                auto annotationAttribute = value->getAttr<clang::AnnotateAttr>();
                if (annotationAttribute == nullptr)
                    return;

                reflInfo.Properties[propertyOffset] = extractOffset(annotationAttribute);
            }
        }
    );

    matchFinder.Run();

    return reflInfo;
}

void Analyzer::ProcessObject(IDA::API::Function const& functionInfo, ReflInfo& reflInfo) {
	std::string assembledPseudocode = [&] {
		std::stringstream strm;
		Utils::Exporter exporter(strm);
		exporter.Run(functionInfo, [](tinfo_t& argType) {
			argType = tinfo_t{ BTF_UINT64 };
		});

		return strm.str();
	}();

    return ParsePseudoCode([this, &functionInfo, &reflInfo](clang::ASTContext& context) {
        return this->ProcessObject(context, functionInfo, reflInfo);
    }, assembledPseudocode);
}

void Analyzer::ProcessObject(clang::ASTContext& context, IDA::API::Function const& functionInfo, ReflInfo& reflInfo) {
    auto scopeQuery = matchers::forFunction(matchers::hasName(functionInfo.GetName()));

    AST::Explorer firstStage(context);
    
    firstStage.AddMatcher(
        matchers::returnStmt(
            scopeQuery,
            matchers::hasReturnValue(
                matchers::ignoringParenCasts(
                    matchers::unaryOperator(
                        matchers::hasOperatorName("&"),
                        matchers::hasUnaryOperand(
                            matchers::declRefExpr().bind("instance")
                        )
                    )
                )
            )
        ),
        [&](const matchers::MatchFinder::MatchResult& result) {
            auto instanceVariable = result.Nodes.getNodeAs<clang::DeclRefExpr>("instance");

            auto attribute = instanceVariable->getDecl()->getAttr<clang::AnnotateAttr>();
            if (attribute == nullptr)
                return;

            reflInfo.Self = extractOffset(attribute);
        }
    );

    firstStage.Run();
}


void Analyzer::ProcessReflectionObjectConstructionCall(IDA::API::Function const& functionInfo, ReflInfo& reflInfo, uint64_t reflCtor) {
	std::string assembledPseudocode = [&] {
        std::stringstream strm;
		Utils::Exporter exporter(strm);
		exporter.Run(functionInfo, [](tinfo_t& argType) {
			argType = tinfo_t{ BTF_UINT64 };
		});

        return strm.str();
    }();

    return ParsePseudoCode([this, &reflInfo, &functionInfo, reflCtor](clang::ASTContext& context) {
        return this->ProcessReflectionObjectConstructionCall(context, functionInfo, reflInfo, reflCtor);
    }, assembledPseudocode);
}

template <typename T>
auto ExtractArgument(const clang::Expr* arg) -> const T* {
    if (auto declRef = clang::dyn_cast<T>(arg))
        return declRef;

	if (auto unaryOperator = clang::dyn_cast<clang::UnaryOperator>(arg))
		if (unaryOperator->getOpcode() == clang::UnaryOperatorKind::UO_AddrOf)
			return ExtractArgument<T>(unaryOperator->getSubExpr());

	if (auto castExpr = clang::dyn_cast<clang::CastExpr>(arg))
		return ExtractArgument<T>(castExpr->getSubExpr());

	if (auto constructExpr = clang::dyn_cast<clang::CXXConstructExpr>(arg)) {
		using namespace std::string_view_literals;

		if (constructExpr->getNumArgs() == 0)
			return nullptr;

		if (constructExpr->getConstructor()->getNameAsString() != "AnyType"sv)
			return nullptr;

		return ExtractArgument<T>(constructExpr->getArg(0));
	}

    if (auto memberCallExpr = clang::dyn_cast<clang::CallExpr>(arg))
    {
        if (memberCallExpr->getNumArgs() == 0)
            return nullptr;

        return ExtractArgument<T>(memberCallExpr->getArg(0));
    }

	if (auto materializeExpr = clang::dyn_cast<clang::MaterializeTemporaryExpr>(arg))
		return ExtractArgument<T>(materializeExpr->getSubExpr());

	return nullptr;
}

template <typename T, typename Fn>
auto ProcessParameter(const clang::CallExpr* callSite, size_t index, Fn&& fn) {
	if (callSite == nullptr || callSite->getNumArgs() <= index)
		return false;

	auto parameter = ExtractArgument<T>(callSite->getArg(index));
	if (parameter != nullptr)
		return fn(parameter);

	return false;
};


void Analyzer::ProcessReflectionObjectConstructionCall(clang::ASTContext& context, IDA::API::Function const& functionInfo, ReflInfo& reflInfo, uint64_t reflCtor) {
    std::unordered_map<uint64_t, const clang::CallExpr*> functionCalls;
    std::unordered_map<const clang::Decl*, const clang::FunctionDecl*> assignments;
    std::multimap<const clang::Decl*, const clang::CallExpr*> constructions;

    AST::Explorer explorer(context);
    explorer.AddMatcher(matchers::binaryOperator(
        matchers::hasOperatorName("="),
        matchers::hasOperands(
            matchers::declRefExpr().bind("declRef"),
            matchers::ignoringParenCasts(
                matchers::hasDescendant(
                    matchers::callExpr(
                        matchers::callee(
                            matchers::functionDecl(
                                matchers::hasAttr(clang::attr::Annotate)
                            ).bind("functionDecl")
                        )
                    )
                )
            )
        )
    ), [&](const matchers::MatchFinder::MatchResult& result) {
		auto functionDecl = result.Nodes.getNodeAs<clang::FunctionDecl>("functionDecl");
		auto declRef = result.Nodes.getNodeAs<clang::DeclRefExpr>("declRef");

        assignments.emplace(declRef->getDecl(), functionDecl);
    });
    explorer.AddMatcher(matchers::callExpr(
        matchers::forFunction(
            matchers::functionDecl(
                matchers::hasName(functionInfo.GetName())
            )
        ),
        matchers::callee(
			matchers::functionDecl(
				matchers::hasAttr(clang::attr::Annotate)
			)
        )
    ).bind("callExpr"), [&](const matchers::MatchFinder::MatchResult& result) {
        auto callExpr = result.Nodes.getNodeAs<clang::CallExpr>("callExpr");

		if (auto calleeDecl = callExpr->getDirectCallee()) {
			auto calleeAttr = calleeDecl->getAttr<clang::AnnotateAttr>();

            functionCalls.emplace(extractOffset(calleeAttr), callExpr);
		}

		if (callExpr->getNumArgs() != 0) {
			auto instanceDeclRef = ExtractArgument<clang::DeclRefExpr>(callExpr->getArg(0));
			if (instanceDeclRef != nullptr)
				constructions.emplace(instanceDeclRef->getDecl(), callExpr);
		}
    });
    explorer.Run(clang::TraversalKind::TK_IgnoreUnlessSpelledInSource);

    // Find the call site
    auto constructorCallSite = [&]() -> const clang::CallExpr* {
        // Identify via clang::annotate
        auto itr = functionCalls.find(reflCtor);
        if (itr != functionCalls.end())
            return itr->second;

        return nullptr;
    }();

	// CreateReflInfo(&instance, &name, baseTypePtr, pfn1, pfn2);

	if (!ProcessParameter<clang::DeclRefExpr>(constructorCallSite, 0, [&reflInfo](const clang::DeclRefExpr* instanceParameter) {
		auto instanceAttribute = instanceParameter->getDecl()->getAttr<clang::AnnotateAttr>();
		if (instanceAttribute == nullptr)
			return false;

		reflInfo.Self = extractOffset(instanceAttribute);
        return true;
    }))
        return;

    if (!ProcessParameter<clang::DeclRefExpr>(constructorCallSite, 1, [&](const clang::DeclRefExpr* nameParameter) {
        auto typeNameAssignmentValue = [&]() -> const clang::CallExpr* {
            auto typeNameConstruction = constructions.upper_bound(nameParameter->getDecl());
            if (typeNameConstruction == constructions.end())
                return nullptr;

            return typeNameConstruction->second;
        }();

        if (typeNameAssignmentValue != nullptr) {
            auto typeName = ExtractArgument<clang::StringLiteral>(typeNameAssignmentValue->getArg(1));
            if (typeName == nullptr)
                return false;

            reflInfo.TypeName = typeName->getBytes();
            return true;
        }

        return false;
    })) {
        // Problem: the call to base::global::CStrId (which is really what we're looking for here)
        //   likely got inlined, meaning that instead we have to look for CRC64 in this really stupid way
        //   and hope that there isn't more than one call into it.
        // https://i.imgur.com/PUOAzoy.png
        // Here is the expected output: https://i.imgur.com/GFA6X9a.png
        AST::Explorer crcExplorer(context);
        crcExplorer.AddMatcher(matchers::callExpr(
			matchers::callee(matchers::functionDecl(matchers::hasAttr(clang::attr::Annotate)).bind("functionDecl")),
            matchers::hasArgument(0, matchers::stringLiteral().bind("typeName")),
            matchers::hasArgument(1, matchers::integerLiteral().bind("integerLiteral"))
        ), [&](const matchers::MatchFinder::MatchResult& result) {
            auto typeName = result.Nodes.getNodeAs<clang::StringLiteral>("typeName");
            auto integerLiteral = result.Nodes.getNodeAs<clang::IntegerLiteral>("integerLiteral");
            auto functionDecl = result.Nodes.getNodeAs<clang::FunctionDecl>("functionDecl");

            auto declAttr = functionDecl->getAttr<clang::AnnotateAttr>();
            if (declAttr == nullptr /* || extractOffset(declAttr) != this->_versionInfo->Properties.CRC64 */)
                return;

            if (typeName->getByteLength() != integerLiteral->getValue())
                return;

            reflInfo.TypeName = typeName->getBytes();
        });
        crcExplorer.Run(clang::TraversalKind::TK_IgnoreUnlessSpelledInSource);
    }

	// Third parameter is the base type
	//   If not provided, 0LL is given, and Clang sees it as an IntegerLiteral, not a DeclRefExpr.
    if (!ProcessParameter<clang::DeclRefExpr>(constructorCallSite, 2, [&](const clang::DeclRefExpr* baseTypeParam) {
		auto baseFunctionDecl = [&]() -> const clang::FunctionDecl* {
			auto itr = assignments.find(baseTypeParam->getDecl());
			if (itr == assignments.end())
				return nullptr;

			return itr->second;
		}();

		if (baseFunctionDecl == nullptr)
			return false;

		auto baseTypeAttr = baseFunctionDecl->getAttr<clang::AnnotateAttr>();
		if (baseTypeAttr == nullptr)
			return false;

		// Base type is stored here.
		reflInfo.Properties[0x78] = extractOffset(baseTypeAttr);
        return true;
    }))
        return;

    // Fourth parameter is the function enumerating member variables
    if (!ProcessParameter<clang::DeclRefExpr>(constructorCallSite, 3, [&](const clang::DeclRefExpr* varEnumerator) {
		auto enumeratorAttr = varEnumerator->getDecl()->getAttr<clang::AnnotateAttr>();
		if (enumeratorAttr != nullptr)
			reflInfo.Properties[0x70] = extractOffset(enumeratorAttr);

        return enumeratorAttr != nullptr;
    }))
        return;

    // And fifth parmeter depends!
    //  1. For CClass, it enumerates member functions
    //  2. For CEnumType, it enumerates member values
    //  3. And god knows what else
    // TODO: Write the code for this
}

void Analyzer::HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) {
#if _DEBUG
    llvm::SmallVector<char, 128> Message;
    info.FormatDiagnostic(Message);

    IDA::API::Message("(Dread) {}.\n", std::string_view{ Message.data(), Message.size() });
#endif
}
