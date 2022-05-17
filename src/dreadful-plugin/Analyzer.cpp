#include "Analyzer.hpp"

// ast-parser
#include <AST/Explorer.hpp>
// dreadful-plugin-ida-base
#include <IDA/API/Function.hpp>
#include <Utils/Exporter.hpp>

#include <hexrays.hpp>

// std
#include <regex>
#include <type_traits>

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

            // Small fixup, needed because of the string replacements we do on the pseudocode...
            for (char& character : reflInfo.Name)
                if (character == '_')
                    character = ':';
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

void Analyzer::ProcessReflectionObjectConstructionCall(clang::ASTContext& context, IDA::API::Function const& functionInfo, ReflInfo& reflInfo, uint64_t reflCtor) {
    // This also has a return (uint64_t)&...
    // So just reuse that
    ProcessObject(context, functionInfo, reflInfo);

    // And now for the fun part
    std::vector<const clang::CallExpr*> callExpressions;
    { // Dump all call expressions
        AST::Explorer finder(context);
        finder.AddMatcher(
            matchers::callExpr().bind("root"),
            [&](const matchers::MatchFinder::MatchResult& result) {
                callExpressions.push_back(result.Nodes.getNodeAs<clang::CallExpr>("root"));
            }
        );
        finder.Run();
    }

    auto ctorCallSite = [&]() -> const clang::CallExpr* {
        auto itr = std::find_if(callExpressions.begin(), callExpressions.end(), [&](const clang::CallExpr* callExpression) -> bool {
            auto calleeAttr = callExpression->getCalleeDecl()->getAttr<clang::AnnotateAttr>();
            return calleeAttr != nullptr && extractOffset(calleeAttr) == reflCtor;
        });

        if (itr != callExpressions.end())
            return *itr;

        return nullptr;
    }();

    // If ProcessObject didn't find the global instance, do that now
	if (reflInfo.Self == 0) {
        // 2. Inspect arguments
        auto thisArg = ctorCallSite->getArg(0);
        if (auto unaryOpArg = clang::dyn_cast<clang::UnaryOperator>(thisArg)) {
            assert(unaryOpArg->getOpcode() == clang::UnaryOperator::Opcode::UO_AddrOf);
            if (auto declRef = clang::dyn_cast<clang::DeclRefExpr>(unaryOpArg->getSubExpr())) {
                clang::AnnotateAttr* annotationAttr = declRef->getDecl()->getAttr<clang::AnnotateAttr>();
                if (annotationAttr != nullptr)
                    return;

                reflInfo.Self = extractOffset(annotationAttr);
            }
        }
    }

    // auto nameVarDecl = [&]() -> const clang::Decl* {
	// 	auto nameReference = clang::dyn_cast<clang::UnaryOperator>(ctorCallSite->getArg(1));
	// 	if (nameReference != nullptr && nameReference->getOpcode() == clang::UnaryOperator::Opcode::UO_AddrOf)
    //         return clang::dyn_cast<clang::Decl>(nameReference->getSubExpr());
    //     return nullptr;
    // }();
    // 
    // matchers::callExpr(
    //     matchers::callee(matchers::equalsNode(ctorCallSite->getCalleeDecl())),
    //     matchers::hasArgument(0,
    //         matchers::declRefExpr(matchers::to(matchers::equalsNode(nameVarDecl)))
    //     ),
    //     matchers::hasArgument(1,
    //         matchers::unaryOperator(
    //             matchers::hasOperatorName("&"),
    //             matchers::hasUnaryOperand(
    //                 matchers::declRefExpr(matchers::to(matchers::decl().bind("nameDecl")))
    //             )
    //         )
    //     )
    // ).bind("root");
    // 
    // // Second argument is a DeclRefExpr to a VarDecl that is the name of the object
    // auto nameReference = clang::dyn_cast<clang::UnaryOperator>(ctorCallSite->getArg(1));
    // if (nameReference != nullptr && nameReference->getOpcode() == clang::UnaryOperator::Opcode::UO_AddrOf) {
    //     auto nameDecl = clang::dyn_cast<clang::Decl>(nameReference->getSubExpr());
    // 
    //     // Find the assignment
    //     matchers::MatchFinder callMatcher;
    // 
    //     Utils::MatchQuery query{
    //         callMatcher,
    //         matchers::callExpr(
    //             matchers::callee(matchers::equalsNode(ctorCallSite->getCalleeDecl())),
    //             matchers::argumentCountIs(3),
    //             matchers::hasArgument(0,
    //                 matchers::declRefExpr(matchers::to(matchers::equalsNode(nameDecl)))
    //             ),
    //             matchers::hasArgument(1,
    //                 matchers::ignoringParenCasts(matchers::stringLiteral().bind("typeName"))
    //             ),
    //             matchers::hasArgument(2,
    //                 matchers::ignoringParenCasts(matchers::integerLiteral(matchers::equals(1)))
    //             )
    //         ),
    //         [&](const matchers::MatchFinder::MatchResult& result) {
    //             auto typeName = result.Nodes.getNodeAs<clang::StringLiteral>("typeName");
    // 
    //             reflInfo.TypeName = typeName->getBytes();
    //         }
    //     };
    // 
    //     callMatcher.matchAST(context);
    // }
    // 
    // // Third argument may be a local variable, which is assigned from a call, meaning this type has a base type
    // if (auto baseTypeDeclRef = clang::dyn_cast<clang::DeclRefExpr>(ctorCallSite->getArg(2))) {
    //     auto baseTypeDecl = clang::dyn_cast<clang::VarDecl>(baseTypeDeclRef->getDecl());
    // }
}

void Analyzer::HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) {

}