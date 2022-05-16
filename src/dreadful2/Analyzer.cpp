#include "Analyzer.hpp"
#include "SyntaxTreeVisitor.hpp"
#include "IDA/API/Function.hpp"

#include <regex>
#include <type_traits>

#include <hexrays.hpp>

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchersInternal.h>
#include <clang/Tooling/CompilationDatabase.h>
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

namespace Utils {
    /// <summary>
    /// Associates a query with a query callback.
    /// Construction registers the query for the finder.
    /// </summary>
    template <typename QueryCallback>
	struct MatchQuery final : matchers::MatchFinder::MatchCallback {
        template <typename Query>
		MatchQuery(matchers::MatchFinder& finder, Query&& query, QueryCallback handler) noexcept
			: _handler(handler) {
            finder.addMatcher(query, this);
        }

		void run(const matchers::MatchFinder::MatchResult& result) override {
			std::invoke(_handler, result);
		}

	private:
		QueryCallback _handler;
	};

    template <typename Handler>
    auto AnalyzeFunction(IDA::API::Function const& functionInfo, Handler handler, std::string_view sourceCode)
        -> std::invoke_result_t<Handler, clang::ASTContext&, IDA::API::Function const&>
    {
        using namespace clang;

		clang::IgnoringDiagConsumer diagnosticConsumer;

        using namespace std::string_literals;

        auto astUnit = tooling::buildASTFromCodeWithArgs(sourceCode,
            { "-std=c++20"s, "-fsyntax-only"s },
            "disassembly.cpp",
            "dread-tool"s,
            std::make_shared<PCHContainerOperations>(),
            tooling::getClangStripDependencyFileAdjuster(),
            tooling::FileContentMappings(),
            &diagnosticConsumer);

		using return_type = std::invoke_result_t<Handler, clang::ASTContext&, IDA::API::Function const&>;

        if constexpr (!std::is_void_v<return_type>) {
            if (astUnit == nullptr)
                return return_type{};
        }
        else {
            if (astUnit == nullptr)
                return;
        }

        return handler(astUnit->getASTContext(), functionInfo);
    }
}

std::string GeneratePseudocode(IDA::API::Function const& functionInfo, std::function<void(tinfo_t&)> returnTypeTransform) {
    auto modifyArgCallback = [](tinfo_t& argType) {
        if (argType.is_struct()) {
            size_t argumentSize = argType.get_size();

            switch (argumentSize) {
                case BADSIZE: // ???
                    break;
                case 16:
                    argType = tinfo_t{ BTF_UINT128 };
                    break;
                case 8:
                    argType = tinfo_t{ BTF_UINT64 };
                    break;
                case 4:
                    argType = tinfo_t{ BTF_UINT32 };
                    break;
                case 2:
                    argType = tinfo_t{ BTF_UINT16 };
                    break;
                case 1:
                    argType = tinfo_t{ BTF_UINT8 };
                    break;
                default:
                {
                    // If the type is a struct, pretend it's the raw binary data
                    // TODO: What about type alignment?
                    array_type_data_t arrayData(0, argumentSize);
                    arrayData.elem_type = tinfo_t{ BTF_UINT8 };

                    argType.create_array(arrayData);
                    break;
                }
            }
        }
        else if (argType.is_ptr()) {
            using namespace std::string_view_literals;

            // If it's a pointer to struct or function, change to uint64 
            // so that we can ignore it. Otherwise don't touch.
            tinfo_t pointedType = argType.get_pointed_object();
            if (!pointedType.is_scalar() || pointedType.is_func() || pointedType.is_struct() || pointedType.is_decl_struct())
                argType = tinfo_t{ BTF_UINT64 };
            // Also hide away guard variables
            else if (pointedType.dstr() == "__guard"sv)
                argType = tinfo_t{ BTF_UINT64 };
        }
    };

    functionInfo.ModifyType([&](tinfo_t& argType, size_t argIndex) {
        if (argIndex == std::numeric_limits<size_t>::max()) {
            returnTypeTransform(argType);
        } else {
            std::invoke(modifyArgCallback, std::ref(argType));
        }
    });

    std::stringstream assembledPseudocode;
    assembledPseudocode << "#include <" IDA_INCLUDE_DIR "/../../../plugins/defs.h>\n";

    assembledPseudocode << R"(
// Universally convertible to-and-from type.
struct AnyType {
    template <typename T> AnyType(T) { }

    AnyType() { }

    template <typename T>
    operator T() { return T {}; }

    template <typename T>
    operator T() const { return T {}; }
};

using _OWORD = unsigned __int128;

AnyType __ldar(AnyType);

unsigned __int64 vtable_for_base__reflection__CType;
unsigned __int64 vtable_for_base__reflection__CClass;
unsigned __int64 vtable_for_base__reflection__CEnum;
unsigned __int64 vtable_for_base__reflection__CCollectionType;

)";

    for (ea_t reference : functionInfo.GetReferencesFrom(XREF_FAR)) {
        IDA::API::Function callee{ reference };
        std::string calleeName = callee.GetName();
        if (calleeName.empty())
            continue;

		// Abuse the clang::annotate attribute to store offsets properly
		assembledPseudocode << '\n' << std::format(R"([[clang::annotate("0x{:016x}")]] )", reference);
		assembledPseudocode << "AnyType " << calleeName << '(';
        for (size_t i = 0; i < callee.GetArgumentCount(); ++i) {
            if (i > 0)
                assembledPseudocode << ", ";
            
            assembledPseudocode << "AnyType";
        }
        assembledPseudocode << ");";
    }

    assembledPseudocode << '\n';

    for (ea_t reference : functionInfo.GetReferencesFrom(XREF_DATA)) {
        std::string name = get_name(reference, GN_DEMANGLED | GN_SHORT).c_str();
        if (name.empty())
            continue;

        // Set data type to uint64_t
        apply_tinfo(reference, tinfo_t{ BTF_UINT64 }, TINFO_DEFINITE);

        // Abuse clang::annotate so that we can later map from names

        // Generate the regular name
        assembledPseudocode << '\n' <<
            std::format(R"([[clang::annotate("0x{1:016x}")]] unsigned __int64 {0};)", name, reference);

        // Why does Hex-Rays do this?
        if (name[0] == '_') {
            // Also generate one with stripped first underscore if it exists
            assembledPseudocode << '\n' <<
                std::format(R"([[clang::annotate("0x{1:016x}")]] unsigned __int64 {0};)", name.substr(1), reference);
        }
        else {
            // Also generate one with extra underscore if it exists
            assembledPseudocode << '\n' <<
                std::format(R"([[clang::annotate("0x{1:016x}")]] unsigned __int64 _{0};)", name, reference);
        }
    }

    assembledPseudocode << "\n\n";
    functionInfo.Decompile(assembledPseudocode, [](cfunc_t& fn) {
        // 1. Make all pointer stack elements uint64
        lvars_t* localVariables = fn.get_lvars();
        assert(localVariables != nullptr);

        for (size_t i = 0; i < localVariables->size(); ++i) {
            lvar_t& localVariable = (*localVariables)[i];
            const tinfo_t& variableType = localVariable.type();

            if (variableType.is_ptr())
                localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT64 });
            else if (variableType.is_struct()) {
                size_t variableSize = variableType.get_size();
                switch (variableSize) {
                    case BADSIZE: // ??? Send help
						break;
					case 16:
						localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT128 });
                        break;
					case 8:
						localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT64 });
                        break;
                    case 4:
                        localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT32 });
                        break;
                    case 2:
                        localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT16 });
                        break;
                    case 1:
                        localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT8 });
                        break;
                    default:
                    {
                        // If it's a struct, set it to an array matching the size of the structure
                        // TODO: type alignment?
                        array_type_data_t arrType(0, variableType.get_size());
                        arrType.elem_type = tinfo_t{ BTF_UINT8 };

                        tinfo_t newType;
                        newType.create_array(arrType);
                        localVariable.set_final_lvar_type(newType);

                        break;
                    }
                }
            }
        }
    });

    std::string pseudocode = assembledPseudocode.str();

    auto replaceString = [](std::string& input, std::string_view needle, std::string_view repl) {
        size_t pos = 0;
        while ((pos = input.find(needle, pos)) != std::string::npos) {
            input.replace(pos, needle.length(), repl);
            pos += repl.length();
        }
    };

    replaceString(pseudocode, "&`vtable for'", "&vtable_for_");
    replaceString(pseudocode, "::", "__");
    replaceString(pseudocode, "__~", "__dtor_");

    // Try **really** hard to get rid of casts
    // First pass removes casts to incomplete types
    pseudocode = std::regex_replace(pseudocode,
        std::regex{ R"(#[0-9]+ \*)" }, "AnyType");
    //pseudocode = std::regex_replace(pseudocode,
    //    std::regex{ R"((\([a-z0-9_ *&]+\))(&?\*?[a-z]))" }, "$2");

    // This is stupid ....
    replaceString(pseudocode, "clang__annotate", "clang::annotate");

    // This is EVEN more stupid - HexRays won't always insert casts...
    pseudocode = std::regex_replace(pseudocode,
        std::regex{ R"(\) = (&?[^0-9~][^;]+);)" }, ") = (AnyType)($1);");

    return pseudocode;
}

auto Analyzer::ProcessReflectionObjectConstruction(IDA::API::Function const& functionInfo)
    -> ReflInfo
{
    std::string assembledPseudocode = GeneratePseudocode(functionInfo, [](tinfo_t& argType) {
        argType = tinfo_t{ BTF_VOID };
    });

    return Utils::AnalyzeFunction(functionInfo, [this](clang::ASTContext& context, IDA::API::Function const& functionInfo) -> ReflInfo {
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
    matchers::MatchFinder matchFinder;

    Utils::MatchQuery reflectedNameQuery { 
        matchFinder,
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
    };

    //< Handle vtable assignment.
    Utils::MatchQuery vtableAssigmentQuery{
        matchFinder,
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
    };

    Utils::MatchQuery memberAssignmentQuery {
        matchFinder,
        matchers::binaryOperator(
	        matchers::hasOperatorName("="),
	        matchers::hasOperands(
		        matchers::unaryOperator(
			        matchers::hasOperatorName("*"),
			        matchers::hasUnaryOperand(
				        matchers::optionally( 
					        matchers::castExpr(
						        matchers::hasSourceExpression(
							        matchers::ignoringParens(
								        matchers::binaryOperator(
									        matchers::hasOperatorName("+"),
									        matchers::hasOperands(
										        matchers::optionally(
                                                    matchers::castExpr(
                                                        matchers::hasSourceExpression(
                                                            matchers::anyOf(
											                    matchers::declRefExpr().bind("declRef"),
                                                                matchers::unaryOperator(
                                                                    matchers::hasOperatorName("&"),
                                                                    matchers::hasUnaryOperand(
                                                                        matchers::declRefExpr().bind("declRef")
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    ).bind("castDeclRef")
										        ),
										        matchers::ignoringParenCasts(
											        matchers::integerLiteral().bind("offset")
										        )
									        )
								        )
							        )
						        )
					        ).bind("castProp")
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
    };
    
    matchFinder.matchAST(context);

    return reflInfo;
}

void Analyzer::ProcessObject(IDA::API::Function const& functionInfo, ReflInfo& reflInfo) {
	std::string assembledPseudocode = GeneratePseudocode(functionInfo, [](tinfo_t& argType) {
		argType = tinfo_t{ BTF_UINT64 };
	});

	return Utils::AnalyzeFunction(functionInfo, [this, &reflInfo](clang::ASTContext& context, IDA::API::Function const& functionInfo) {
		return this->ProcessObject(context, functionInfo, reflInfo);
    }, assembledPseudocode);
}

void Analyzer::ProcessObject(clang::ASTContext& context, IDA::API::Function const& functionInfo, ReflInfo& reflInfo) {
	auto scopeQuery = matchers::forFunction(matchers::hasName(functionInfo.GetName()));

    
    matchers::MatchFinder firstStage;
    Utils::MatchQuery findReturnStmtQuery{
        firstStage,
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
    };

    firstStage.matchAST(context);
}
