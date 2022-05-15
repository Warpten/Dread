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

const matchers::internal::VariadicDynCastAllOfMatcher<clang::Expr, clang::RecoveryExpr> recoveryExpr;

namespace Utils {
    template <typename QueryCallback>
    struct MatchCallback final : matchers::MatchFinder::MatchCallback {
        explicit MatchCallback(QueryCallback handler, Analyzer* analyzer)
            : _handler(handler), _analyzer(analyzer)
        { }

        void run(const matchers::MatchFinder::MatchResult& result) override {
            std::invoke(_handler, result);
        }

    private:
        QueryCallback _handler;
        Analyzer* _analyzer;
    };

    template <typename Q, typename QueryCallback>
    void ExecuteQuery(Analyzer* analyzer, clang::ASTContext& context, 
        IDA::API::Function const& function, Q&& query, QueryCallback handler)
    {
        MatchCallback callback{ handler, analyzer };

        matchers::MatchFinder finder;
        finder.addMatcher(query, &callback);
        finder.matchAST(context);
    }

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

        if (astUnit == nullptr)
            return return_type{};

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
#if 1
		assembledPseudocode << "AnyType " << calleeName << '(';
        for (size_t i = 0; i < callee.GetArgumentCount(); ++i) {
            if (i > 0)
                assembledPseudocode << ", ";
            
            assembledPseudocode << "AnyType";
        }
        assembledPseudocode << ");";
#else
        callee.ModifyType([&](tinfo_t& argType, size_t argIndex) {
            if (argIndex == std::numeric_limits<size_t>::max()) {
                // Set to uint64 if the return type is a pointer (aliasing)
                if (argType.is_ptr()) {
                    argType = tinfo_t{ BTF_UINT64 };
                }
            }

            std::invoke(modifyArgCallback, std::ref(argType));
        });

        // Pretend every function returns a void*; doesn't matter for our purposes, decompilation is already done
        assembledPseudocode << ' ' << callee.GetReturnType().ToString() << ' ';

        assembledPseudocode << calleeName << '(';
        for (size_t i = 0; i < callee.GetArgumentCount(); ++i) {
            if (i > 0)
                assembledPseudocode << ", ";

            assembledPseudocode << callee.GetArgumentType(i).ToString();
        }
        assembledPseudocode << ");";
#endif
    }

    assembledPseudocode << '\n';

    for (ea_t reference : functionInfo.GetReferencesFrom(XREF_DATA)) {
        std::string name = get_name(reference).c_str();
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

	auto extractOffset = [](clang::AnnotateAttr* attribute) -> uint64_t {
		llvm::StringRef annotation{ attribute->getAnnotation() };

		uint64_t offsetValue = 0uLL;
		auto [ptr, ec] = std::from_chars(annotation.begin(), annotation.end(), offsetValue);
		if (ec != std::errc{})
			return 0uLL;

		return offsetValue;
	};

    Utils::ExecuteQuery(this, context, functionInfo, matchers::callExpr(
        matchers::forFunction(matchers::hasName(functionInfo.GetName())),
        matchers::hasArgument(0, 
            matchers::hasDescendant(
                matchers::stringLiteral().bind("stringLiteral")
            )
        ),
        matchers::hasArgument(1, 
            matchers::hasDescendant(
                matchers::integerLiteral().bind("integerLiteral")
            )
        )
    ), [&](const matchers::MatchFinder::MatchResult& result) {
        auto stringLiteral = result.Nodes.getNodeAs<clang::StringLiteral>("stringLiteral");
        auto integerLiteral = result.Nodes.getNodeAs<clang::IntegerLiteral>("integerLiteral");

        if (stringLiteral == nullptr || integerLiteral == nullptr)
            return;

        assert(stringLiteral->getByteLength() == integerLiteral->getValue());
        reflInfo.Name = stringLiteral->getBytes();
    });

    /**
     * // Vtable assignment
     * stru_7101CF38F8 = (unsigned __int64)&vtable_for_base__reflection__CType;
     *  `-BinaryOperator 0x2079b211110 <line:69:5, col:42> 'unsigned long long' lvalue '='
     * 	|-DeclRefExpr 0x2079b211078 <col:5> 'unsigned long long' lvalue Var 0x2079b20ffa8 'stru_7101CF38F8' 'unsigned long long'
     * 	`-CStyleCastExpr 0x2079b2110e8 <col:23, col:42> 'unsigned long long' <PointerToIntegral>
     * 	  `-UnaryOperator 0x2079b2110b8 <col:41, col:42> 'unsigned long long *' prefix '&' cannot overflow
     * 		`-DeclRefExpr 0x2079b211098 <col:42> 'unsigned long long' lvalue Var 0x2079b209060 'vtable_for_base__reflection__CType' 'unsigned long long'
     * 
     * This also works for assignment to a1 (instance arg); LHS operator will be a DeclRefExpr to a ParmVarDecl, not a VarDecl.
     * Incidentally that means that there won't be [[clang::annotate]] in the decl referenced, meaning we automatically know if
     * We need to perform a secondary pass to find the instance variable.
     */
    auto vtableAssigmentQuery = matchers::binaryOperator(
		matchers::forFunction(
			matchers::functionDecl(
				matchers::hasName(functionInfo.GetName())
			)
		),
        matchers::hasOperatorName("="),
        matchers::hasOperands(
            matchers::declRefExpr().bind("this"),
            matchers::cStyleCastExpr(
                matchers::hasSourceExpression(
                    matchers::unaryOperator(
                        matchers::declRefExpr().bind("declRef")
                    )
                )
            )
        )
    );

    Utils::ExecuteQuery(this, context, functionInfo, vtableAssigmentQuery,
        [&](const matchers::MatchFinder::MatchResult& result) {
            auto instance = result.Nodes.getNodeAs<clang::DeclRefExpr>("this");
            auto declRef = result.Nodes.getNodeAs<clang::DeclRefExpr>("declRef");

            if (instance == nullptr || declRef == nullptr)
                return;

			const clang::ValueDecl* instanceDeclaration = declRef->getDecl();
            if (clang::AnnotateAttr* annotationAttribute = instanceDeclaration->getAttr<clang::AnnotateAttr>())
                reflInfo.Self = extractOffset(annotationAttribute);

            const clang::ValueDecl* vtableDeclaration = declRef->getDecl();
            if (clang::AnnotateAttr* annotationAttribute = vtableDeclaration->getAttr<clang::AnnotateAttr>())
                reflInfo.Properties[0x00] = extractOffset(annotationAttribute);
        }
    );

    /**
     * // Member assignment
     * *(&stru_7101CF38F8 + 1) = a2;
	 *  `-BinaryOperator 0x2374029c6c0 <line:70:5, col:31> 'unsigned long long' lvalue '='
     * 	|-UnaryOperator 0x2374029c658 <col:5, col:27> 'unsigned long long' lvalue prefix '*' cannot overflow
     * 	| `-ParenExpr 0x2374029c638 <col:6, col:27> 'unsigned long long *'
     * 	|   `-BinaryOperator 0x2374029c618 <col:7, col:26> 'unsigned long long *' '+'
     * 	|     |-UnaryOperator 0x2374029c5d8 <col:7, col:8> 'unsigned long long *' prefix '&' cannot overflow
     * 	|     | `-DeclRefExpr 0x2374029c5b8 <col:8> 'unsigned long long' lvalue Var 0x2374029b4e8 'stru_7101CF38F8' 'unsigned long long'
     * 	|     `-IntegerLiteral 0x2374029c5f0 <col:26> 'int' 1
     * 	`-ImplicitCastExpr 0x2374029c6a8 <col:31> 'unsigned long long' <LValueToRValue>
     * 	  `-DeclRefExpr 0x2374029c670 <col:31> 'unsigned long long' lvalue Var 0x2374029c538 'a2' 'unsigned long long'
     * 
     * This also works for assignment to a1 (instance arg). DeclRefExpr will point to a ParmVarDecl instead of a VarDecl.
     */

    /*
     * // Member assignment (cast)
     * *((_OWORD *)&stru_7101CF38F8 + 2) = 0xFFFFFFFF00000000LL;
	 *  `-BinaryOperator 0x2127dd63fe0 <line:76:5, col:41> '_OWORD':'unsigned __int128' lvalue '='
     *	|-UnaryOperator 0x2127dd63f88 <col:5, col:37> '_OWORD':'unsigned __int128' lvalue prefix '*' cannot overflow
     *	| `-ParenExpr 0x2127dd63f68 <col:6, col:37> '_OWORD *'
     *	|   `-BinaryOperator 0x2127dd63f48 <col:7, col:36> '_OWORD *' '+'
     *	|     |-CStyleCastExpr 0x2127dd63ef8 <col:7, col:18> '_OWORD *' <BitCast>
     *	|     | `-UnaryOperator 0x2127dd63e70 <col:17, col:18> 'unsigned long long *' prefix '&' cannot overflow
     *	|     |   `-DeclRefExpr 0x2127dd63e50 <col:18> 'unsigned long long' lvalue Var 0x2127dd62d58 'stru_7101CF38F8' 'unsigned long long'
     *	|     `-IntegerLiteral 0x2127dd63f20 <col:36> 'int' 2
     *	`-ImplicitCastExpr 0x2127dd63fc8 <col:41> '_OWORD':'unsigned __int128' <IntegralCast>
	 *	  `-IntegerLiteral 0x2127dd63fa0 <col:41> 'long long' -4294967296
     * 
	 * This also works for assignment to a1 (instance arg). DeclRefExpr will point to a ParmVarDecl instead of a VarDecl.
     */
    auto memberAssignmentQuery = matchers::binaryOperator(
        matchers::forFunction(
            matchers::functionDecl(
                matchers::hasName(functionInfo.GetName())
            )
        ),
        matchers::hasOperatorName("="),
        matchers::hasOperands(
            matchers::unaryOperator(
                matchers::hasUnaryOperand(
                    matchers::ignoringParenCasts(
                        matchers::binaryOperator(
                            matchers::hasOperatorName("+"),
                            matchers::hasOperands(
                                matchers::anyOf(
                                    /**
	                                  *	CStyleCastExpr 0x2127dd63ef8 <col:7, col:18> '_OWORD *' <BitCast>
	                                  *	`-UnaryOperator 0x2127dd63e70 <col:17, col:18> 'unsigned long long *' prefix '&' cannot overflow
	                                  *	  `-DeclRefExpr 0x2127dd63e50 <col:18> 'unsigned long long' lvalue Var 0x2127dd62d58 'stru_7101CF38F8' 'unsigned long long'
                                     */
									matchers::cStyleCastExpr(
										matchers::hasSourceExpression(
                                            matchers::unaryOperator(matchers::hasUnaryOperand(
                                                matchers::declRefExpr().bind("declRef")
                                            ))
										)
									).bind("castDeclRef"),
                                    /**
                                	 * UnaryOperator 0x2374029c5d8 <col:7, col:8> 'unsigned long long *' prefix '&' cannot overflow
                                	 * `-DeclRefExpr 0x2374029c5b8 <col:8> 'unsigned long long' lvalue Var 0x2374029b4e8 'stru_7101CF38F8' 'unsigned long long'
                                     */
									matchers::unaryOperator(matchers::hasUnaryOperand(
                                        matchers::declRefExpr().bind("declRef")
                                    ))
                                ),
                                matchers::integerLiteral().bind("offset")
                            )
                        )
                    )
                )
            ),
            matchers::ignoringParenCasts(
                matchers::anyOf(
                    matchers::integerLiteral().bind("value"),
                    matchers::ignoringParenCasts(
                        matchers::declRefExpr().bind("value")
                    )
                )
            )
        )
    );

    Utils::ExecuteQuery(this, context, functionInfo, memberAssignmentQuery,
        [&](const matchers::MatchFinder::MatchResult& result) {
            auto offset = result.Nodes.getNodeAs<clang::IntegerLiteral>("offset");
            auto value = result.Nodes.getNodeAs<clang::Expr>("value");
            auto declRef = result.Nodes.getNodeAs<clang::DeclRefExpr>("declRef");
            auto castDeclRef = result.Nodes.getNodeAs<clang::CStyleCastExpr>("castDeclRef");

            if (offset == nullptr || value == nullptr || declRef == nullptr)
                return;

            // TODO: Asserts that the reference is on the first argument

            uint64_t propertyOffset = offset->getValue().getLimitedValue(std::numeric_limits<uint64_t>::max());
            if (castDeclRef != nullptr) {
                // clang::TypeInfo stores size and alignment in bits.
                // Offset expressed as increments of 64 bits.
                propertyOffset *= context.getTypeInfo(castDeclRef->getTypeAsWritten()).Width / 64;
            }

            if (const clang::IntegerLiteral* integerLit = clang::dyn_cast<clang::IntegerLiteral>(value)) {
                // Get the value, limited to the size of the target type if it exists.
                // If it doesn't, default to uint64.
                uint64_t maxValue = std::numeric_limits<uint64_t>::max();

                if (castDeclRef != nullptr) {
                    uint64_t typeWidth = context.getTypeInfo(castDeclRef->getTypeAsWritten()).Width;
                    
                    if (typeWidth == 128) {
                        // Special handling, store as 2x64
                        uint64_t loPart = integerLit->getValue().extractBitsAsZExtValue(64, 0);
                        uint64_t hiPart = integerLit->getValue().extractBitsAsZExtValue(64, 64);
                        reflInfo.Properties[propertyOffset] = loPart;
                        reflInfo.Properties[propertyOffset + 1] = hiPart;

                        return;
                    }

                    maxValue = 1uLL << typeWidth;
                }

                reflInfo.Properties[propertyOffset] = integerLit->getValue().getLimitedValue(maxValue);
            }
            else if (auto valueRef = clang::dyn_cast<clang::DeclRefExpr>(value)) {
                auto value = valueRef->getDecl();
                if (auto functionDecl = clang::dyn_cast<clang::FunctionDecl>(value)) {
                    auto annotationAttribute = functionDecl->getAttr<clang::AnnotateAttr>();
                    if (annotationAttribute == nullptr)
                        return;

                    reflInfo.Properties[propertyOffset] = extractOffset(annotationAttribute);
                }
                // Anything else?
            }
        }
    );

    // This variation is necessary for reflobjects where the constructed object is inlined.
    return reflInfo;
}
