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
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>

using namespace clang;
namespace matchers = clang::ast_matchers;

const matchers::internal::VariadicDynCastAllOfMatcher<clang::Expr, clang::RecoveryExpr> recoveryExpr;

namespace Utils {
    template <typename QueryCallback>
    struct MatchCallback final : matchers::MatchFinder::MatchCallback {
        explicit MatchCallback(QueryCallback handler, Analyzer* analyzer, IDA::API::Function const& functionInfo)
            : _handler(handler), _analyzer(analyzer), _functionInfo(functionInfo)
        { }

        void run(const matchers::MatchFinder::MatchResult& result) override {
            std::invoke(_handler, result, _functionInfo);
        }

    private:
        QueryCallback _handler;
        Analyzer* _analyzer;
        IDA::API::Function const& _functionInfo;
    };

    template <typename Q, typename QueryCallback>
    void ExecuteQuery(Analyzer* analyzer, clang::ASTContext& context, 
        IDA::API::Function const& function, Q&& query, QueryCallback handler)
    {
        MatchCallback callback{ handler, analyzer, function };

        matchers::MatchFinder finder;
        finder.addMatcher(query, &callback);
        finder.matchAST(context);
    }

    template <typename Handler>
    auto AnalyzeFunction(IDA::API::Function const& functionInfo, Handler handler, std::string_view sourceCode)
        -> std::invoke_result_t<Handler, clang::ASTContext&, IDA::API::Function const&>
    {
        using namespace clang;

        using return_type = std::invoke_result_t<Handler, clang::ASTContext&, IDA::API::Function const&>;

        auto executeAction = [&](std::unique_ptr<AST::FrontendAction> toolAction) -> void {
            // clang::tooling::runToolOnCodeWithArgs, with a custom diagnostics listener
            using namespace std::string_literals;

            std::vector<std::string> arguments{
                "dread-tool"s,
                "-std=c++20"s, "-fsyntax-only"s,
                std::format("{}.cpp", functionInfo.GetName())
            };
            // NOT USELESS - Twines take crvalues and store pointers.
            const Twine fileNameTwine{ arguments.back() };

            llvm::IntrusiveRefCntPtr ofs{ new llvm::vfs::OverlayFileSystem(llvm::vfs::getRealFileSystem()) };
            llvm::IntrusiveRefCntPtr mfs{ new llvm::vfs::InMemoryFileSystem() };
            ofs->pushOverlay(mfs);
            mfs->addFile(arguments.back(), 0, llvm::MemoryBuffer::getMemBuffer(sourceCode));

            // Virtual mapped files, we don't use these
            // FileContentMappings fcm;
            // for (auto&& [name, code] : fcm)
            //     mfs->addFile(name, 0, llvm::MemoryBuffer::getMemBuffer(code));

            llvm::IntrusiveRefCntPtr fs { new FileManager(FileSystemOptions{}, ofs) };

            tooling::ToolInvocation invocation{
                std::move(arguments), std::move(toolAction), fs.get()
            };

            clang::IgnoringDiagConsumer diagnosticConsumer;
            invocation.setDiagnosticConsumer(&diagnosticConsumer); // +
            invocation.run();
        };

        // TODO: Hopefully language features make it so that this can be simplified.
        if constexpr (!std::is_void_v<return_type>) {
            return_type result{};
            auto toolAction = std::make_unique<AST::FrontendAction>([&](ASTContext& context) {
                result = std::invoke(handler, context, functionInfo);
                });
            executeAction(std::move(toolAction));
            return result;
        }
        else {
            auto toolAction = std::make_unique<AST::FrontendAction>([&](ASTContext& context) {
                std::invoke(handler, context, functionInfo);
                });

            executeAction(std::move(toolAction));
        }
    }
}

std::string GeneratePseudocode(IDA::API::Function const& functionInfo, std::function<void(tinfo_t&)> returnTypeTransform) {
    auto modifyArgCallback = [](tinfo_t& argType) {
        if (argType.is_struct()) {
            // If the type is a struct, pretend it's the raw binary data
            // TODO: What about type alignment?
            array_type_data_t arrayData(0, argType.get_size());
            arrayData.elem_type = tinfo_t{ BTF_UINT8 };

            argType.create_array(arrayData);
        }
        else if (argType.is_ptr()) {
            // If it's a pointer to struct or function, change to uint64 
            // so that we can ignore it. Otherwise don't touch.
            tinfo_t pointedType = argType.get_pointed_object();
            if (pointedType.is_struct() || pointedType.is_func())
                argType = tinfo_t{ BTF_UINT64 };
        }
    };

    functionInfo.ModifyType([&](tinfo_t& argType, size_t argIndex) {
        if (argIndex == std::numeric_limits<size_t>::max()) {
            returnTypeTransform(argType);
        } else {
            modifyArgCallback(argType);
        }
    });

    std::stringstream assembledPseudocode;
    assembledPseudocode << "#include <" IDA_INCLUDE_DIR "/../../../plugins/defs.h>\n";

    for (ea_t reference : functionInfo.GetReferencesFrom(XREF_FAR)) {
        IDA::API::Function callee{ reference };
        std::string calleeName = callee.GetName();
        if (calleeName.empty())
            continue;

        callee.ModifyType([&](tinfo_t& argType, size_t argIndex) {
            if (argIndex == std::numeric_limits<size_t>::max())
                return;

            modifyArgCallback(argType);
        });

        assembledPseudocode << '\n' << callee.GetReturnType().ToString() << ' ';

        {
            size_t pos = calleeName.find('(');
            if (pos != std::string::npos)
                calleeName = calleeName.substr(0, pos);
        }

        assembledPseudocode << calleeName;
        assembledPseudocode << '(';
        for (size_t i = 0; i < callee.GetArgumentCount(); ++i) {
            if (i > 0)
                assembledPseudocode << ", ";
            assembledPseudocode << callee.GetArgumentType(i).ToString();
        }
        assembledPseudocode << "); // 0x" << std::format("{:016X}", reference);
    }

    for (ea_t reference : functionInfo.GetReferencesFrom(XREF_DATA)) {
        std::string name = get_name(reference).c_str();
        if (name.empty())
            continue;

        // Set data type to QWORD
        apply_tinfo(reference, tinfo_t{ BTF_UINT64 }, TINFO_GUESSED);
        assembledPseudocode << std::format("\n_QWORD {}; // 0x{:016x}", name,  reference);
    }

    assembledPseudocode << '\n';
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
                // If it's a struct, set it to an array matching the size of the structure
                // TODO: type alignment?
                array_type_data_t arrType(0, variableType.get_size());
                arrType.elem_type = tinfo_t{ BTF_UINT8 };

                tinfo_t newType;
                newType.create_array(arrType);
                localVariable.set_final_lvar_type(newType);
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

    replaceString(pseudocode, "`vtable for'", "vtbl_for_");
    replaceString(pseudocode, "::~", "__dtor_");
    replaceString(pseudocode, "::", "__");

    // Try **really** hard to get rid of casts
    // First pass removes casts to incomplete types
    pseudocode = std::regex_replace(pseudocode,
        std::regex{ R"(#[0-9]+ \*)" }, "void *");
    pseudocode = std::regex_replace(pseudocode,
        std::regex{ R"(\([^)(]+\)([a-z0-9_]+)([,).]))" }, "$1$2");

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

    std::unordered_map<std::string, ea_t> referencedFunctions;
    for (ea_t rva : functionInfo.GetReferencesFrom(XREF_FAR)) {
        if (!IDA::API::IsFunction(rva))
            continue;

        referencedFunctions.try_emplace(IDA::API::Function{ rva }.GetName(), rva);
    }

    Utils::ExecuteQuery(this, context, functionInfo, matchers::callExpr(
        matchers::forFunction(matchers::hasName(functionInfo.GetName())),
        matchers::hasArgument(0, matchers::stringLiteral().bind("stringLiteral")),
        matchers::hasArgument(1, matchers::integerLiteral().bind("integerLiteral"))
    ), [&](const matchers::MatchFinder::MatchResult& result, IDA::API::Function const& functionInfo) {
        auto stringLiteral = result.Nodes.getNodeAs<clang::StringLiteral>("stringLiteral");
        auto integerLiteral = result.Nodes.getNodeAs<clang::IntegerLiteral>("integerLiteral");

        if (stringLiteral == nullptr || integerLiteral == nullptr)
            return;

        assert(stringLiteral->getByteLength() == integerLiteral->getValue());
        reflInfo.Name = stringLiteral->getBytes();
    });

    Utils::ExecuteQuery(this, context, functionInfo, matchers::binaryOperator(
        matchers::forFunction(
            matchers::functionDecl(
                matchers::hasName(functionInfo.GetName()),
                matchers::hasParameter(0, matchers::parmVarDecl().bind("firstParmVar"))
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
                                matchers::ignoringParenCasts(
                                    matchers::declRefExpr().bind("declRef")
                                ),
                                matchers::ignoringParenCasts(
                                    matchers::integerLiteral().bind("offset")
                                )
                            )
                        )
                    )
                )
            ),
            matchers::ignoringParenCasts(
                matchers::expr(
                    matchers::anyOf(
                        // TODO: Change this if we manage to properly emit declarations for referenced functions here.
                        //       As it stands, we don't, because function pointers live in .got, and we take these as 
                        //       input for ldr/stp instructions:
                        //         .text:0000007101193000 LDR             X8, [X8,#off_7101CE6DF8@PAGEOFF] ; Load from Memory
                        //         .text:0000007101193004 STP             XZR, X8, [X19, #0x50]; Store Pair
                        //         ...
                        //         .got:0000007101CE6DF8  off_7101CE6DF8  DCQ unknown_libname_18115
                        //       Meaning that enumerated references from the function are data xrefs,
                        //         which get shoved up as _QWORD in our pseudocode.
                        matchers::hasDescendant(matchers::unresolvedLookupExpr().bind("value")),
                        // recoveryExpr(
                        //     matchers::unresolvedLookupExpr().bind("value")
                        // ),
                        matchers::integerLiteral().bind("value")
                    )
                )
            )
        )
    ), [&](const matchers::MatchFinder::MatchResult& result, IDA::API::Function const& functionInfo) {
        auto offset = result.Nodes.getNodeAs<clang::IntegerLiteral>("offset");
        auto value = result.Nodes.getNodeAs<clang::Expr>("value");
        auto declRef = result.Nodes.getNodeAs<clang::DeclRefExpr>("declRef");
        auto firstParm = result.Nodes.getNodeAs<clang::ParmVarDecl>("firstParmVar");

        if (offset == nullptr || value == nullptr || declRef == nullptr || firstParm == nullptr)
            return;

        // Asserts that the reference is on the first argument
        // TODO: make equalsBoundNode work somehow...
        if (declRef->getDecl() != firstParm)
            return;

        uint64_t propertyOffset = offset->getValue().getLimitedValue(std::numeric_limits<uint64_t>::max());

        if (const auto* integerLiteral = clang::dyn_cast<clang::IntegerLiteral>(value)) {
            reflInfo.Properties.try_emplace(propertyOffset,
                integerLiteral->getValue().getLimitedValue(std::numeric_limits<uint64_t>::max())
            );
        }
        else if (const auto* unresolvedLookup = clang::dyn_cast<clang::UnresolvedLookupExpr>(value)) {
            auto itr = referencedFunctions.find(unresolvedLookup->getName().getAsString());
            assert(itr != referencedFunctions.end());

            reflInfo.Properties.try_emplace(propertyOffset, itr->second);
        }
    });

    // This variation is necessary for reflobjects where the constructed object is inlined.
    return reflInfo;
}
