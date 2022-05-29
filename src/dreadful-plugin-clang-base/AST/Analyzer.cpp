#include "Analyzer.hpp"
#include "Explorer.hpp"

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Rewrite/Frontend/FixItRewriter.h>

namespace AST {
    using namespace clang::ast_matchers;

    const internal::VariadicDynCastAllOfMatcher<clang::Stmt, clang::RecoveryExpr> recoveryExpr;

    std::vector<const clang::CallExpr*> Analyzer::CollectCallExpressions(clang::ASTContext& context) const {
        std::vector<const clang::CallExpr*> callExpressions;

        AST::Explorer finder(context);
        finder.AddMatcher(
            callExpr().bind("root"),
            [&](const MatchFinder::MatchResult& result) {
                callExpressions.push_back(result.Nodes.getNodeAs<clang::CallExpr>("root"));
            }
        );
        finder.Run();
        
        return callExpressions;
    }

    /*
    struct AutoFixConsumer : public clang::ASTConsumer, private MatchFinder::MatchCallback {
        using MatchResult = MatchFinder::MatchResult;

        explicit AutoFixConsumer() {
            const auto recoveryMatcher = recoveryExpr().bind("recoveryExpression");

            _matchFinder.addMatcher(recoveryMatcher, this);

        }

        // clang::ASTConsumer
        void HandleTranslationUnit(clang::ASTContext& context) override {
            _matchFinder.matchAST(context);
        }

    private:
        // MatchFinder::MatchCallback
        void run(const MatchResult& matchResult) override {
            auto recoveryNode = matchResult.Nodes.getNodeAs<clang::RecoveryExpr>("recoveryExpression");
            assert(recoveryNode != nullptr);

            auto context = matchResult.Context;
            auto&& diagnosticsEngine = context->getDiagnostics();

            // Create the fixit rewriter now
            if (_rewriter == nullptr) {
                struct Options : clang::FixItOptions {
                    Options() {
                        clang::FixItOptions::InPlace = true;
                    }

                    std::string RewriteFilename(const std::string& Filename, int& fd) override {
                        // Rewrite in-place.
                        fd = -1;
                        return Filename;
                    }
                };
                static Options options;

                _rewriter = std::make_unique<clang::FixItRewriter>(diagnosticsEngine, 
                    context->getSourceManager(), context->getLangOpts(), &options);

                diagnosticsEngine.setClient(_rewriter.get(), false);
            }
        }

    private:
        MatchFinder _matchFinder;
        std::unique_ptr<clang::FixItRewriter> _rewriter;
    };

    struct AutoFixAction : clang::FrontendAction {
        std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance& compilerInstance,
            llvm::StringRef fileName) override
        {
            return std::make_unique<AutoFixConsumer>();
        }
    };

    struct AutoFixActionFactory : clang::tooling::FrontendActionFactory {
        bool runInvocation(std::shared_ptr<CompilerInvocation> Invocation,
            clang::FileManager* Files,
            std::shared_ptr<clang::PCHContainerOperations> PCHContainerOps,
            clang::DiagnosticConsumer* DiagConsumer) {

        }
    };*/
}
