#include "Analyzer.hpp"
#include "Explorer.hpp"

namespace AST {
	using namespace clang::ast_matchers;

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
}
