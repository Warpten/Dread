#include "Explorer.hpp"

using namespace clang::ast_matchers;

struct Callback_ : MatchFinder::MatchCallback {
	explicit Callback_(AST::Explorer* explorer, AST::Explorer::Callback&& callback) noexcept 
		: _callback(std::move(callback)), _explorer(explorer)
	{

	}

	llvm::Optional<clang::TraversalKind> getCheckTraversalKind() const override {
		return _explorer->GetTraversalKind();
	}

	void run(const MatchFinder::MatchResult& Result) override {
		_callback(Result);
	}

private:
	AST::Explorer::Callback _callback;
	AST::Explorer* _explorer;
};

namespace AST {
	Explorer::Explorer(clang::ASTContext& context) noexcept : _context(context) { }

	void Explorer::Run(clang::TraversalKind traversalKind /* = clang::TraversalKind::TK_AsIs */) {
		_traversalKind = traversalKind;
		_context.getParentMapContext().setTraversalKind(traversalKind);

		_matchFinder.matchAST(_context);
	}

	void Explorer::AddMatcher(const DeclarationMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}

	void Explorer::AddMatcher(const TypeMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}

	void Explorer::AddMatcher(const StatementMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}
	
	void Explorer::AddMatcher(const NestedNameSpecifierMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}
	
	void Explorer::AddMatcher(const NestedNameSpecifierLocMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}
	
	void Explorer::AddMatcher(const TypeLocMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}
	
	void Explorer::AddMatcher(const CXXCtorInitializerMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}
	
	void Explorer::AddMatcher(const TemplateArgumentLocMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}
	
	void Explorer::AddMatcher(const AttrMatcher& nodeMatch, Callback&& action) {
		Callback_* callback = new Callback_(this, std::move(action));
		_callbacks.push_back(callback);

		_matchFinder.addMatcher(nodeMatch, callback);
	}

}