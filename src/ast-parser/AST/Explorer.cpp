#include "Explorer.hpp"

namespace AST {
	Explorer::Explorer(clang::ASTContext& context) noexcept : _context(context) { }

	void Explorer::Run() {
		_matchFinder.matchAST(_context);
	}

	void Explorer::AddMatcher(const DeclarationMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}

	void Explorer::AddMatcher(const TypeMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}
	void Explorer::AddMatcher(const StatementMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}
	void Explorer::AddMatcher(const NestedNameSpecifierMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}
	void Explorer::AddMatcher(const NestedNameSpecifierLocMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}
	void Explorer::AddMatcher(const TypeLocMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}
	void Explorer::AddMatcher(const CXXCtorInitializerMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}
	void Explorer::AddMatcher(const TemplateArgumentLocMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}
	void Explorer::AddMatcher(const AttrMatcher& nodeMatch, Callback action) {
		auto callback = _callbacks.emplace_back(action);
		_matchFinder.addMatcher(nodeMatch, std::addressof(callback));
	}

	Explorer::MatchCallback::MatchCallback(Callback callback) noexcept : _callback(callback) { }

	void Explorer::MatchCallback::run(const MatchFinder::MatchResult& result) {
		_callback(result);
	}
}