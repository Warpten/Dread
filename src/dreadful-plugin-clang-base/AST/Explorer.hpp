#pragma once

#include <functional>

#include <clang/AST/ASTContext.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

namespace AST {
	using namespace clang::ast_matchers;

	struct Explorer final {
		Explorer() = delete;
		Explorer(Explorer&&) = delete;
		Explorer(Explorer const&) = delete;

		explicit Explorer(clang::ASTContext& context) noexcept;

		void Run(clang::TraversalKind traversalKind = clang::TraversalKind::TK_AsIs);

		using Callback = std::function<void(MatchFinder::MatchResult const&)>;

		void AddMatcher(const DeclarationMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const TypeMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const StatementMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const NestedNameSpecifierMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const NestedNameSpecifierLocMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const TypeLocMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const CXXCtorInitializerMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const TemplateArgumentLocMatcher& nodeMatch, Callback&& action);
		void AddMatcher(const AttrMatcher& nodeMatch, Callback&& action);

		clang::TraversalKind GetTraversalKind() const { return _traversalKind; }

	private:
		clang::ASTContext& _context;
		clang::TraversalKind _traversalKind = clang::TraversalKind::TK_AsIs;
		MatchFinder _matchFinder;
		std::vector<MatchFinder::MatchCallback*> _callbacks;
	};
}