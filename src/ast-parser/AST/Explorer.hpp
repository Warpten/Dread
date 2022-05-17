#pragma once

#include <functional>

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

namespace clang {
	class ASTContext;
}

namespace AST {
	using namespace clang::ast_matchers;

	struct Explorer final {
		explicit Explorer(clang::ASTContext& context) noexcept;

		void Run();

		using Callback = std::function<void(MatchFinder::MatchResult const&)>;

		void AddMatcher(const DeclarationMatcher& NodeMatch, Callback Action);
		void AddMatcher(const TypeMatcher& NodeMatch, Callback Action);
		void AddMatcher(const StatementMatcher& NodeMatch, Callback Action);
		void AddMatcher(const NestedNameSpecifierMatcher& NodeMatch, Callback Action);
		void AddMatcher(const NestedNameSpecifierLocMatcher& NodeMatch, Callback Action);
		void AddMatcher(const TypeLocMatcher& NodeMatch, Callback Action);
		void AddMatcher(const CXXCtorInitializerMatcher& NodeMatch, Callback Action);
		void AddMatcher(const TemplateArgumentLocMatcher& NodeMatch, Callback Action);
		void AddMatcher(const AttrMatcher& NodeMatch, Callback Action);

	private:
		struct MatchCallback : MatchFinder::MatchCallback {
			explicit MatchCallback(Callback callback) noexcept;

			void run(const MatchFinder::MatchResult& Result) override;

		private:
			Callback _callback;
		};

		clang::ASTContext& _context;
		MatchFinder _matchFinder;
		std::vector<MatchCallback> _callbacks;
	};
}