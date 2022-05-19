#pragma once

#include "Explorer.hpp"

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Tooling/Tooling.h>

namespace AST {
	using namespace clang::ast_matchers;

	struct Analyzer : private clang::DiagnosticConsumer {
		virtual ~Analyzer() { }

		std::vector<const clang::CallExpr*> CollectCallExpressions(clang::ASTContext& context) const;

		template <typename U, typename T, typename = std::enable_if_t<!std::is_pointer_v<U>> >
		auto Collect(clang::ASTContext& context, T&& matcher) const
			-> std::vector<std::conditional_t<std::is_same_v<U, clang::DynTypedNode>, clang::DynTypedNode, const U*>>
		{
			if constexpr (std::is_same_v<U, clang::DynTypedNode>) {
				std::vector<clang::DynTypedNode> collectedNodes;

				Explorer explorer(context);
				explorer.AddMatcher(matcher.bind("root"), [&](const MatchFinder::MatchResult& result) {
					collectedNodes.push_back(result.Nodes.getNode("root"));
				});
				explorer.Run();

				collectedNodes.shrink_to_fit();
				return collectedNodes;
			}
			else {
				std::vector<const T*> collectedNodes;

				Explorer explorer{ context };
				explorer.AddMatcher(matcher.bind("root"), [&](const MatchFinder::MatchResult& result) {
					collectedNodes.push_back(result.Nodes.getNodeAs<T>("root"));
				});
				explorer.Run();

				collectedNodes.shrink_to_fit();
				return collectedNodes;
			}
		}

		template <typename Handler>
		auto ParsePseudoCode(Handler&& handler, std::string_view sourceCode)
			-> std::invoke_result_t<Handler, clang::ASTContext&>
		{
			using namespace clang;
			using namespace std::string_literals;

			auto astUnit = tooling::buildASTFromCodeWithArgs(sourceCode,
				{ "-std=c++20"s, "-fsyntax-only"s },
				"disassembly.cpp",
				"dread-tool"s,
				std::make_shared<PCHContainerOperations>(),
				tooling::getClangStripDependencyFileAdjuster(),
				tooling::FileContentMappings(),
				this);

			using return_type = std::invoke_result_t<Handler, clang::ASTContext&>;

			if constexpr (!std::is_void_v<return_type>) {
				if (astUnit == nullptr)
					return return_type{};
			}
			else {
				if (astUnit == nullptr)
					return;
			}

			return handler(astUnit->getASTContext());
		}

	public: // clang::DiagnosticConsumer
		virtual void HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) override = 0;
	};
}
