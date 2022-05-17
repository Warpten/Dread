#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

#include <clang/Tooling/Tooling.h>

namespace clang {
    class ASTContext;
}

namespace AST {
	struct Analyzer : private clang::DiagnosticConsumer {
		virtual ~Analyzer() { }

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

			return std::invoke(handler, astUnit->getASTContext());
		}

	public: // clang::DiagnosticConsumer
		virtual void HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) override = 0;
	};
}
