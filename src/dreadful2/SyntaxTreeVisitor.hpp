#pragma once

#include <clang/AST/ASTContext.h> 
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>

#include <functional>
#include <unordered_map>

namespace AST {
	struct Consumer : clang::ASTConsumer {
		Consumer(clang::ASTContext* context, std::function<void(clang::ASTContext&)> callback)
			: _callback(callback)
		{ }

		void HandleTranslationUnit(clang::ASTContext& context) override;

	private:
		std::function<void(clang::ASTContext&)> _callback;
	};

	struct FrontendAction : clang::ASTFrontendAction {
		explicit FrontendAction(std::function<void(clang::ASTContext&)> callback) 
			: _callback(callback) { }

		std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance& compiler,
			llvm::StringRef inFile) override
		{
			return std::make_unique<Consumer>(&compiler.getASTContext(), _callback);
		}

	private:
		std::function<void(clang::ASTContext&)> _callback;
	};
}
