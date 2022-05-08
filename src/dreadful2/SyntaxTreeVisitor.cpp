#include "SyntaxTreeVisitor.hpp"

#include <memory>

#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchersInternal.h>

namespace matchers = clang::ast_matchers;

namespace AST {
    void Consumer::HandleTranslationUnit(clang::ASTContext& context) {
        _callback(context);
    }
}