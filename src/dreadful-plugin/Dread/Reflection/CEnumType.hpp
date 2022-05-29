#pragma once

#include "Shared.hpp"
#include "CType.hpp"

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

namespace Dread::Reflection::CEnumType {
    constexpr static const char Name[] = "base::reflection::CEnumType";

    struct Store : virtual CType::Store, virtual Types::CommonBase {
        explicit Store();

        void ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) override;

        auto MakeConstructorQuery(const clang::ast_matchers::DeclarationMatcher& declMatcher)
            -> clang::ast_matchers::internal::Matcher<clang::Stmt> override;

        void ProcessConstructorQuery(const clang::ast_matchers::MatchFinder::MatchResult& matchResults) override;
    };
}
