#pragma once

#include "Shared.hpp"

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

namespace Dread::Reflection::CType {
    constexpr static const char Name[] = "base::reflection::CType";

    struct Store : virtual Types::CommonBase {
        explicit Store();

        void ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value);

        auto MakeConstructorQuery(const clang::ast_matchers::DeclarationMatcher& declMatcher)
            -> clang::ast_matchers::internal::Matcher<clang::Stmt> override;

        void ProcessConstructorQuery(const clang::ast_matchers::MatchFinder::MatchResult& matchResults) override;

        std::string_view TypeName() const override final { return _typeName; }

    protected:
        void ProcessCommonConstructorArguments(uint64_t instanceRVA, std::string_view typeName, uint64_t baseTypeRVA);

    private:
        std::string _typeName;
        union {
            Store* Value;
            uint64_t RVA = 0;
        } _baseType;
        uint64_t _instanceRVA = 0;
    };
}