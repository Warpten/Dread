#pragma once

#include "Shared.hpp"
#include "CType.hpp"

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

namespace Dread::Reflection::CPointerType {
    constexpr static const char Name[] = "base::reflection::CPointerType";

    struct Store : virtual CType::Store, virtual Types::CommonBase {
        explicit Store();

        void ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) override;
    };
}