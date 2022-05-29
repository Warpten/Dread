#pragma once

#include "Shared.hpp"
#include "CType.hpp"

#include <clang/AST/ASTFwd.h>
#include <clang/ASTMatchers/ASTMatchers.h>

namespace Dread::Reflection::CClass {
    constexpr static const char Name[] = "base::reflection::CClass";

    struct Store : virtual CType::Store, virtual Types::CommonBase {
        explicit Store();

        void ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) override;
    };
}
