#pragma once

#include "Shared.hpp"
#include "CType.hpp"

namespace Dread::Reflection::CCollectionType {
    constexpr static const char Name[] = "base::reflection::CCollectionType";

    struct Store : virtual CType::Store, virtual Types::CommonBase {
        explicit Store();

        bool ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) override;
    };
}
