#include "CCollectionType.hpp"
#include "CType.hpp"

namespace Dread::Reflection::CCollectionType {
    Store::Store() : CType::Store(), Types::CommonBase(Name) { }

    bool Store::ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) {
        if (CType::Store::ProcessProperty(offset, semanticKind, value))
            return true;

        return false;
    }
}
