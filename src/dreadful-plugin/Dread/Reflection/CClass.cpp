#include "CClass.hpp"
#include "CType.hpp"

namespace Dread::Reflection::CClass {
    using namespace clang;
    using namespace clang::ast_matchers;
    using namespace clang::ast_matchers::internal;

    Store::Store() : CType::Store(), Types::CommonBase(Name) { }

    bool Store::ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) {
        if (CType::Store::ProcessProperty(offset, semanticKind, value))
            return true;

        return false;
    }
}
