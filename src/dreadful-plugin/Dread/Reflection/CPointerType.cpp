#include "CPointerType.hpp"

namespace Dread::Reflection::CPointerType {
    using namespace clang;
    using namespace clang::ast_matchers;
    using namespace clang::ast_matchers::internal;

    Store::Store() : CType::Store(), CommonBase(Name) { }

    void Store::ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) {
        switch (offset) {
            // case 0x??: // Pointee
            //  this->Pointee = value;
            break;
        }

        CType::Store::ProcessProperty(offset, semanticKind, value);
    }
}
