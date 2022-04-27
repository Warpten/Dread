#ifndef Analysers_ReflectiveType_hpp__
#define Analysers_ReflectiveType_hpp__

#include <cstdint>
#include <unordered_map>

namespace Analyzers {
    enum class ReflectiveType : uint8_t {
        Unknown = 0,
        CType,
        CPointerType,
        CEnumType,
        CClass,
        CCollectionType,
        CFunction,
        CEnumConstRef,
        CFlagsetConstRef,
        CFunction_ConstPtr, // CFunction const*
    };
}

#endif // Analysers_ReflectiveType_hpp__
