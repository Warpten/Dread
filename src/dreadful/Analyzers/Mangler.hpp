#ifndef Mangler_hpp__
#define Mangler_hpp__

#include "ReflectiveType.hpp"

#include <string>

struct Mangler final {
    struct Result {
        std::string ObjectName;
        std::string Initialize;
        std::string InitializeSimple;
        std::string Get;
    };

    Result Execute(std::string fullyQualifiedTypeName, Analyzers::ReflectiveType instanceType) const;
};

#endif // Mangler_hpp__
