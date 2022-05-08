#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

namespace IDA::API {
    struct Function;
}

namespace clang {
    class ASTContext;
}

struct Analyzer final {
    struct ReflInfo {
        std::string Name;
        std::unordered_map<uint64_t /* offset */, uint64_t /* value */> Properties;
    };

    ReflInfo ProcessReflectionObjectConstruction(IDA::API::Function const& functionInfo);
    ReflInfo ProcessReflectionObjectConstruction(clang::ASTContext& context, IDA::API::Function const& functionInfo);

    void ProcessObject(IDA::API::Function const& functionInfo);
    void ProcessObject(clang::ASTContext& context, IDA::API::Function const& functionInfo);
};
