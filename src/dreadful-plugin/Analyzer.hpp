#pragma once

// dreadful-ast-parser
#include <AST/Analyzer.hpp>

// std
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

struct Analyzer final : AST::Analyzer {
    struct ReflInfo {
        std::string Name;
        std::string TypeName;

        uint64_t Self = 0;
        std::unordered_map<uint64_t /* offset */, uint64_t /* value */> Properties;
    };

    ReflInfo ProcessReflectionObjectConstruction(IDA::API::Function const& functionInfo);
    ReflInfo ProcessReflectionObjectConstruction(clang::ASTContext& context, IDA::API::Function const& functionInfo);

	void ProcessReflectionObjectConstructionCall(IDA::API::Function const& functionInfo, ReflInfo& reflInfo, uint64_t reflCtor);
	void ProcessReflectionObjectConstructionCall(clang::ASTContext& context, IDA::API::Function const& functionInfo, ReflInfo& reflInfo, uint64_t reflCtor);

    void ProcessObject(IDA::API::Function const& functionInfo, ReflInfo& reflInfo);
    void ProcessObject(clang::ASTContext& context, IDA::API::Function const& functionInfo, ReflInfo& reflInfo);

public:
    void HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) override;
};
