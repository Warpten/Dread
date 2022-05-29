#pragma once

#include "Dread/Reflection/CType.hpp"

// dreadful-plugin-clang-base
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
    /// <summary>
    /// Analysis entry point.
    /// </summary>
    /// <param name="functionInfo">The function to analyze.</param>
    Dread::Reflection::CType::Store* Identify(IDA::API::Function const& functionInfo);

private:
    std::string GetPseudocode(const IDA::API::Function& functionInfo) const;

    template <typename T>
    T* Analyze(clang::ASTContext&, const IDA::API::Function&);

public: // clang::DiagnosticsConsumer
    void HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) override;
};
