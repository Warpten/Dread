#include "CFlagsetType.hpp"

namespace Dread::Reflection::CFlagsetType {
    using namespace clang;
    using namespace clang::ast_matchers;
    using namespace clang::ast_matchers::internal;

    namespace Traits = Dread::Reflection::Traits;

    Store::Store() : CType::Store(), Types::CommonBase(Name)
    {

    }

    void Store::ProcessConstructorQuery(const MatchFinder::MatchResult& matchResults) {
        using ConstructorArguments = Traits::ConstructorTraits<
            Traits::RVA<clang::VarDecl, Traits::Instance>,
            Traits::StringLiteral<Traits::TypeName>
        >;

        auto [instance, typeName] = ConstructorArguments::Extract(matchResults);
    }

    void Store::ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) {

    }

    auto Store::MakeConstructorQuery(const DeclarationMatcher& declMatcher) -> Matcher<Stmt> {
        return Dread::Reflection::Shared::MakeConstructorQuery(declMatcher);
    }
}