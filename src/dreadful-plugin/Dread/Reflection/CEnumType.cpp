#include "CEnumType.hpp"

namespace Dread::Reflection::CEnumType {
    using namespace clang;
    using namespace clang::ast_matchers;
    using namespace clang::ast_matchers::internal;

    namespace Traits {
        using namespace Dread::Reflection::Traits;

        constexpr static const char IterateEnumerationMembers[] = "iterateEnumerationMembersFn";
    }

    Store::Store() : CType::Store(), Types::CommonBase(Name) { }

    void Store::ProcessConstructorQuery(const clang::ast_matchers::MatchFinder::MatchResult& matchResults) {
        using ConstructorArguments = Traits::ConstructorTraits<
            Traits::RVA<clang::VarDecl, Traits::Instance>,
            Traits::StringLiteral<Traits::TypeName>,
            Traits::RVA<clang::FunctionDecl, Traits::IterateEnumerationMembers>
        >;

        auto [instance, typeName, iterateEnumerationMembers] = ConstructorArguments::Extract(matchResults);
    }

    bool Store::ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) {
        if (CType::Store::ProcessProperty(offset, semanticKind, value))
            return true;

        return false;
    }

    Matcher<Stmt> Store::MakeConstructorQuery(const DeclarationMatcher& declMatcher) {
        return Dread::Reflection::Shared::MakeConstructorQuery(declMatcher,
            hasArgument(2,
                declRefExpr(to(functionDecl().bind(Traits::IterateEnumerationMembers)))
            )
        );
    }
}