#include "CType.hpp"

namespace Dread::Reflection::CType {
    using namespace clang;
    using namespace clang::ast_matchers;
    using namespace clang::ast_matchers::internal;

    namespace Traits {
        using namespace Dread::Reflection::Traits;

        constexpr static const char FirstFunction[] = "firstFunction";
        constexpr static const char SecondFunction[] = "secondFunction";
    }

    Store::Store() : CommonBase(Name) { }

    void Store::ProcessConstructorQuery(const MatchFinder::MatchResult& matchResults) {
        using ConstructorArguments = Traits::ConstructorTraits<
            Traits::RVA<clang::VarDecl, Traits::Instance>,
            Traits::StringLiteral<Traits::TypeName>,
            Traits::RVA<clang::Decl, Traits::BaseType>,
            Traits::RVA<clang::FunctionDecl, Traits::FirstFunction>,
            Traits::RVA<clang::FunctionDecl, Traits::SecondFunction>
        >;

        auto [instance, typeName, baseType, firstFunction, secondFunction] = ConstructorArguments::Extract(matchResults);

        ProcessCommonConstructorArguments(instance, typeName, baseType);
    }

    void Store::ProcessCommonConstructorArguments(uint64_t instanceRVA, std::string_view typeName, uint64_t baseTypeRVA) {
        _instanceRVA = instanceRVA;
        _typeName.assign(typeName);
        _baseType.RVA = baseTypeRVA;
    }

    bool Store::ProcessProperty(uint64_t offset, Types::PropertySemanticKind semanticKind, uint64_t value) {
        using PropertySequence = Traits::PropertySequence<
            Traits::PropertyInfo<0x18, Types::PropertySemanticKind::IntegerLiteral, &Store::_typeSize>,
            Traits::PropertyInfo<0x28, Types::PropertySemanticKind::RVA, &Store::_constructorRVA>,
            Traits::PropertyInfo<0x30, Types::PropertySemanticKind::RVA, &Store::_copyConstructorRVA>,
            Traits::PropertyInfo<0x38, Types::PropertySemanticKind::RVA, &Store::_moveConstructorRVA>,
            Traits::PropertyInfo<0x40, Types::PropertySemanticKind::RVA, &Store::_destructorRVA>,
            // 0x48 fptr
            // 0x50 fptr
            Traits::PropertyInfo<0x58, Types::PropertySemanticKind::RVA, &Store::_equalityComparerRVA>,
            Traits::PropertyInfo<0x60, Types::PropertySemanticKind::RVA, &Store::_hashCodeRVA>,
            Traits::PropertyInfo<0x68, Types::PropertySemanticKind::RVA, &Store::_getReflInfoRVA>
        >;

        return PropertySequence::TryProcess(this, offset, semanticKind, value);
    }

    Matcher<Stmt> Store::MakeConstructorQuery(clang::ast_matchers::DeclarationMatcher const& declMatcher) 
    {
        return Dread::Reflection::Shared::MakeConstructorQuery(declMatcher,
            hasArgument(2, anyOf(
                // Reference to variable assigned from call.
                declRefExpr(to(
                    varDecl(
                        custom_matchers::matchesMatcher<VarDecl>(
                            binaryOperator(hasOperatorName("="), hasOperands(
                                declRefExpr(to(equalsBoundNode("this"))),
                                ignoringParenCasts(
                                    callExpr(argumentCountIs(0), callee(
                                        functionDecl(hasAttr(attr::Annotate)).bind(Traits::BaseType))
                                    )
                                )
                            )), "this", true
                        )
                    )
                )),
                // Unary operator to global variable.
                unaryOperator(hasOperatorName("&"), hasUnaryOperand(
                    declRefExpr(to(
                        varDecl(hasAttr(attr::Annotate)).bind(Traits::BaseType)
                    ))
                )),
                // 0 (no base type, possible if there are other parameters - fptrs)
                integerLiteral(equals(0))
            )),
            hasArgument(3,
                declRefExpr(to(functionDecl().bind(Traits::FirstFunction)))
            ),
            hasArgument(4,
                declRefExpr(to(functionDecl().bind(Traits::SecondFunction)))
            )
        );
    }
}
