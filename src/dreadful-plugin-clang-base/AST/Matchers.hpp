#pragma once

#include <llvm/ADT/StringRef.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchersInternal.h>
#include <clang/ASTMatchers/ASTMatchersMacros.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

#include "Explorer.hpp"

namespace custom_matchers {
    using namespace clang;
    using namespace clang::ast_matchers;
    using namespace clang::ast_matchers::internal;

    /// <summary>
    /// Matches a node if it has an RVA associated with it of the given value.
    /// </summary>
    AST_MATCHER_P(Decl, hasRVA, uint64_t, rva) {
        auto attr = Node.getAttr<AnnotateAttr>();
        if (attr == nullptr)
            return false;

        uint64_t value = 0;
        auto [_, ec] = std::from_chars(attr->getAnnotation().data() + 2, attr->getAnnotation().data() + attr->getAnnotationLength(), value, 16);
        if (ec != std::errc{})
            return false;

        return value == rva;
    }

    AST_MATCHER_P(Expr, ignoringAnyConstruct, Matcher<Expr>, InnerMatcher) {
        auto nextContext = Node.IgnoreParenCasts();

        if (auto constructExpr = dyn_cast<CXXConstructExpr>(nextContext)) {
            // If it's a call to Any::Any, ignore it, and test past
            bool isNamedDecl = namedDecl(hasName("Any"))
                .matches(*constructExpr->getConstructor(), Finder, Builder);
            if (isNamedDecl && constructExpr->getNumArgs() == 1) {
                return InnerMatcher.matches(*constructExpr->getArg(0), Finder, Builder);
            }
            
            // Otherwise match on this (or return false?)
            return InnerMatcher.matches(*nextContext, Finder, Builder);
        } else {
            return InnerMatcher.matches(*nextContext, Finder, Builder);
        }
    }

    namespace internal {
        template <typename T>
        struct FalseMatcherImpl : public MatcherInterface<T> {
            bool matches(const T&, ASTMatchFinder*, BoundNodesTreeBuilder*) const override {
                return false;
            }
        };
    }

    /// <summary>
    /// A matchers that matches nothing.
    /// </summary>
    /// <typeparam name="T">The type of the node the matcher would match, if it could match anything.</typeparam>
    template <typename T>
    inline Matcher<T> nothing() {
        return Matcher<T>(new internal::FalseMatcherImpl<T>());
    }

    using NeighborFilter = std::function<bool(const Stmt& /* node */, const Stmt* /* sibling */)>;
    AST_MATCHER_P2(Stmt, selectNeighbor, Matcher<Stmt>, InnerMatcher, NeighborFilter, Filter) {
        auto parents = Finder->getASTContext().getParents(Node);

        for (auto&& parent : parents) {
            if (const Stmt* parentStmt = parent.get<Stmt>()) {
                auto children = parentStmt->children();

                for (const Stmt* child : children) {
                    if (child == &Node || child == nullptr)
                        continue;

                    if (!InnerMatcher.matches(*child, Finder, Builder))
                        continue;

                    if (!Filter(Node, child))
                        continue;

                    return true;
                }
            }
        }

        return false;
    }

    namespace internal {
        template <typename SourceType, typename TargetType>
        class matcher_MatchesMatcher final
            : public MatcherInterface<SourceType> {

        public:
            matcher_MatchesMatcher(DynTypedMatcher const& innerMatcher,
                llvm::StringRef const& boundName,
                bool injectMatches)
                : boundName_(boundName), injectMatches_(injectMatches),
                innerMatcher_(innerMatcher)
            { }

            bool matches(const SourceType& node, ASTMatchFinder* finder,
                BoundNodesTreeBuilder* builder) const override 
            {
                ASTContext& context = finder->getASTContext();
                TranslationUnitDecl* translationUnit = context.getTranslationUnitDecl();
                DynTypedNode dynNode = DynTypedNode::create(node);

                BoundNodesTreeBuilder subTree(*builder);
                subTree.setBinding(boundName_, dynNode);

                bool matchesAnyDescendant = finder->matchesDescendantOf(*translationUnit,
                    innerMatcher_,
                    &subTree,
                    ASTMatchFinder::BK_All);

                if (injectMatches_) {
                    struct Visitor final : BoundNodesTreeBuilder::Visitor {
                        Visitor(BoundNodesTreeBuilder& subTree, llvm::StringRef const& boundName) : _subTree(subTree), _boundName(boundName) { }

                        void visitMatch(const BoundNodes& BoundNodesView) override {
                            for (auto&& [k, v] : BoundNodesView.getMap())
                                if (k != _boundName)
                                    _subTree.setBinding(k, v);
                        }

                    private:
                        BoundNodesTreeBuilder& _subTree;
                        llvm::StringRef const& _boundName;
                    } visitor(*builder, boundName_);

                    subTree.visitMatches(&visitor);
                }

                return matchesAnyDescendant;
            }

        private:
            DynTypedMatcher innerMatcher_;
            llvm::StringRef boundName_;
            bool injectMatches_;
        };
    }

    /// Matches nodes that match another query.
    /// 
    /// Given
    /// \code
    /// uint32_t y = 0;
    /// uint32_t x = foo();
    /// bar(x);
    /// bar(y);
    /// \endcode
    /// 
    /// callExpr(hasArgument(0, declRefExpr(matchesMatcher(binaryOperator(hasOperands(declRefExpr(equalsBoundNode("declRef")), callExpr())), "declRef"))))
    ///   matches 'bar(x);' but not 'bar(y);'.
    template <typename SourceType, typename TargetType>
    auto matchesMatcher(Matcher<TargetType> const& matcher,
        llvm::StringRef const& boundName, bool keepMatches) {
        return Matcher<SourceType>(
            new internal::matcher_MatchesMatcher<SourceType, TargetType>(matcher, boundName, keepMatches)
        );
    }

    /// <summary>
    /// Specific matcher for CRC64(const char*, size_t) calls.
    /// </summary>
    AST_MATCHER(CallExpr, crcCallExpr) {
        if (Node.getNumArgs() != 2)
            return false;

        auto stringLiteral = dyn_cast<StringLiteral>(Node.getArg(0));
        auto integerLiteral = dyn_cast<IntegerLiteral>(Node.getArg(1));
        if (stringLiteral == nullptr || integerLiteral == nullptr)
            return false;

        if (stringLiteral->getByteLength() != integerLiteral->getValue())
            return false;

        return true;
    }
}
