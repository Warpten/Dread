#pragma once

#include "Dread/Utilities.hpp"

#include <clang/AST/ASTFwd.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

#include <AST/Matchers.hpp>
#include <CallableTraits/CallableTraits.hpp>
#include <IDA/API.hpp>

#include <functional>

namespace custom_matchers {
    using namespace clang;
    using namespace clang::ast_matchers;
    using namespace clang::ast_matchers::internal;

    AST_MATCHER_P2(Stmt, closestPreceding, llvm::StringRef, BoundRef, size_t, MaxDelta) {
        struct Visitor : BoundNodesTreeBuilder::Visitor {
            explicit Visitor(llvm::StringRef const& boundRef, const Stmt& node, 
                BoundNodesTreeBuilder* builder, ASTContext& context, size_t maxDelta)
                : _boundRef(boundRef), Node(node), Builder(builder), Context(context), MaxDelta(maxDelta)
            { }

            void visitMatch(const BoundNodes& BoundNodesView) override {
                auto boundReference = BoundNodesView.getNodeAs<clang::Stmt>(_boundRef);
                if (boundReference == nullptr)
                    return;

                auto&& sourceManager = Context.getSourceManager();
                auto refRange = boundReference->getSourceRange().getBegin();
                auto targetRange = Node.getSourceRange().getBegin();

                auto refLocation = sourceManager.getPresumedLineNumber(refRange);
                auto targetLocation = sourceManager.getPresumedLineNumber(targetRange);

                _matches = refLocation < targetLocation && (targetLocation - refLocation) <= MaxDelta;
            }

            bool Matches() const { return _matches; }

        private:
            bool _matches = false;

            llvm::StringRef _boundRef;

            size_t MaxDelta;
            const Stmt& Node;
            BoundNodesTreeBuilder* Builder;
            ASTContext& Context;
        } visitor(BoundRef, Node, Builder, Finder->getASTContext(), MaxDelta);

        Builder->visitMatches(&visitor);

        return visitor.Matches();
    };
}

namespace Dread::Reflection {
    namespace Types {
        /// <summary>
        /// Describes the semantic kind of a property value.
        /// </summary>
        enum class PropertySemanticKind : uint32_t {
            IntegerLiteral,
            RVA
        };

        struct CommonBase {
        protected:
            constexpr CommonBase(std::string_view kind) noexcept : _kind(kind) { }

        public:
            constexpr std::string_view Kind() const { return _kind; }

            virtual std::string_view TypeName() const = 0;
            virtual bool ProcessProperty(uint64_t offset, PropertySemanticKind semanticKind, uint64_t value) = 0;

            virtual clang::ast_matchers::internal::Matcher<clang::Stmt> MakeConstructorQuery(const clang::ast_matchers::DeclarationMatcher& declMatcher) = 0;
            virtual void ProcessConstructorQuery(const clang::ast_matchers::MatchFinder::MatchResult& matchResults) = 0;
        private:
            std::string_view _kind;
        };
    };

    namespace Traits {
        constexpr static const char Instance[] = "Instance";
        constexpr static const char TypeName[] = "TypeName";
        constexpr static const char BaseType[] = "BaseType";

        /// <summary>
        /// A parameter that extracts its value from an AST match as an AST node.
        /// </summary>
        /// <typeparam name="T">The type of the node to extract</typeparam>
        template <typename T, Utilities::Literal ID> struct NodeParameter {
            using value_type = const T*;

            static value_type Extract(const clang::ast_matchers::MatchFinder::MatchResult& result) {
                return result.Nodes.getNodeAs<T>(ID.Value);
            }

            constexpr static const std::string_view Name = ID.Value;
        };

        /// <summary>
        /// A parameter that extracts its value from the RVA associated with an AST node.
        /// 
        /// This is done by looking for a `clang::annotate` attribute on the node. The RVA
        /// is extracted from the annotation itself. If none is found, this returns `0uLL`.
        /// </summary>
        /// <typeparam name="T">The type of the node to extract</typeparam>
        template <typename T, Utilities::Literal ID>
        struct RVA {
            using value_type = uint64_t;

            static value_type Extract(const clang::ast_matchers::MatchFinder::MatchResult& result) {
                auto node = NodeParameter<T, ID>::Extract(result);
                if (node == nullptr)
                    return 0uLL;

                clang::AnnotateAttr* attr = node->getAttr<clang::AnnotateAttr>();
                if (attr == nullptr)
                    return 0uLL;

                uint64_t value = 0uLL;
                auto [_, ec] = std::from_chars(attr->getAnnotation().data() + 2, attr->getAnnotation().data() + attr->getAnnotationLength(), value, 16);
                if (ec != std::errc{ })
                    return 0uLL;

                return value;
            }

            constexpr static const std::string_view Name = ID.Value;
        };

        /// <summary>
        /// A parameter which extracts its value from a `StringLiteral` as the actual value
        /// of the string.
        /// </summary>
        template <Utilities::Literal ID>
        struct StringLiteral {
            using value_type = std::string_view;

            static value_type Extract(const clang::ast_matchers::MatchFinder::MatchResult& result) {
                using namespace std::string_view_literals;

                const clang::StringLiteral* node = NodeParameter<clang::StringLiteral, ID>::Extract(result);
                if (node == nullptr)
                    return ""sv;

                return std::string_view{ node->getBytes().data(), node->getByteLength()};
            }

            constexpr static const std::string_view Name = ID.Value;
        };

        /// <summary>
        /// Type trait that encapsulates the parameters of a given reflection object type.
        /// </summary>
        /// <typeparam name="...Ps">Parameter types</typeparam>
        template <typename... Ps>
        struct ConstructorTraits {
            using value_type = std::tuple<typename Ps::value_type...>;

            static value_type Extract(const clang::ast_matchers::MatchFinder::MatchResult& result) {
                return std::tuple{ Ps::Extract(result)... };
            }
        };

        template <size_t Offset, Types::PropertySemanticKind Kind, auto>
        struct PropertyInfo;

        template <size_t Offset, Types::PropertySemanticKind Kind, typename T, typename C, T C::*P>
        struct PropertyInfo<Offset, Kind, P> {
            static bool TryAssign(T* instance, size_t offset, Types::PropertySemanticKind kind, uint64_t value) {
                if (offset != Offset)
                    return false;

                if (kind != Kind) {
                    IDA::API::Message("(Dread) Invalid kind for value at {:x}: Expected {}, got {}.",
                        Offset, Kind, kind);
                    return false;
                }

                std::invoke(instance, P) = value;
                return true;
            }

            template <typename U, typename... Args>
            static auto TryAssign(U* instance, Args&&...)
                -> std::enable_if_t<!std::is_same_v<T, U>, bool>
            { return false; }
        };

        template <typename... Ps>
        struct PropertySequence {
            template <typename T>
            static bool TryProcess(T* instance, size_t offset, Types::PropertySemanticKind kind, uint64_t value) {
                return (Ps::TryAssign(instance, offset, kind, value) || ...);
            }
        };
    }

    namespace Shared {
        using namespace clang;
        using namespace clang::ast_matchers;
        using namespace clang::ast_matchers::internal;

        /// <summary>
        /// Constructs a query that looks for a call expression to a function
        /// taking at least two arguments.
        /// 
        /// The first argument to this function is 'this' (as in, it's the equivalent of a __thiscall).
        /// It is passed by reference from a variable, either local or global.
        /// If global, this means the call got inlined, which we don't really care about, but it does
        /// help us out.
        /// 
        /// The second argument to this function is the name of the type for which a ReflInfo is being
        /// constructed. It's of type `base::global::CStrId*`, and is passed as a reference to a value
        /// on the stack, since `CStrId` actually saves the string it represents in a static global
        /// pool.
        /// Note that the call to `base::global::CStrId`'s constructor can be inlined, in which case
        /// we look for a call to the function pooling the string.
        /// 
        /// The following arguments depend; see the individual documentation of the related 
        /// `MakeConstructorQuery` functions for more informations.
        /// </summary>
        /// <typeparam name="...Qs">Types of the matchers for other arguments</typeparam>
        /// <param name="declMatcher">A filtering query to exactly match the function of interest</param>
        /// <param name="...queries">Matchers for extra arguments</param>
        /// <returns></returns>
        template <typename... Qs>
        auto MakeConstructorQuery(DeclarationMatcher const& declMatcher, Qs&&... queries) -> Matcher<clang::Stmt> {
            return traverse(clang::TK_AsIs, callExpr(
                // Implicitely capture ourselves
                callExpr().bind("self"),

                callee(declMatcher),
                hasArgument(0, // 'this'
                    unaryOperator(hasOperatorName("&"), hasUnaryOperand(
                        declRefExpr(to(
                            varDecl(hasAttr(attr::Annotate)).bind(Traits::Instance)
                        ))
                    ))
                ),
                hasArgument(1, // base::global::CStrId* 'typeName'
                    unaryOperator(hasOperatorName("&"), hasUnaryOperand(
                        declRefExpr(to(
                            varDecl(
                                anyOf(
                                    // Nominal case
                                    custom_matchers::matchesMatcher<VarDecl>(
                                        callExpr(
                                            custom_matchers::closestPreceding("self", 5),

                                            hasArgument(0,
                                                unaryOperator(hasOperatorName("&"), hasUnaryOperand(
                                                    declRefExpr(to(
                                                        varDecl(equalsBoundNode("this"))
                                                    ))
                                                ))
                                            ),
                                            hasArgument(1, stringLiteral().bind(Traits::TypeName)),
                                            hasArgument(2, integerLiteral(equals(1)))
                                        ).bind("typeNameCallExpr"), "this", true),

                                    // Special case when base::global::CStrId is inlined
                                    // Look for the pooling call (https://i.imgur.com/mBQyMPW.png)
                                    custom_matchers::matchesMatcher<VarDecl>(
                                        binaryOperator(
                                            custom_matchers::closestPreceding("self", 15),

                                            hasOperatorName("="), hasOperands(
                                                declRefExpr(to(varDecl(equalsBoundNode("this")))),
                                                ignoringParenCasts(
                                                    callExpr(
                                                        hasArgument(2, stringLiteral().bind(Traits::TypeName))
                                                    ).bind("typeNameCallExpr")
                                                )
                                            )
                                        ), "this", true)
                                )
                            )
                        ))
                    ))
                ),
                std::forward<Qs&&>(queries)...
            ));
        }
    }
}