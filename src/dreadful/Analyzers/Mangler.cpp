#include "Mangler.hpp"
#include "IDA/API/API.hpp"

#include <regex>
#include <span>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include <clang/AST/Mangle.h> 
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Tooling/Tooling.h>

#if _DEBUG
namespace utils {
    struct DiagConsumer : clang::DiagnosticConsumer {
        void HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) override {
            if (diagLevel == clang::DiagnosticsEngine::Level::Ignored)
                return;

            clang::SmallString<64> message;
            info.FormatDiagnostic(message);

            IDA::API::LogMessage("Diagnostic emitted by Clang: {}.\r\n", message.c_str());
        }
    };

    std::unique_ptr<clang::ASTUnit> generateAST(llvm::StringRef source, std::string_view filename,
        std::string_view toolname,
#if _DEBUG
        clang::DiagnosticConsumer* consumer = new utils::DiagConsumer()
#else
        clang::DiagnosticConsumer * consumer = new clang::IgnoringDiagConsumer()
#endif
    );
}
#endif

namespace utils {
    struct TreeNode;
    struct Namespace;
    struct Type;
    struct TemplateType;

    struct Node : std::enable_shared_from_this<Node> {
        explicit Node() noexcept : _owner(nullptr) { }

        virtual ~Node() {
            deleteFromParent();
        }

        Node(Node const&) = delete;
        Node(Node&&) = delete;

        void deleteFromParent() {
            if (_owner != nullptr)
                _owner->deleteChild(this->shared_from_this());
        }

        virtual void deleteChild(std::shared_ptr<Node> node) {
            std::shared_ptr<Type> type = node->toType();
            if (type == nullptr)
                return;

            std::ranges::remove(_types, type);
        }

        /// <summary>
        /// Reinterprets the current node as a namespace. Returns nullptr if not able to.
        /// </summary>
        virtual std::shared_ptr<Namespace> toNamespace() { return nullptr; }
        /// <summary>
        /// Reinterprets the current node as a type. Returns nullptr if not able to.
        /// </summary>
        virtual std::shared_ptr<Type> toType() { return nullptr; }

        /// <summary>
        /// Reinterprets the current node as a namespace. Returns nullptr if not able to.
        /// </summary>
        virtual std::shared_ptr<const Namespace> toNamespace() const { return nullptr; }
        /// <summary>
        /// Reinterprets the current node as a type. Returns nullptr if not able to.
        /// </summary>
        virtual std::shared_ptr<const Type> toType() const { return nullptr; }

        /// <summary>
        /// Adds a type to the node.
        /// </summary>
        /// <param name="name">The name of the type to add</param>
        /// <returns>An instance of said type</returns>
        std::shared_ptr<Type> beginType(std::string_view name);

        /// <summary>
        /// Gets the node in which this node is declared, or nullptr if this node is declared in the
        /// global scope.
        /// </summary>
        std::shared_ptr<Node> getDeclarationNode() const { return _owner; }

        /// <summary>
        /// Gets the name of this node.
        /// </summary>
        virtual std::string_view getName() const = 0;

        /// <summary>
        /// Returns a fully qualified string representation of this type.
        /// </summary>
        virtual std::string toString() const = 0;

        /// <summary>
        /// Returns all types nested in this node.
        /// </summary>
        /// <returns></returns>
        std::vector<std::shared_ptr<Type>> const& getDeclaredTypes() const { return _types; }

    protected:
        explicit Node(std::shared_ptr<Node> owner) noexcept : _owner(owner) { }

    private:
        std::vector<std::shared_ptr<Type>> _types;
        std::shared_ptr<Node> _owner;
    };

    struct Namespace final : Node {
        Namespace(std::string_view name, std::shared_ptr<Node> owner = nullptr) noexcept : Node(owner), _name(name) { }

        Namespace() = delete;
        Namespace(Namespace const&) = delete;
        Namespace(Namespace&&) = delete;

        std::shared_ptr<const Namespace> toNamespace() const override { return std::reinterpret_pointer_cast<const Namespace>(this->shared_from_this()); }
        std::shared_ptr<Namespace> toNamespace() override { return std::reinterpret_pointer_cast<Namespace>(this->shared_from_this()); }

        std::string_view getName() const override { return _name; }

        std::string toString() const override;

    private:
        std::string_view _name;
        std::vector<std::shared_ptr<Namespace>> _nestedNamespaces;
    };

    struct Type final : Node {
        Type(std::string_view name, std::shared_ptr<Node> owner = nullptr) noexcept;

        Type(Type const&) = delete;
        Type(Type&&) = delete;

        void setConst() { _const = true; }
        void setPointer() { _pointer = true; }
        
        bool isBuiltin() const;
        std::string getUnqualifiedName() const;

        std::shared_ptr<Type> toType() override { return std::reinterpret_pointer_cast<Type>(this->shared_from_this()); }
        std::shared_ptr<const Type> toType() const override { return std::reinterpret_pointer_cast<const Type>(this->shared_from_this()); }

        std::string_view getName() const override { return _name; }

        std::string toString() const override;

        void addTypeParameter(std::shared_ptr<Type> type) { _templateTypes.push_back(type); }
        std::vector<std::shared_ptr<Type>> const& getTypeParameters() const { return _templateTypes; }

        bool isTemplateInstanciation() const { return !_templateTypes.empty(); }

    private:
        std::pair<std::unique_ptr<clang::ASTUnit>, const clang::QualType> _getTypeNode() const;

        std::string_view _name;

    protected:
        bool _const = false;
        bool _pointer = false;

        std::vector<std::shared_ptr<Type>> _templateTypes;
    };

    // -- Node --

    std::shared_ptr<Type> Node::beginType(std::string_view name) {
        return _types.emplace_back(std::make_shared<Type>(name, this->shared_from_this()));
    }

    // -- Namespace --

    std::string Namespace::toString() const {
        std::stringstream ss;
        if (std::shared_ptr<Node> declarationNode = getDeclarationNode())
            ss << declarationNode->toString() << "::";
        ss << getName();
        return ss.str();
    }

    // -- Type --

    Type::Type(std::string_view name, std::shared_ptr<Node> owner) noexcept : Node(owner), _name(name) { }

    std::string Type::toString() const {
        std::stringstream ss;
        if (std::shared_ptr<Node> declarationNode = getDeclarationNode())
            ss << declarationNode->toString() << "::";

        ss << getName();
        if (!_templateTypes.empty()) {
            ss << '<';
            for (size_t i = 0; i < _templateTypes.size(); ++i) {
                if (i > 0)
                    ss << ", ";

                ss << _templateTypes[i]->toString();
            }
            ss << '>';
        }

        if (_const) ss << " const";
        if (_pointer) ss << '*';
        return ss.str();
    }

    std::pair<std::unique_ptr<clang::ASTUnit>, const clang::QualType> Type::_getTypeNode() const {
        constexpr static const char TYPEDEF_NAME[] = "some_type";
        std::string source = std::format("using {} = {}", TYPEDEF_NAME, getName());

        struct Consumer final : clang::DiagnosticConsumer {
            void HandleDiagnostic(clang::DiagnosticsEngine::Level diagLevel, const clang::Diagnostic& info) override {
                errorFound |= diagLevel == clang::DiagnosticsEngine::Level::Error;
            }

            bool errorFound = false;
        };

        auto c = new Consumer();
        std::unique_ptr<clang::ASTUnit> ast = utils::generateAST(source, "type-test.cpp", "is-builtin", c);
        if (c->errorFound)
            return std::pair{ nullptr, clang::QualType() };

        namespace matchers = clang::ast_matchers;
        auto const matcher = matchers::typeAliasDecl(
            matchers::hasName(TYPEDEF_NAME),
            matchers::hasDescendant(
                matchers::typeLoc(
                    matchers::loc(
                        matchers::type()
                    ).bind("unqualifiedAliasedType")
                )
            )
        );

        const clang::TypeLoc* aliasedType = matchers::selectFirst<clang::TypeLoc>("unqualifiedAliasedType",
            matchers::match(matcher, ast->getASTContext()));

        return std::pair{ std::move(ast), aliasedType->getType().getUnqualifiedType() };
    }

    std::string Type::getUnqualifiedName() const {
        auto [ast, type] = _getTypeNode();
        if (type.isNull()) {
            // Help
        }

        return type.getAsString();
    }

    bool Type::isBuiltin() const {
        auto [ast, type] = _getTypeNode();
        return !type.isNull() && clang::isa<clang::BuiltinType>(type.getTypePtr());
    }

    // Utilities

    template <typename T, typename U = T, typename... Args>
    requires std::derived_from<T, U>
    std::shared_ptr<U> chain(std::shared_ptr<Node> parent, Args&&... args) {
        if (parent == nullptr)
            return std::make_shared<T>(std::forward<Args&&>(args)...);
        return std::make_shared<T>(std::forward<Args&&>(args)..., parent);
    }

    std::string toString(std::shared_ptr<Node> node) {
        if (node == nullptr) return "";
        return node->toString();
    }

    // -- EvaluationContext --

    struct EvaluationContext {
        struct Stack {
            std::deque<std::shared_ptr<Node>> Context;

            /// <summary>
            /// Finalizes the last element on the stack to become a type.
            /// </summary>
            /// <returns>The type created, nullptr if the stack is empty.</returns>
            std::shared_ptr<Type> finalizeType() {
                if (Context.empty())
                    return nullptr;

                std::shared_ptr<Node> node = Context.back();
                if (std::shared_ptr<Type> type = node->toType(); type != nullptr)
                    return type;

                // Convert to a type
                std::shared_ptr<Node> parent = node->getDeclarationNode();
                std::shared_ptr<Type> type = chain<Type>(parent, node->getName());

                node->deleteFromParent();

                Context.pop_back();
                Context.push_back(type);
                return type;
            }
        };

        Stack& getCurrentContext() {
            if (_evaluationStacks.empty())
                return openContext();

            return _evaluationStacks.back();
        }

        std::shared_ptr<Node> getCurrentNode() const {
            if (_evaluationStacks.empty())
                return nullptr;

            auto&& stack = _evaluationStacks.back();
            if (stack.Context.empty())
                return nullptr;

            return stack.Context.back();
        }

        std::shared_ptr<Type> getCurrentType() {
            std::shared_ptr<Node> node = getCurrentNode();
            if (node == nullptr)
                return nullptr;
            
            return node->toType();
        }

        std::shared_ptr<Node> processModifier(std::string_view token) {
            std::shared_ptr<Type> type = getCurrentType();
            if (type == nullptr)
                return nullptr;

            if (token == "const") {
                type->setConst();
            }

            return type;
        }

        std::shared_ptr<Node> processToken(std::string_view token) {
            if (token.empty())
                return getCurrentNode();

            Stack& evaluationContext = getCurrentContext();
            // Can't use getCurrentNode() because that does not return a reference!
            std::shared_ptr<Node> parent = getCurrentNode();

            if (token == "const") {
                return processModifier(token);
            } else {
                std::shared_ptr<Node> child = nullptr;

                // If the parent is a type, we're a type.
                constexpr static const char* builtins[] = {
                    "int",  "unsigned int",
                    "long", "unsigned long",
                    "long long", "unsigned long long",
                    "float",
                    "double",
                    "char",
                    "short",
                };
                bool createType = parent != nullptr && parent->toType() != nullptr;
                if (!createType) {
                    createType |= token[0] >= 'A' && token[0] <= 'Z';
                    if (!createType) {
                        for (const char* builtin : builtins)
                            createType |= token == builtin;
                    }
                }

                child = createType ? chain<Type, Node>(parent, token) : chain<Namespace, Node>(parent, token);

                // Remove the parent from the stack if it exists
                if (!evaluationContext.Context.empty())
                    evaluationContext.Context.pop_back();
                evaluationContext.Context.push_back(child);
                return child;
            }
        }

        Stack& openContext() {
            return _evaluationStacks.emplace_back();
        }

        Stack closeContext() {
            assert(!_evaluationStacks.empty());

            Stack back = _evaluationStacks.back();
            _evaluationStacks.pop_back();
            return back;
        }

    private:
        std::vector<Stack> _evaluationStacks;
    };

    std::unique_ptr<clang::ASTUnit> generateAST(llvm::StringRef source, std::string_view filename,
        std::string_view toolname, clang::DiagnosticConsumer* consumer)
    {
        namespace tooling = clang::tooling;

        return tooling::buildASTFromCodeWithArgs(source,
            /* Args = */{ "-std=c++20", "-fsyntax-only" },
            /* FileName = */filename,
            /* ToolName = */toolname,
            /* PCHContainerOps = */std::make_shared<clang::PCHContainerOperations>(),
            /* Adjuster */tooling::getClangStripDependencyFileAdjuster(),
            /* VirtualMappedFiles = */tooling::FileContentMappings{},
            consumer);
    }

    static const struct {
        char Token;
        size_t Delta;
        std::function<void(std::string_view, EvaluationContext&)> Handler;
    } delimiters[] = {
        {
            ':', 2uLL, [](std::string_view input, EvaluationContext& evalCtx) {
                evalCtx.processToken(input);
            }
        }, {
            '<', 1uLL, [](std::string_view input, EvaluationContext& evalCtx) {
                EvaluationContext::Stack& evalStack = evalCtx.getCurrentContext();

                evalCtx.processToken(input);
                
                evalStack.finalizeType();
                evalCtx.openContext();
            }
        }, {
            '>', 1uLL, [](std::string_view input, EvaluationContext& evalCtx) {
                evalCtx.processToken(input);

                EvaluationContext::Stack tplStack = evalCtx.closeContext();
                std::shared_ptr<utils::Type> templatedType = tplStack.finalizeType();

                assert(!evalCtx.getCurrentContext().Context.empty());

                for (std::shared_ptr<Node> templateParameter : tplStack.Context) {
                    std::shared_ptr<Type> type = templateParameter->toType();
                    assert(type != nullptr);

                    templatedType->addTypeParameter(type);
                }
            }
        }, {
            ',', 1uLL, [](std::string_view input, EvaluationContext& evalCtx) {
                // Replace the back of the stack by a type
                evalCtx.getCurrentContext().finalizeType();
            }
        }, {
            '*', 1uLL, [](std::string_view input, EvaluationContext& evalCtx) {
                evalCtx.processToken(input);
                evalCtx.processModifier("*");
            }
        }
    };

    std::shared_ptr<Type> parse(std::string_view input) {
        static auto find_delimiter = [](std::string_view input) -> size_t {
            const char* itr = input.data();
            const char* end = itr + input.size();
            while (itr < end) {
                for (auto&& delimInfo : delimiters)
                    if (*itr == delimInfo.Token)
                        return static_cast<size_t>(itr - input.data());

                ++itr;
            }

            return std::string_view::npos;
        };

        EvaluationContext evaluationStack;
        while (!input.empty()) {
            size_t index = find_delimiter(input);
            bool tokenFound = false;
            if (index == std::string_view::npos) {
                // The whole string is a token but we have no token
                // to determine what to do.
                // Just add a type.
                evaluationStack.processToken(input);
                evaluationStack.getCurrentContext().finalizeType();
                break;
            }

            char delimiter = input[index];
            for (auto&& delimInfo : delimiters) {
                tokenFound = delimInfo.Token == delimiter;
                if (!tokenFound)
                    continue;

                std::string_view token = input.substr(0, index);
                input.remove_prefix(token.size() + delimInfo.Delta);
                delimInfo.Handler(token, evaluationStack);
                break;
            }

            if (!tokenFound)
                break;
        }

        EvaluationContext::Stack finalStack = evaluationStack.closeContext();
        assert(finalStack.Context.size() == 1 && finalStack.Context.front()->toType() != nullptr);
        return finalStack.Context.front()->toType();
    }

    bool enumerateTypes(std::shared_ptr<Node> node, std::unordered_set<std::shared_ptr<Type>>& container, std::unordered_set<std::shared_ptr<Node>>& visitedNodes) {
        if (visitedNodes.contains(node))
            return true;

        for (std::shared_ptr<Type> declaredType : node->getDeclaredTypes())
        {
            // Template parameters first
            for (std::shared_ptr<Type> tplType : declaredType->getTypeParameters())
                enumerateTypes(tplType, container, visitedNodes);

            // Declared nested types
            enumerateTypes(declaredType, container, visitedNodes);
        }

        if (std::shared_ptr<Type> type = node->toType()) {
            container.insert(type);
            visitedNodes.insert(type);
        }

        // Collect types in declaring context.
        // Do this **after** adding the current type
        // so that we don't add it forever.
        if (std::shared_ptr<Node> parent = node->getDeclarationNode())
            enumerateTypes(parent, container, visitedNodes);

        return true;
    }

    std::unordered_multimap<std::string, std::shared_ptr<Type>> collectTypes(std::unordered_set<std::shared_ptr<Type>> types) {
        std::unordered_multimap<std::string, std::shared_ptr<Type>> result;

        for (std::shared_ptr<Type> type : types) {
            std::shared_ptr<Node> declaringNode = type->getDeclarationNode();

            std::string declaringName = utils::toString(declaringNode);

            result.emplace(declaringName, type);
        }

        return result;
    }
    
    void macroize(std::shared_ptr<Node> type, std::stringstream& ss) {
        if (std::shared_ptr<Node> parent = type->getDeclarationNode())
            macroize(parent, ss);

        ss << '_' << std::regex_replace(std::string{ type->getName() }, std::regex("\\*"), "_PTR");
    }

    std::string generateDefineGuard(std::shared_ptr<Type> type, bool includeTemplateParameters) {
        std::stringstream ss;
        macroize(type, ss);
        
        if (includeTemplateParameters) {
            for (std::shared_ptr<Type> templateParam : type->getTypeParameters())
                macroize(templateParam, ss);
        }

        ss << "_DEFINED"; // If you change this suffix, make sure to change it in the template below.
        std::string macroName = ss.str();
        std::transform(macroName.begin(), macroName.end(), macroName.begin(), [](unsigned char c) { return std::toupper(c); });
        return macroName;
    }
}

constexpr static const char evaluationTemplate[] = R"(
// Scaffolding code for Clang to generate a valid AST.

namespace std {
  template <typename T>
  struct default_deleter { /* unspecified */ };

  template <typename T, typename D = default_deleter<T>>
  struct unique_ptr { /* unspecified */ };

  template <typename T>
  struct shared_ptr { /* unspecified */ };

  struct mutex { /* unspecified */ };
  
  template <typename T> struct lock_guard { /* unspecified */ };

  enum class memory_order {
    relaxed, consume, acquire, release, acq_rel, seq_cst
  };
  inline constexpr memory_order memory_order_relaxed = memory_order::relaxed;
  inline constexpr memory_order memory_order_consume = memory_order::consume;
  inline constexpr memory_order memory_order_acquire = memory_order::acquire;
  inline constexpr memory_order memory_order_release = memory_order::release;
  inline constexpr memory_order memory_order_acq_rel = memory_order::acq_rel;
  inline constexpr memory_order memory_order_seq_cst = memory_order::seq_cst;

  template <typename T> struct atomic {
    bool compare_exchange_weak(T&, T, memory_order, memory_order) noexcept;
    bool compare_exchange_strong(T&, T, memory_order) noexcept;
  };
} // namespace std

namespace base {
  namespace reflection {
    struct CType { };
    struct CClass : CType { };
    struct CEnumType : CType { };
    struct CPointerType : CType { };
    struct CCollectionType : CType { };
  }

  namespace global {
    struct CStrId { };
  }
} // namespace base

namespace reflection {
  // T: Type of the reflected object.
  template <typename T>
  struct Meta {
    // Hello future me. This is past you. You may be wondering why
    // `static ... _instance` et al. are not here.
    // Because all I do is generate an AST and use it to produce
    // mangled names, I need to have the synthesized types in the
    // AST. As such, the base specialization of this type will
    // be empty, and explicit template specializations will contain
    // the expected static members, already specialized.
    // TL;DR: Do not touch.
  };
} // namespace reflection)";

#pragma warning(disable: 4715)
auto getReflTypeName(Analyzers::ReflectiveType instanceType)
{
    switch (instanceType) {
        case Analyzers::ReflectiveType::CClass:
            return "base::reflection::CClass";
        case Analyzers::ReflectiveType::CType:
            return "base::reflection::CType";
        case Analyzers::ReflectiveType::CEnumType:
            return "base::reflection::CEnumType";
        case Analyzers::ReflectiveType::CPointerType:
            return "base::reflection::CPointerType";
        default:
#if _DEBUG
            assert(false && "Unknown reflobject instance type");
#else
            __assume(false);
#endif
    }
#pragma warning(default: 4715)
}

std::pair<std::string, std::shared_ptr<utils::Type>> _ScaffoldSourceCode(std::string_view fullyQualifiedType, Analyzers::ReflectiveType instanceType) {
    std::shared_ptr<utils::Type> symbolTree = utils::parse(fullyQualifiedType);
    if (symbolTree == nullptr)
        return std::pair{ "", nullptr };

    // Emit forward declarations for all types in the symbol tree.
    std::unordered_set<std::shared_ptr<utils::Type>> declaredTypes;
    {
        std::unordered_set<std::shared_ptr<utils::Node>> visitStore;
        if (!utils::enumerateTypes(symbolTree, declaredTypes, visitStore))
            return std::pair{ "", nullptr };
    }

    auto collectedTypes = utils::collectTypes(declaredTypes);

    std::stringstream ss;
    ss << evaluationTemplate;
    for (auto&& [ns, type] : collectedTypes) {
        ss << "\r\n";

        std::string guardName = utils::generateDefineGuard(type, type->isTemplateInstanciation());
        if (!type->isBuiltin())
        {
            ss << "#ifndef ODR" << guardName << "\r\n";
            ss << "#define ODR" << guardName << "\r\n";

            ss << "namespace " << ns << " {\r\n";

            if (type->isTemplateInstanciation()) {
                // Declare the base template and guard it.

                ss << "  template <";
                for (size_t i = 0; i < type->getTypeParameters().size(); ++i) {
                    if (i > 0)
                        ss << ", ";
                    ss << "typename T" << i;
                }
                ss << ">\r\n";
                // We don't need to explicitly specialize the type since all the data
                // is encapsulated in Meta, which synthesizes the type for us in the AST.
                // Complete type information will be bundled in the mangled name for Meta<T>.
                // ... not that it matters, since we get the fully qualified name from our
                // own abstractions.
            }

            ss << "  struct " << type->getName() << " { };\r\n";
            ss << "}\r\n";
            ss << "#endif // ODR" << guardName << "\r\n\r\n";
        }

        auto reflType = getReflTypeName(instanceType);

        ss << "namespace reflection {\r\n";
        ss << "#ifndef ODR_META" << guardName << "\r\n";
        ss << "#define ODR_META" << guardName << "\r\n";
        ss << " template <>\r\n";
        ss << " struct Meta<" << type->toString() << "> {\r\n";
        ss << "    static " << reflType << "* _instance;\r\n";
        ss << "    static " << reflType << "* GetReflInfo();\r\n";
        ss << "    static void Initialize(" << reflType << "& instance,\r\n";
        ss << "      base::global::CStrId* name,\r\n",
        ss << "      base::reflection::CType* parentType,\r\n";
        ss << "      void (*fptr0)(base::reflection::CClass*),\r\n";
        ss << "      void (*fptr1)(base::reflection::CClass*)\r\n";
        ss << "    );\r\n";
        ss << "    static void Initialize(" << reflType << "& instance,\r\n";
        ss << "      base::global::CStrId* name);\r\n";
        ss << "  };\r\n";
        ss << "#endif // ODR_META" << guardName << "\r\n";
        ss << "}\r\n";
    }

    return std::pair{ ss.str(), symbolTree };
}

Mangler::Result Mangler::Execute(std::string fullyQualifiedTypeName, Analyzers::ReflectiveType instanceType) const {
    auto [scaffoldedSource, type] = _ScaffoldSourceCode(fullyQualifiedTypeName, instanceType);
    auto reflType = getReflTypeName(instanceType);

    std::unique_ptr<clang::ASTUnit> ast = utils::generateAST(scaffoldedSource,
        "namegen.cpp",
        "ida-mangler.cpp");
    assert(ast != nullptr);

    namespace matchers = clang::ast_matchers;

    matchers::DeclarationMatcher query = matchers::classTemplateSpecializationDecl(
        matchers::matchesName("reflection::Meta"),
        matchers::hasTemplateArgument(0, // Matches T
            matchers::templateArgument(
                matchers::refersToType(
                    matchers::hasDeclaration(
                        matchers::cxxRecordDecl(
                            matchers::matchesName(type->toString())
                        ).bind("reflectedType")
                    )
                )
            )
        ),
        matchers::hasDescendant(
            matchers::varDecl(
                matchers::isStaticStorageClass(),
                matchers::hasName("_instance")
            ).bind("instance")
        ),
        matchers::hasDescendant(
            matchers::cxxMethodDecl(
                matchers::isStaticStorageClass(),
                matchers::hasName("Initialize"),
                matchers::parameterCountIs(5)
            ).bind("create")
        ),
        matchers::hasDescendant(
            matchers::cxxMethodDecl(
                matchers::isStaticStorageClass(),
                matchers::hasName("Initialize"),
                matchers::parameterCountIs(2)
            ).bind("createSimple")
        ),
        matchers::hasDescendant(
            matchers::cxxMethodDecl(
                matchers::isStaticStorageClass(),
                matchers::hasName("GetReflInfo")
            ).bind("get")
        )
    ).bind("meta");

    clang::ClassTemplateSpecializationDecl const* metaNode = matchers::selectFirst<clang::ClassTemplateSpecializationDecl>("meta",
        matchers::match(query, ast->getASTContext()));

    clang::CXXMethodDecl const* initMethodNode = matchers::selectFirst<clang::CXXMethodDecl>("create",
        matchers::match(query, ast->getASTContext()));

    clang::CXXMethodDecl const* initSimpleMethodNode = matchers::selectFirst<clang::CXXMethodDecl>("createSimple",
        matchers::match(query, ast->getASTContext()));

    clang::CXXMethodDecl const* getMethodNode = matchers::selectFirst<clang::CXXMethodDecl>("get",
        matchers::match(query, ast->getASTContext()));

    clang::VarDecl const* objNode = matchers::selectFirst<clang::VarDecl>("instance",
        matchers::match(query, ast->getASTContext()));

    std::shared_ptr<clang::ItaniumMangleContext> mangleContext{ clang::ItaniumMangleContext::create(ast->getASTContext(), ast->getDiagnostics()) };

    static auto get_mangled_name = [](std::shared_ptr<clang::ItaniumMangleContext> context, clang::GlobalDecl name) {
        std::string mangledName;
        llvm::raw_string_ostream outStream(mangledName);
        context->mangleCXXName(name, outStream);
        outStream.flush();

        return mangledName;
    };

    std::string mangledCreate       = get_mangled_name(mangleContext, clang::GlobalDecl{ initMethodNode });
    std::string mangledGet          = get_mangled_name(mangleContext, clang::GlobalDecl{ getMethodNode });
    std::string mangledObj          = get_mangled_name(mangleContext, clang::GlobalDecl{ objNode });
    std::string mangledSimpleCreate = get_mangled_name(mangleContext, clang::GlobalDecl{ initSimpleMethodNode });

    return Result {
        .ObjectName = mangledObj,
        .Initialize = mangledCreate,
        .InitializeSimple = mangledSimpleCreate,
        .Get = mangledGet
    };
}
