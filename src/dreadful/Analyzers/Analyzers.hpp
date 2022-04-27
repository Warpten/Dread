#ifndef Analyzers_hpp__
#define Analyzers_hpp__

#include <cassert>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

#include "IDA/API/API.hpp"
#include "utils/EnumFlags.hpp"
#include "IDA/Microcode/Instructions.hpp"
#include "IDA/Microcode/Microcode.hpp"
#include "Mangler.hpp"

namespace Analysis {
    struct Engine;
    struct Meta;

    struct Meta {
        void Process(Engine& engine);

		ea_t Base = 0; //< Address of the `_instance` static global.
        
        struct {
            std::string Value;
            size_t Variable = 0;
        } CStrId;

		struct {
			// Stack index of variable that holds a pointer to parent type's reflinfo
			// as returned by Meta<T>::GetReflInfo()
            int Variable = 0;
            ea_t GetReflInfo;
        } Parent;

		struct Function {
			ea_t Base = 0;
			std::unique_ptr<mba_t> Microcode;
            std::vector<ea_t> ExtraParameters;
		};

		Function GetReflInfo; //< Represents the `GetReflInfo` method.
		Function Initialize; //< Represents the `Initialize` method.

		Analyzers::ReflectiveType Type = Analyzers::ReflectiveType::Unknown;

        struct {

        } CType;

        struct {

        } CClass;

        struct {

        } CPointerType;

        struct {

        } CEnumType;

        struct {
            std::optional<mreg_t> Register = std::nullopt;
        } ReflObject;
    };

	struct Engine {
        using element_type = Meta;

        Meta& FindEntry(ea_t address) {
            auto [itr, _] = _storage.try_emplace(address, Meta{});
            return itr->second;
        }

        Meta& FindEntry(std::string typeName) {
            auto itr = _typeStorage.find(typeName);
            if (itr == _typeStorage.end()) {
                for (auto&& [k, v] : _storage) {
                    if (v.CStrId.Value != typeName)
                        continue;

                    _typeStorage.emplace(typeName, std::addressof(v));
                    return v;
                }

                throw std::logic_error("Type not registered");
            }
            else {
                return *itr->second;
            }
        }

        void Process() {
            for (auto&& [k, v] : _storage)
                v.Process(*this);
        }

	private:
		std::unordered_map<ea_t, Meta> _storage;
        // Indexes into `storage`.
        std::unordered_map<std::string, Meta*> _typeStorage;
	};
}

namespace Filters {
    template <bool Nullable = false>
    struct _GlobalPointer {
        using type = ea_t;

        static bool Matches(mop_t const& operand) {
            if constexpr (Nullable) {
                if (operand.t == mop_n) {
                    if (operand.nnn->value == 0)
                        return true;
                    return false;
                }
            }

            return operand.t == mop_a && operand.a->t == mop_v;
        }

        static type Extract(mop_t const& operand) {
            if constexpr (Nullable) {
                if (operand.t == mop_n)
                    return static_cast<ea_t>(operand.nnn->value);
            }

            return operand.a->g;
        }
    };

    template <bool Nullable = false>
    struct _LocalPointer {
        using type = lvar_ref_t*;

        static bool Matches(mop_t const& operand) {
            if constexpr (Nullable) {
                if (operand.t == mop_n) {
                    if (operand.nnn->value == 0)
                        return true;

                    return false;
                }
            }

            return operand.t == mop_a && operand.a->t == mop_l;
        }

        static type Extract(mop_t const& operand) {
            if constexpr (Nullable) {
                if (operand.t == mop_n) {
                    return nullptr;
                    assert(operand.nnn->value == 0uLL);
                }
            }

            return operand.a->l;
        }
    };

    template <bool Nullable>
    struct Pointer {
        using type = std::variant<ea_t, lvar_ref_t*>;

        static bool Matches(mop_t const& operand) {
            if constexpr (Nullable) {
                if (operand.t == mop_n) {
                    if (operand.nnn->value == 0)
                        return true;

                    return false;
                }
            }

            return operand.t == mop_a && (operand.a->t == mop_l || operand.a->t == mop_v);
        }

        static type Extract(mop_t const& operand) {
            if constexpr (Nullable) {
                if (operand.t == mop_n) {
                    return nullptr;
                    assert(operand.nnn->value == 0uLL);
                }
            }

            if (operand.a->t == mop_l)
                return operand.a->l;
            else
                return operand.a->g;
        }
    };

    using Register = IDA::API::OperandFilter<mop_l>;

    //< Operand filter for a pointer to a local variable. May not be nullptr. mop_a->mop_l.
    using LocalPointer = _LocalPointer<false>;
    //< Operand filter for a pointer to a local variable. May be nullptr. mop_a->mop_l || mop_n.
    using NullableLocalPointer = _LocalPointer<true>;

    //< Operand filter for a function pointer. May not be nullptr. mop_a->mop_v.
    using FunctionPointer = _GlobalPointer<false>;
    //< Operand filter for a global variable pointer. May not be nullptr. mop_a->mop_v
    using GlobalPointer = _GlobalPointer<false>;

    //< Operand filter for a function pointer. May be nullptr. mop_a->mop_v || mop_n
    using NullableFunctionPointer = _GlobalPointer<true>;
    //< Operand filter for a global variant pointer. May be nullptr. mop_a->mop_v || mop_n
    using NullableGlobalPointer = _GlobalPointer<true>;

    /**
     * Filter for an operand that ensures it is a number of a given value.
     * 
     * In IDA lingo, this is a mop_n or mop_fn.
     */
    template <auto Value>
    struct ExpectedValueOperand {
        using type = decltype(Value);

        static bool Matches(mop_t const& operand) noexcept {
            if constexpr (std::is_same_v<type, float>) {
                if (operand.t != mop_fn || operand.fpc->nbytes != sizeof(type))
                    return false;

                // TODO: figure out how to turn the internal IDA IEEE754 crap to floats
                // is it just glorified float128?
            } else if constexpr (std::is_integral_v<type>) { 
                return operand.t == mop_n && operand.nnn->value == Value;
            }
        }

        static type Extract(mop_t& operand) noexcept {
            if constexpr (std::is_same_v<type, float>) {
                throw "cock and balls";
            } else if constexpr (std::is_integral_v<type>) {
                return operand.nnn->value;
            }
        }
    };

    struct IntegerOperand {
        using type = size_t;

        static bool Matches(mop_t const& operand) noexcept {
            return operand.t == mop_n;
        }

        static type Extract(mop_t& operand) noexcept {
            return operand.nnn->value;
        }
    };
}

// Definition of instruction handlers ---
namespace base::global {
    namespace CStrId {
        /**
         * Detects calls to CStrId::CStrId and registers the caller as a candidate method
         * for reflection extraction.
         * 
         * Call sites typically look like
         *     CStrId::CStrId(&this, "base::reflection::CClass", 1uLL);
         * with the actual signature being
         *     void CStrId(CStrId* __hidden this, const char*, uint64_t);
         */
        struct CStrId final {
            constexpr static const ea_t Address = 0x00000071000003D4uLL;

            static bool TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept;
        };
    }
}

struct CRC64 final {
    constexpr static const ea_t Address = 0x0000007100001570uLL;

    static bool TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept;
};

struct VtableAssignment final {
    static bool TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept;
};

struct ConstructorCall final {
    static bool TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept;
};

template <typename T, typename E>
concept is_static_tryprocess = requires (minsn_t* i, E& e, typename E::element_type& s) {
	{ T::TryProcess(i, e, s) } -> std::same_as<bool>;
};

// Actual visitor
template <typename E, typename... Ts>
struct InstructionVisitor : minsn_visitor_t {
    static_assert(sizeof...(Ts) > 0, "No instruction handler provided");

    constexpr static const bool instance_eval = !(is_static_tryprocess<Ts, E> && ...);

public:
	static bool Run(mba_t* microcode, E& engine, typename E::element_type& storage)
		requires (!instance_eval)
	{
		InstructionVisitor<E, Ts...> self{ engine, microcode, storage };
		return microcode->for_all_insns(self);
	}

	static bool Run(mba_t* microcode, E& engine, typename E::element_type& storage, Ts&&... analyzers)
		requires (instance_eval)
	{
		InstructionVisitor<E, Ts...> self{ engine, microcode, storage, std::forward<Ts&&>(analyzers)... };
		return microcode->for_all_insns(self);
	}

private:
    InstructionVisitor(E& engine, mba_t* microcode, typename E::element_type& storage) noexcept requires (!instance_eval)
        : minsn_visitor_t(microcode, nullptr, nullptr), 
        _engine{engine}, _storage{storage}
    { }

    InstructionVisitor(E& engine, mba_t* microcode, typename E::element_type& storage, Ts&&... analyzers) noexcept requires (instance_eval)
        : minsn_visitor_t(microcode, nullptr, nullptr), 
        _engine{engine}, _storage{storage}, 
        _analyzers{ std::tuple<Ts...> { std::forward<Ts&&>(analyzers)...} }
    { }

    int idaapi visit_minsn() override {
        return TryProcess<0>(curins, _engine);
    }

private:
	template <size_t I>
	bool TryProcess(minsn_t* instruction, E& engine) {
		if constexpr (I < sizeof...(Ts)) {
			if constexpr (instance_eval) {
				if (!std::get<I>(*_analyzers).TryProcess(instruction, engine))
					return TryProcess<I + 1>(instruction, engine);
            }
			else {
				using element_type = std::tuple_element_t<I, typename decltype(_analyzers)::value_type>;

				if (!element_type::TryProcess(instruction, engine, _storage))
					return TryProcess<I + 1>(instruction, engine);
            }

            return true;
		}
		else
			return false;
	}

    E& _engine;
    typename E::element_type& _storage;
    std::optional<std::tuple<Ts...>> _analyzers = std::nullopt;
};

template <typename E, typename... Ts>
InstructionVisitor(E&, mba_t*, Ts&&...) -> InstructionVisitor<E, Ts&&...>;

#endif // Analyzers_hpp__
