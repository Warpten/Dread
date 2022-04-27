#ifndef IDA_API_Instructions_hpp__
#define IDA_API_Instructions_hpp__

#pragma warning( disable : 4267 4244 )
#include <hexrays.hpp>
#pragma warning( default : 4267 4244 )

#include <array>
#include <concepts>
#include <functional>
#include <tuple>

#include "Microcode.hpp"

namespace IDA::API {
    struct TEmpty{};

    template <mopt_t... Ts>
    struct OperandFilter {
        static_assert(((Ts != mop_z) && ...));
        
    private:
        constexpr static auto values = std::array { Ts... };
    public:
        using type = std::conditional_t<(sizeof...(Ts) > 1),
            std::variant<typename Microcode::operand_traits<Ts>::value_type...>,
            typename Microcode::operand_traits<std::get<0>(values)>::value_type>;

        static bool Matches(mop_t& opt) noexcept { return ((opt.t == Ts) || ...); }
        static type Extract(mop_t& opt) noexcept { return _Extract<0>(opt); }

        template <size_t I>
        static type _Extract(mop_t& opt) {
            if constexpr (I < sizeof...(Ts)) {
                if (values[I] == opt.t)
                    return Microcode::operand_traits<values[I]>::_Extract(opt);
                else
                    return _Extract<I + 1>(opt);
            } else {
                throw std::runtime_error("None of the expected operand types match the runtime value");
                // Shut up warnings
                return type{};
            }
        }
    };

    template <>
    struct OperandFilter<> {
        using type = TEmpty;
        static bool Matches(mop_t opt) noexcept { return opt.t == mop_z; }
        static TEmpty Extract(mop_t&) noexcept { return TEmpty{}; }
    };

    namespace utils {
        namespace details {
            template <size_t I, typename Needle, typename... Ts, size_t... Is>
            constexpr static auto find_nonmatch_indices(std::tuple<Ts...> const& haystack, std::index_sequence<Is...> seq) noexcept {
                using tuple_type = std::tuple<Ts...>;

                if constexpr (I < sizeof...(Ts)) {
                    if constexpr (std::is_same_v<Needle, std::tuple_element_t<I, tuple_type>>) {
                        // If needle found, iterate to next
                        return find_nonmatch_indices<I + 1, Needle>(haystack, seq);
                    } else {
                        // Otherwise, insert index at the back of the tuple and iterate again
                        return find_nonmatch_indices<I + 1, Needle>(haystack, std::index_sequence<Is..., I>{});
                    }
                } else {
                    return seq; // Done
                }
            }

            template <typename... Ts, size_t... Is>
            constexpr static auto select(std::tuple<Ts...> const& t, std::index_sequence<Is...>) {
                return std::tuple { std::get<Is>(t)... };
            }
        }

        template <typename Needle, typename Tuple>
        constexpr static auto filter(Tuple const& tuple) {
            return details::select(
                tuple,
                details::find_nonmatch_indices<0, Needle>(
                    tuple,
                    std::index_sequence<> {}
                )
            );
        }

        template <typename Needle, typename Tuple>
        using filtered_tuple_t = decltype(filter<Needle, Tuple>(std::declval<Tuple>()));
            
        template <typename R, typename... Filters>
        struct DelegateGenerator final {
                
            template <typename W, typename X>
            struct function_sign_generator_t;

            template <typename W, typename... Xs>
            struct function_sign_generator_t<W, std::tuple<Xs...>> {
                using type = std::function<W(Xs...)>;
            };

        public:
            using args = utils::filtered_tuple_t<TEmpty, std::tuple<typename Filters::type...>>;
            using type = typename function_sign_generator_t<R, args>::type;
        };

        template <typename R, typename... Filters>
        using Delegate = typename DelegateGenerator<R, Filters...>::type;
    }
        
    /**
     * High-level API around a microcode instruction.
     * @typeparam L The type of the left operand.
     * @typeparam R The type of the right operand.
     * @typeparam D The type of the destination operand.
     */
    template <mcode_t C, typename L, typename R, typename D>
    struct Instruction final {
        using function_type = utils::Delegate<bool, L, R, D>;

        static bool TryProcess(minsn_t* instruction, function_type handler) noexcept {
            if (instruction->opcode != C)
                return false;

            if (!L::Matches(instruction->l) || !R::Matches(instruction->r) || !D::Matches(instruction->d))
                return false;

            std::tuple unfilteredArguments { left(instruction), right(instruction), destination(instruction) } ;
            auto args = utils::filter<TEmpty>(unfilteredArguments);
            static_assert(std::is_same_v<decltype(args), typename utils::DelegateGenerator<bool, L, R, D>::args>);

            return std::apply(handler, args);
        }

    protected:
            
        static auto left(minsn_t* instruction) noexcept
            -> std::conditional_t<!std::is_same_v<L, OperandFilter<>>, typename L::type, TEmpty>
        {
            if constexpr (std::is_same_v<L, OperandFilter<>>)
                return TEmpty{};
            else
                return L::Extract(instruction->l);
        }
        static auto right(minsn_t* instruction) noexcept
            -> std::conditional_t<!std::is_same_v<R, OperandFilter<>>, typename R::type, TEmpty>
        {
            if constexpr (std::is_same_v<R, OperandFilter<>>)
                return TEmpty{};
            else
                return R::Extract(instruction->r);
        }
        static auto destination(minsn_t* instruction) noexcept
            -> std::conditional_t<!std::is_same_v<D, OperandFilter<>>, typename D::type, TEmpty>
        {
            if constexpr (std::is_same_v<D, OperandFilter<>>)
                return TEmpty{};
            else
                return D::Extract(instruction->d);
        }
    };
    
    /**
     * High-level API around a microcode call instruction.
     * 
     * @typeparam Left The type of the left hand operand of the opcode. This is to be used by superclasses.
     * 
     * @rem L mop_b, mop_h as well as mop_v
     *        mop_b would be a call to a microcode block
     *        mop_h a "helper function" (HexRays intrinsics?)
     *        mop_v is a global EA to a function (what we care about here)
     */
    template <typename Left>
    struct CallInstruction final {
        using Base = Instruction<mcode_t::m_call, Left, OperandFilter<>, OperandFilter<mop_f>>;

        static_assert(std::is_same_v<Left, OperandFilter<mop_h>> 
            || std::is_same_v<Left, OperandFilter<mop_b>>
            || std::is_same_v<Left, OperandFilter<mop_v>>);

        using function_type = utils::Delegate<bool, Left, OperandFilter<>, OperandFilter<mop_f>>;
        using left_type = typename Left::type;

        static bool TryProcess(minsn_t* instruction, function_type handler) noexcept {
            return Base::TryProcess(instruction, handler);
        }
    };
    
    /*
     * High level API around a microcode call instruction on a particular function.
     * 
     * @typeparam Base The EA of the function being called.
     * @typeparam Args Expected types pack of the arguments for this function call.
     */
    template <ea_t Address, typename... Args>
    struct FunctionCallInstruction final {
        constexpr static const ea_t Address = Address;

        using Base = CallInstruction<OperandFilter<mop_v>>;
        using function_type = utils::Delegate<bool, Args...>;

        static bool TryProcess(minsn_t* instruction, function_type handler) noexcept {
            return Base::TryProcess(instruction, [handler](ea_t functionAddress, mcallinfo_t* args) {
                if constexpr (Address != std::numeric_limits<ea_t>::max()) {
                    if (functionAddress != Address)
                        return false;
                }

                return _CallDelegateHelper(handler, args, std::make_index_sequence<sizeof...(Args)> {});
            });
        }

        static ea_t GetCallee(minsn_t* instruction) noexcept {
            assert(instruction->l.t == mop_v);
            return instruction->l.g;
        }

    private:
        template <typename Fn, size_t... Is>
        static auto _CallDelegateHelper(Fn&& handler, mcallinfo_t* args, std::index_sequence<Is...>) noexcept {
            if (!handler || args->args.size() != sizeof...(Is))
                return false;

            if ((Args::Matches(args->args[Is]) && ...)) {
                return std::apply(handler,
                    utils::filter<TEmpty>(std::tuple {
                        Args::Extract(args->args[Is])...
                    })
                );
            }
            return false;
        }
    };

    template <typename... Args>
    struct IntrinsicCall final {
        using Base = CallInstruction<OperandFilter<mop_h>>;
        using function_type = utils::Delegate<bool, OperandFilter<mop_h>, Args...>;

        static bool TryProcess(minsn_t* instruction, function_type handler) noexcept {
            return Base::TryProcess(instruction, [handler](char* helperName, mcallinfo_t* args) {
                return _CallDelegateHelper(handler, helperName, args, std::make_index_sequence<sizeof...(Args)> {});
            });
        }

    private:
        template <typename Fn, size_t... Is>
        static auto _CallDelegateHelper(Fn&& handler, char* helperName, mcallinfo_t* args, std::index_sequence<Is...>) noexcept {
            if (!handler)
                return false;

            return std::apply(handler,
                std::tuple_cat(
                    std::tuple { helperName },
                    utils::filter<TEmpty>(std::tuple {
                        Args::Extract(args->args[Is])...
                    })
                )
            );
        }
    };

    /**
     * Helper for FunctionCallInstruction designed for non-specific function pointers
     * with the same signatures.
     */
    template <typename... Args>
    using AnyFunctionCallInstruction = FunctionCallInstruction<std::numeric_limits<ea_t>::max(), Args...>;

    template <typename From, typename To>
    using MemoryXferInstruction = Instruction<mcode_t::m_mov, From, OperandFilter<>, To>;
}

#endif // IDA_API_Instructions_hpp__
