#ifndef IDA_API_Microcode_hpp__
#define IDA_API_Microcode_hpp__

#pragma warning( disable : 4267 4244 )
#include <hexrays.hpp>
#pragma warning( default : 4267 4244 )

#include <array>
#include <tuple>
#include <type_traits>
#include <variant>

namespace IDA::API {
    namespace Microcode {
        template <mopt_t OperandType> struct operand_traits;
        template <> struct operand_traits<mop_z> { using value_type = void; };
        template <> struct operand_traits<mop_r> { 
            using value_type = decltype(std::declval<mcallarg_t>().r);

            static value_type const& _Extract(mop_t const& operand) { return operand.r; }
        };
        template <> struct operand_traits<mop_n  > { 
            using value_type = decltype(std::declval<mcallarg_t>().nnn);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.nnn; }
        };
        template <> struct operand_traits<mop_str> {
            using value_type = decltype(std::declval<mcallarg_t>().cstr);
            
            static value_type _Extract(mop_t const& argInfo) { return argInfo.cstr; }
        };
        template <> struct operand_traits<mop_d> {
            using value_type = decltype(std::declval<mcallarg_t>().d);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.d; }
        };
        template <> struct operand_traits<mop_S> {
            using value_type = decltype(std::declval<mcallarg_t>().s);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.s; }
        };
        template <> struct operand_traits<mop_v> {
            using value_type = decltype(std::declval<mcallarg_t>().g);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.g; }
        };
        template <> struct operand_traits<mop_b> {
            using value_type = decltype(std::declval<mcallarg_t>().b);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.b; }
        };
        template <> struct operand_traits<mop_f> {
            using value_type = decltype(std::declval<mcallarg_t>().f);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.f; }
        };
        template <> struct operand_traits<mop_l> {
            using value_type = decltype(std::declval<mcallarg_t>().l);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.l; }
        };
        template <> struct operand_traits<mop_a> {
            using value_type = decltype(std::declval<mcallarg_t>().a);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.a; }
        };
        template <> struct operand_traits<mop_h> {
            using value_type = decltype(std::declval<mcallarg_t>().helper);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.helper; }
        };
        template <> struct operand_traits<mop_c> {
            using value_type = decltype(std::declval<mcallarg_t>().c);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.c; }
        };
        template <> struct operand_traits<mop_fn> {
            using value_type = decltype(std::declval<mcallarg_t>().fpc);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.fpc; }
        };
        template <> struct operand_traits<mop_p> {
            using value_type = decltype(std::declval<mcallarg_t>().pair);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.pair; }
        };
        template <> struct operand_traits<mop_sc > {
            using value_type = decltype(std::declval<mcallarg_t>().scif);

            static value_type _Extract(mop_t const& argInfo) { return argInfo.scif; }
        };
        
        template <typename R, mopt_t... TypeIDs>
        class DelegateGenerator {
            template <mopt_t... Is> struct operand_to_type;
            template <> struct operand_to_type<> { using type = std::tuple<>; };

            template <mopt_t Head, mopt_t... Tail>
            struct operand_to_type<Head, Tail...> {
                using type = std::conditional_t<
                    Head == 0, 
                    typename operand_to_type<Tail...>::type,
                    decltype(
                        std::tuple_cat(
                            std::declval<std::tuple<typename Microcode::operand_traits<Head>::value_type>>(),
                            std::declval<typename operand_to_type<Tail...>::type>()
                        )
                    )
                >;
            };

            template <typename W, typename X>
            struct function_sign_generator_t;

            template <typename W, typename... Xs>
            struct function_sign_generator_t<W, std::tuple<Xs...>> {
                using type = std::function<W(Xs...)>;
            };

        public:
            using type = typename function_sign_generator_t<R, typename operand_to_type<TypeIDs...>::type>::type;
        };
    }
}


#endif // IDA_API_Microcode_hpp__
