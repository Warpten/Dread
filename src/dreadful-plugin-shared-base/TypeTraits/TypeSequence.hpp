#pragma once

#include <tuple>
#include <type_traits>

namespace Traits {
    template <typename... Ts> struct TypeSequence {
        constexpr static const size_t Length = sizeof...(Ts);
    };
}

namespace std {
    template <typename... Ts>
    struct tuple_size<Traits::TypeSequence<Ts...>> : std::integral_constant<std::size_t, sizeof...(Ts)> { };
}
