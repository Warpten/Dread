#pragma once

#include <algorithm>
#include <functional>
#include <string_view>

namespace Dread::Utilities {
	template <size_t N>
	struct Literal {
		constexpr Literal(const char(&v)[N]) {
			std::copy_n(v, N, Value);
		}

		char Value[N];

		bool operator == (std::string_view view) {
			return view.length() == N && std::memcmp(Value, view.data(), N);
		}
	};

	template <typename R, typename T, typename... Ts>
	auto Curry(R(*fn)(T, Ts&&...), T&& arg) -> std::function<R(Ts&&...)> {
		return [&fn, &arg](Ts&&... args) -> R {
			return fn(std::forward<T&&>(arg), std::forward<Ts&&>(args)...);
		};
	}
}
