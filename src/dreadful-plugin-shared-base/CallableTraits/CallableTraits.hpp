#pragma once

/* 
 * This file is part of the snippetspp distribution (https://github.com/Warpten/snippetspp).
 * Copyright (c) 2022 Warpten.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <tuple>
#include <type_traits>

namespace CallableTraits {
	template <typename T> struct CallableTraits;

	template <typename R, typename... Args>
	struct CallableTraits<R(*)(Args...)> {
		using return_type = R;
		
		template <template <typename...> typename Seq = std::tuple>
		using argument_types = Seq<Args...>;

		template <size_t I>
		using Argument = std::tuple_element_t<I, std::tuple<Args...>>;
	};

	template <typename R, typename C, typename... Args>
	struct CallableTraits<R(C::*)(Args...)> {
		using return_type = R;
		using owner_type = C;
		using owner_pointer_type = C*;

		template <template <typename...> typename Seq = std::tuple>
		using argument_types = std::conditional_t<
			std::is_member_function_pointer_v<R(C::*)(Args...)>,
			Seq<owner_pointer_type, Args...>,
			Seq<Args...>
		>;

		template <size_t I>
		using Argument = std::tuple_element_t<I, std::tuple<Args...>>;
	};

	template <typename R, typename C, typename... Args>
	struct CallableTraits<R(C::*)(Args...) noexcept> : CallableTraits<R(C::*)(Args...)> { };

	template <typename R, typename C, typename... Args>
	struct CallableTraits<R(C::*)(Args...) const> {
		using return_type = R;
		using owner_type = C;
		using owner_pointer_type = C const*;

		template <template <typename...> typename Seq = std::tuple>
		using argument_types = std::conditional_t<
			std::is_member_function_pointer_v<R(C::*)(Args...) const>,
			Seq<owner_pointer_type, Args...>,
			Seq<Args...>
		>;

		template <size_t I>
		using Argument = std::tuple_element_t<I, std::tuple<Args...>>;
	};

	template <typename R, typename C, typename... Args>
	struct CallableTraits<R(C::*)(Args...) const noexcept> : CallableTraits<R(C::*)(Args...) const> { };

	template <typename T>
	struct CallableTraits<T&&> : CallableTraits<T> { };

	template <typename T>
	struct CallableTraits<T&> : CallableTraits<T> { };

	template <typename T>
	struct CallableTraits<T const&> : CallableTraits<T> { };

	template <typename T>
	struct CallableTraits : CallableTraits<decltype(&T::operator())> { };
}
