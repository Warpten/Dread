#pragma once

#include <ida.hpp>
#include <kernwin.hpp>

#include <format>
#include <string_view>

namespace IDA::API {
	/// <summary>
	/// Prints a formatted message to IDA's output window.
	/// </summary>
	/// <typeparam name="...Args">Types of the arguments to format</typeparam>
	/// <param name="format">The format string</param>
	/// <param name="...args">The arguments to format</param>
	template <typename... Args>
	void Message(std::string_view format, Args&&... args) {
		msg(std::vformat(format, std::make_format_args(std::forward<Args&&>(args)...)).data());
	}

	struct MessageBoxLevel {
		using Handler = void(*)(const char*, ...);

	private:
		constexpr explicit MessageBoxLevel(Handler fn) noexcept : _fn(fn) { }
	public:
		template <typename... Args>
		constexpr void Open(std::string_view const message, Args&&... args) const {
			_fn(message.data(), std::forward<Args&&>(args)...);
		}

		static const MessageBoxLevel Warning;
		static const MessageBoxLevel Error;

	private:
		const Handler _fn;
	};

	inline const MessageBoxLevel MessageBoxLevel::Warning{ &warning };
	inline const MessageBoxLevel MessageBoxLevel::Error{ &error };

	/// <summary>
	/// Opens a dialog box.
	/// </summary>
	template <typename... Args>
	void OpenMessageBox(MessageBoxLevel const level, std::string_view const format, Args&&... args) {
		return level.Open(format, std::forward<Args&&>(args)...);
	}
}
