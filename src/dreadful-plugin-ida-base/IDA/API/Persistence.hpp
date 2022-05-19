#pragma once

#include <string_view>

namespace IDA::API {
	struct Persistence final {
		explicit Persistence(std::string_view ns) noexcept;

	};
}