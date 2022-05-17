#pragma once

#include <functional>
#include <iosfwd>

#include <hexrays.hpp>

namespace IDA::API {
	struct Function;
}

namespace Utils {
	struct Exporter final {
		explicit Exporter(std::ostream& outputStream);

		void Run(IDA::API::Function const& functionInfo, std::function<void(tinfo_t&)> returnTypeTransform);

	private:
		std::ostream& _outputStream;
	};
}