#pragma once

#include "../Exception.hpp"

namespace IDA::API {
	struct DecompilationException : IDA::Exception {
		DecompilationException(merror_t errorCode, ea_t address, std::string_view description)
			: IDA::Exception(errorCode, description), _address(address)
		{

		}

	private:
		ea_t _address;
	};
}