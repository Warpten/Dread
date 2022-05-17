#pragma once

#include <stdexcept>
#include <string>

#include <hexrays.hpp>

namespace IDA {
	struct Exception : std::exception {
		Exception(merror_t errorCode, std::string_view description) 
			: std::exception(), _errorCode(errorCode), _description(description)
		{
		}

		char const* what() const override {
			return _description.c_str();
		}

	private:
		std::string _description;
		merror_t _errorCode;
	};
}
