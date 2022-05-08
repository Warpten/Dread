#pragma once

#include <optional>

#include <hexrays.hpp>

namespace IDA::API {
	struct Type final {
		explicit Type(tinfo_t typeInfo);

		bool IsCorrect() const;

		bool IsPointer() const;
		std::optional<Type> GetPointee() const;

		bool IsArray() const;
		bool IsStruct() const;

		std::string ToString() const;


	private:
		tinfo_t _type;
	};
}