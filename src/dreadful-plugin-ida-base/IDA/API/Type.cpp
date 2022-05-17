#include "Type.hpp"

namespace IDA::API {
	Type::Type(tinfo_t typeInfo) {
		_type = typeInfo;
	}

	bool Type::IsCorrect() const {
		return _type.is_correct();
	}

	bool Type::IsPointer() const {
		return _type.is_ptr();
	}

	std::optional<Type> Type::GetPointee() const {
		if (!IsPointer())
			return std::nullopt;

		return Type{ _type.get_pointed_object() };
	}

	bool Type::IsArray() const {
		return _type.is_array();
	}

	std::string Type::ToString() const {
		return _type.dstr();
	}

	bool Type::IsStruct() const {
		return _type.is_struct();
	}
}
