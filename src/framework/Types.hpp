#pragma once

namespace base {
	namespace reflection {
		struct CType;
		struct CClass;
		struct CPointerType;
		struct CEnumType;
		struct CTypedValue;
	}

	namespace global {
		struct CStrId;
		struct CRntString;

		struct TRntString64;
		struct TRntString128;
		struct TRntString256;
		struct TRntString512;

		struct StringBuffer;

		using CFilePathStrId = CStrId;
	}
}