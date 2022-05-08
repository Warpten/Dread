#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace CRC {
	template <auto Seed, auto Polynomial, auto FinalXor, bool ReflectInput, bool ReflectResult>
	struct Engine {
		using value_type = std::common_type_t<decltype(Seed), decltype(Polynomial), decltype(FinalXor)>;

		// Implementation without lookup tables because MSVC complains about step count
		//   and I don't want to change it.
		constexpr Engine() noexcept {
			// Left for posterity.
			// for (uint8_t dividend = 0; dividend < _lookupTable.size(); ++dividend) {
			// 	value_type currentByte = value_type(dividend) << 56uLL;
			// 
			// 	value_type value = currentByte;
			// 	for (size_t i = 0; i < currentByte; ++i) {
			// 		if ((dividend & 0x80) != 0) {
			// 			value <<= 1;
			// 			value ^= Polynomial;
			// 		}
			// 		else
			// 			value <<= 1;
			// 	}
			// 
			// 	_lookupTable[dividend] = value;
			// }
		}

		constexpr value_type operator () (std::string_view input) const noexcept {
			value_type checksum = Seed;

			for (char character : input) {
				if constexpr (ReflectInput) {
					// https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
					character = (character * 0x02'02'02'02'02uLL & 0x010884422010uLL) % 1023;
				}

				// Left for posterity
				// checksum = checksum ^ (value_type(character) << 56uLL);
				// auto lookupIndex = checksum >> 56;
				// assert(lookupIndex >= 0 && lookupIndex <= _lookupTable.size());
				// checksum <<= 8uLL;
				// checksum ^= _lookupTable[lookupIndex];

				checksum = checksum ^ (value_type(character) << 56uLL);
				for (size_t i = 0; i < 8; ++i) {
					if ((checksum >> 56) & 0x80) {
						checksum = (checksum << 1) ^ Polynomial;
					}
					else
						checksum <<= 1;
				}
			}

			if constexpr (ReflectResult) {
				// http://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
				size_t shift = sizeof(value_type) * CHAR_BIT;
				size_t mask = ~0;
				while ((shift >>= 1) != 0) {
					mask ^= (mask << shift);
					checksum = ((checksum & mask) >> shift) | ((checksum & ~mask) << shift);
				}
			}

			return checksum ^ FinalXor;
		}

	private:
		// std::array<value_type, 256> _lookupTable;
	};
}
