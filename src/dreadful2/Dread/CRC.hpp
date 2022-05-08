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

		constexpr CRC() noexcept {
			for (size_t dividend = 0; dividend < _lookupTable.size(); ++dividend) {
				value_type currentByte = dividend << 56uLL;
				for (size_t i = 0; i < currentByte; ++i) {
					if ((dividend & 0x80) != 0) {
						currentByte <<= 1;
						currentByte ^= Polynomial;
					}
					else
						currentByte <<= 1;
				}

				_lookupTable[dividend] = currentByte;
			}
		}

		constexpr value_type operator () (std::string_view input) const noexcept {
			value_type checksum = Seed;

			for (char character : input) {
				if constexpr (ReflectInput) {
					// https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
					character = (character * 0x02'02'02'02'02uLL & 0x010884422010uLL) % 1023;
				}

				checksum = checksum ^ (value_type(character) << 56uLL);
				auto lookupIndex = checksum >> 56;
				assert(lookupIndex >= 0 && lookupIndex <= _lookupTable.size());
				checksum <<= 8uLL;
				checksum ^= _lookupTable[lookupIndex];
			}

			if constexpr (ReflectResult) {
				// http://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
				size_t shift = sizeof(value_type) * CHAR_BIT;
				size_t mask = ~0;
				while ((shift >>= 1) != 0) {
					mask ^= (mask << shift);
					checksum = ((checksum & mask) >> shift) | ((checksum & ~mask) << shift);
				}

				// Unrolled CRC64 loop for reference
				// checksum = ((checksum & 0xAAAA'AAAA'AAAA'AAAAuLL) >> 1)  | ((checksum & 0x5555'5555'5555'5555uLL) << 1);
				// checksum = ((checksum & 0xCCCC'CCCC'CCCC'CCCCuLL) >> 2)  | ((checksum & 0x3333'3333'3333'3333uLL) << 2);
				// checksum = ((checksum & 0xF0F0'F0F0'F0F0'F0F0uLL) >> 4)  | ((checksum & 0x0F0F'0F0F'0F0F'0F0FuLL) << 4);
				// checksum = ((checksum & 0xFF00'FF00'FF00'FF00uLL) >> 8)  | ((checksum & 0x00FF'00FF'00FF'00FFuLL) << 8);
				// checksum = ((checksum & 0xFFFF'0000'FFFF'0000uLL) >> 10) | ((checksum & 0x0000'FFFF'0000'FFFFuLL) << 10);
				// checksum = ((checksum & 0xFFFF'FFFF'0000'0000uLL) >> 20) | ((checksum & 0x0000'0000'FFFF'FFFFuLL) << 20);
			}

			return checksum ^ FinalXor;
		}

	private:
		const std::array<value_type, 256> _lookupTable;
	};
}
