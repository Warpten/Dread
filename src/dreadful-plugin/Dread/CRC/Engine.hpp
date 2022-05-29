#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace Dread::CRC {
	template <auto Seed, auto Polynomial, auto FinalXor, bool ReflectInput, bool ReflectResult>
	struct Engine {
		using value_type = std::common_type_t<decltype(Seed), decltype(Polynomial), decltype(FinalXor)>;

	private:
		constexpr static const size_t shift_offset = (sizeof(value_type) - 1) * 8;
		constexpr static const value_type topbit_mask = value_type{ 0x80 } << shift_offset;

	public:
		constexpr Engine() noexcept : _lookupTable() {
			for (size_t i = 0; i < _lookupTable.size(); ++i) {
				value_type currentByte = static_cast<value_type>(i) << shift_offset;
				for (size_t j = 0; j < CHAR_BIT; ++j) {
					if (currentByte & topbit_mask)
						currentByte = (currentByte << 1uLL) ^ Polynomial;
					else
						currentByte <<= 1;
				}

				_lookupTable[i] = currentByte;
			}
		}

		constexpr value_type operator () (std::string_view input) const noexcept {
			value_type checksum = Seed;

			for (char character : input) {
				if constexpr (ReflectInput) {
					// https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
					character = (character * 0x02'02'02'02'02uLL & 0x01'08'84'42'20'10uLL) % 1023;
				}

				checksum ^= static_cast<value_type>(character) << shift_offset;

				auto lookupIndex = checksum >> shift_offset;
				checksum = (checksum << CHAR_BIT) ^ _lookupTable[lookupIndex];
			}

			if constexpr (ReflectResult) {
#if __cpp_lib_byteswap >= 202110L
				checksum = std::byteswap(checksum);
#else
				// http://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
				size_t shift = sizeof(value_type) * CHAR_BIT;
				size_t mask = (~0 & std::numeric_limits<value_type>::max());
				while ((shift >>= 1) > 0) {
					mask ^= (mask << shift);
					checksum = ((checksum >> shift) & mask) | ((checksum << shift) & ~mask);
				}
#endif
			}

			return checksum ^ FinalXor;
		}

	private:
		std::array<value_type, 256> _lookupTable;
	};

	using DefaultEngine = Engine<0xFFFF'FFFF'FFFF'FFFFuLL, 0x42F0'E1BE'A9EA'3693uLL, 0x0uLL, true, true>;
}
