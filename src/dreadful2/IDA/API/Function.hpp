#pragma once

#include "Type.hpp"

#include <hexrays.hpp>

#include <functional>
#include <memory>
#include <string>
#include <sstream>
#include <unordered_set>

namespace IDA::API {
	struct Function {
		friend struct std::hash<Function>;

		explicit Function(ea_t rva);

		ea_t GetAddress() const { return _rva; }
		std::string GetName() const;

		Type GetReturnType() const;
		size_t GetArgumentCount() const;
		Type GetArgumentType(size_t index) const;
		std::string GetArgumentName(size_t index) const;

		void ModifyType(std::function<void(tinfo_t&, size_t)> transform) const;

		/// <summary>
		/// Decompiles the function. Returns the decompiled pseudocode.
		/// Throws <see cref="DecompilationException" /> if decompilation fails.
		/// </summary>
		/// <returns></returns>
		void Decompile(std::ostream& stream, std::function<void(cfunc_t&)> filter = nullptr) const;

		/// <summary>
		/// Lists all xrefs to the current function.
		/// </summary>
		/// <param name="xrefFlags"></param>
		/// <returns></returns>
		std::vector<ea_t> GetReferencesTo(int xrefFlags) const;

		/// <summary>
		/// Lists all xrefs from the current function.
		/// </summary>
		/// <param name="xrefFlags"></param>
		/// <returns></returns>
		std::unordered_set<ea_t> GetReferencesFrom(int xrefFlags) const;

		friend bool operator == (Function const& left, Function const& right);
		friend bool operator != (Function const& left, Function const& right);

	private:
		ea_t _rva;
	};

	bool IsFunction(ea_t);
}

namespace std {
	template <>
	struct hash<IDA::API::Function> {
		const size_t operator() (IDA::API::Function const& function) const noexcept {
			return std::hash<size_t>{}(function._rva);
		}
	};
}