#include "DecompilationException.hpp"
#include "Function.hpp"
 
#include <llvm/ADT/StringRef.h>

#include <clang/Basic/Diagnostic.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Tooling/Tooling.h>

#include <regex>
#include <set>
#include <unordered_set>

namespace IDA::API {
	bool operator == (Function const& left, Function const& right) {
		return left._rva == right._rva;
	}
	bool operator != (Function const& left, Function const& right) {
		return !(left == right);
	}

	bool IsFunction(ea_t rva) {
		return get_func(rva) != nullptr;
	}

	Function::Function(ea_t rva) {
		func_t* function = get_func(rva);
		assert(function != nullptr);

		_rva = function->start_ea;
	}

	bool Function::IsThunk() const {
		func_t* function = get_func(_rva);
		assert(function != nullptr);

		return (function->flags & FUNC_THUNK) != 0;
	}

	const auto get_tinfo_from_cfunc_t = [](ea_t rva) {
		func_t* function = get_func(rva);
		assert(function != nullptr);

		hexrays_failure_t failure;
		cfuncptr_t functionPointer = decompile(function, &failure,
			DECOMP_NO_WAIT | DECOMP_NO_CACHE | DECOMP_NO_XREFS | DECOMP_NO_FRAME);
		if (failure.code != merror_t::MERR_OK)
			throw DecompilationException(failure.code, failure.errea, failure.desc().c_str());

		tinfo_t tif;
		bool success = functionPointer->get_func_type(&tif);
		if (!success)
			throw DecompilationException(failure.code, failure.errea, failure.desc().c_str());

		return tif;
	};

	const auto get_func_type_data = [](ea_t rva) {
		tinfo_t functionInfo = get_tinfo_from_cfunc_t(rva);

		func_type_data_t functionData;
		bool success = functionInfo.get_func_details(&functionData);
		assert(success);

		return functionData;
	};

	Type Function::GetReturnType() const {
		func_type_data_t functionData = get_func_type_data(_rva);

		return Type{ functionData.rettype };
	}

	size_t Function::GetArgumentCount() const {
		func_type_data_t functionData = get_func_type_data(_rva);

		return functionData.size();
	}

	Type Function::GetArgumentType(size_t index) const {
		func_type_data_t functionData = get_func_type_data(_rva);
		assert(index < functionData.size());

		return Type{ functionData[index].type };
	}

	std::string Function::GetArgumentName(size_t index) const {
		func_type_data_t functionData = get_func_type_data(_rva);
		assert(index < functionData.size());

		return functionData[index].name.c_str();
	}

	std::string Function::ToString() const {
		func_type_data_t functionData = get_func_type_data(_rva);

		std::stringstream ss;
		ss << GetReturnType().ToString() << ' ' << GetName() << ' {';
		for (size_t i = 0; i < GetArgumentCount(); ++i)
			ss << ' ' << GetArgumentType(i).ToString();
		ss << " }";
		return ss.str();
	}

	void Function::ModifyType(std::function<void(tinfo_t&, size_t)> transform) const {

		func_type_data_t functionData = get_func_type_data(_rva);

		transform(functionData.rettype, std::numeric_limits<size_t>::max());

		for (size_t i = 0; i < functionData.size(); ++i)
			transform(functionData[i].type, i);

		tinfo_t newTypeInfo;
		bool success = newTypeInfo.create_func(functionData);
		assert(success);
		
		// Goes completely to shit if TINFO_DEFINITE ??
		apply_tinfo(_rva, newTypeInfo, TINFO_DEFINITE);
	}

	std::string Function::GetName() const {
		std::string name = get_name(_rva, GN_DEMANGLED | GN_SHORT).c_str();
		auto replaceString = [](std::string& input, std::string_view needle, std::string_view repl) {
			size_t pos = 0;
			while ((pos = input.find(needle, pos)) != std::string::npos) {
				input.replace(pos, needle.length(), repl);
				pos += repl.length();
			}
		};

		replaceString(name, "::", "__");

		size_t position = name.find('(');
		if (position != std::string::npos)
			return name.substr(0, position);

		// Why does HexRays do this?
		if (name[0] == '_')
			name = name.substr(1);

		return name;
	}

	void Function::Decompile(std::ostream& stream, std::function<void(cfunc_t&)> filter /* = nullptr*/) const {
		func_t* function = get_func(_rva);
		assert(function != nullptr);

		hexrays_failure_t failure;
		cfuncptr_t functionPointer = decompile(function, &failure,
			DECOMP_NO_WAIT | DECOMP_NO_CACHE | DECOMP_NO_XREFS | DECOMP_NO_FRAME);
		if (failure.code != merror_t::MERR_OK)
			throw DecompilationException(failure.code, failure.errea, failure.desc().c_str());

		assert(functionPointer != nullptr);

		if (filter != nullptr)
			filter(*functionPointer);

		functionPointer->build_c_tree();
		functionPointer->refresh_func_ctext();
		const strvec_t& pseudocodeLines = functionPointer->get_pseudocode();

		// assembledPseudocode << "#include <" IDA_INCLUDE_DIR "/../../../plugins/defs.h>\n";

		for (simpleline_t line : pseudocodeLines) {
			tag_remove(&line.line, 0);

			stream << line.line.c_str() << '\n';
		}
	}

	std::vector<ea_t> Function::GetReferencesTo(int xrefFlags) const {
		std::vector<ea_t> crossReferences;

		xrefblk_t block;
		for (bool next = block.first_to(_rva, xrefFlags); next; next = block.next_to())
			if (block.iscode)
				crossReferences.push_back(block.from);

		return crossReferences;
	}

	std::unordered_set<ea_t> Function::GetReferencesFrom(int xrefFlags) const {
		func_t* function = get_func(_rva);
		assert(function != nullptr);

		std::unordered_set<ea_t> crossReferences;

		func_item_iterator_t itr;
		bool success = itr.set(function);
		while (success) {
			ea_t fnItem = itr.current();

			xrefblk_t block;
			for (bool hasMoreData = block.first_from(fnItem, XREF_ALL); hasMoreData; hasMoreData = block.next_from()) {
				if (xrefFlags == XREF_ALL || (xrefFlags == XREF_FAR && block.iscode && !function->contains(block.to)))
					crossReferences.insert(block.to);

				{
					// Read value at offset, if it's a pointer to code, store the reference
					// Same if it's data and we want that
					uint64_t value = get_qword(block.to);
					flags_t flags = get_full_flags(value);
					if (is_code(flags) && is_func(flags)) {
						if (xrefFlags != XREF_DATA) {
							// Don't store xrefs to our own code
							if (!function->contains(value))
								crossReferences.insert(value);
						}
					}
					else {
						if (xrefFlags != XREF_FAR)
							crossReferences.insert(value);
					}
				}
			}

			success = itr.next_code();
		}

		return crossReferences;
	}
}
