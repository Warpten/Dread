#include "DecompilationException.hpp"
#include "Function.hpp"
 
#include <llvm/ADT/StringRef.h>

#include <clang/Basic/Diagnostic.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Tooling/Tooling.h>

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

	const auto get_func_type_data = [](ea_t rva) {
		tinfo_t functionInfo;
		bool success = get_tinfo(&functionInfo, rva);
		assert(success);

		func_type_data_t functionData;
		success = functionInfo.get_func_details(&functionData);
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

	std::string Function::GetDeclaration(bool simplified /* = false */) const {
		tinfo_t functionInfo;
		if (!get_tinfo(&functionInfo, _rva))
			return "";

		func_type_data_t functionData;
		functionInfo.get_func_details(&functionData);

		std::stringstream formatStream;
		auto simplifyTypeIfNeeded = [&](tinfo_t type, auto&& ref) -> std::string {
			if (simplified) {
				if (type.is_ptr()) {
					tinfo_t pointedType = type.get_pointed_object();
					return ref(pointedType, ref) + "*";
				}

				// TODO: Simplify structs, or start dumping them in the pseudocode as well ??
			}

			return type.dstr();
		};

		formatStream << simplifyTypeIfNeeded(functionData.rettype, simplifyTypeIfNeeded) << ' ' << GetName() << '(';
		for (size_t i = 0; i < functionData.size(); ++i) {
			if (i > 0)
				formatStream << ", ";
			formatStream << simplifyTypeIfNeeded(functionData[i].type, simplifyTypeIfNeeded) << ' ' << functionData[i].name.c_str() << ", ";
		}
		formatStream << ");";
		return formatStream.str();
	}

	std::string Function::GetName() const {
		return get_name(_rva, GN_DEMANGLED).c_str();
	}

	std::string Function::Decompile(std::function<void(cfunc_t&)> filter /* = nullptr*/) const {
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
		const strvec_t& pseudocodeLines = functionPointer->get_pseudocode();

		std::stringstream assembledPseudocode;
		assembledPseudocode << "#include <" IDA_INCLUDE_DIR "/../../../plugins/defs.h>\n";

		{
			std::set<ea_t> dataReferences;
			std::set<ea_t> codeReferences;

			func_item_iterator_t itr;
			bool success = itr.set(function);
			while (success) {
				ea_t fnItem = itr.current();

				xrefblk_t block;
				for (bool hasMoreData = block.first_from(fnItem, XREF_ALL); hasMoreData; hasMoreData = block.next_from()) {
					if (block.iscode)
						codeReferences.insert(block.to);
					else {
						dataReferences.insert(block.to);

						uint64_t value = get_qword(block.to);
						flags_t flags = get_full_flags(value);
						if (is_code(flags) && is_func(flags))
							codeReferences.insert(value);
					}
				}

				success = itr.next_addr();
			}

			for (ea_t dataReference : dataReferences) {
				std::string name = get_name(dataReference).c_str();
				if (name.empty())
					continue;

				assembledPseudocode << "\n_QWORD " << name << ';';
			}

			for (ea_t codeReference : codeReferences) {
				std::string name = get_name(codeReference).c_str();
				if (name.empty())
					continue;

				assembledPseudocode << "\n" << IDA::API::Function{ codeReference }.GetDeclaration(true);
			}
		}

		assembledPseudocode << "\n\n";

		for (simpleline_t line : pseudocodeLines) {
			tag_remove(&line.line, 0);

			assembledPseudocode << line.line.c_str() << '\n';
		}
		
		return assembledPseudocode.str();
	}

	std::vector<ea_t> Function::GetReferencesTo(int xrefFlags) const {
		std::vector<ea_t> crossReferences;

		xrefblk_t block;
		for (bool next = block.first_to(_rva, xrefFlags); next; next = block.next_to())
			if (block.iscode)
				crossReferences.push_back(block.from);

		return crossReferences;
	}

	std::vector<ea_t> Function::GetReferencesFrom(int xrefFlags) const {
		std::vector<ea_t> crossReferences;

		func_t* fn = get_func(_rva);
		func_item_iterator_t itr;
		bool success = itr.set(fn);
		while (success) {
			ea_t fnItem = itr.current();

			xrefblk_t block;
			for (bool hasMoreData = block.first_from(fnItem, xrefFlags); hasMoreData; hasMoreData = block.next_from())
				crossReferences.push_back(block.to);

			success = itr.next_code();
		}

		return crossReferences;
	}
}
