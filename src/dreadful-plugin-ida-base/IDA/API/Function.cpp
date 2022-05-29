#include "DecompilationException.hpp"
#include "Function.hpp"

#include <charconv>
#include <regex>
#include <set>
#include <stack>
#include <unordered_set>

auto get_tinfo_from_cfunc_t(ea_t rva) {
	func_t* function = get_func(rva);
	assert(function != nullptr);

	hexrays_failure_t failure;
	cfuncptr_t functionPointer = decompile(function, &failure,
		DECOMP_NO_WAIT | DECOMP_NO_CACHE | DECOMP_NO_XREFS | DECOMP_NO_FRAME);
	if (failure.code != merror_t::MERR_OK)
		throw IDA::API::DecompilationException(failure.code, failure.errea, failure.desc().c_str());

	tinfo_t tif;
	bool success = functionPointer->get_func_type(&tif);
	if (!success)
		throw IDA::API::DecompilationException(failure.code, failure.errea, failure.desc().c_str());

	return tif;
};

auto get_func_type_data(ea_t rva) {
	tinfo_t functionInfo = get_tinfo_from_cfunc_t(rva);

	func_type_data_t functionData;
	bool success = functionInfo.get_func_details(&functionData);
	assert(success);

	return functionData;
}; 

auto get_cfunc_t(ea_t rva) {
	func_t* function = get_func(rva);
	assert(function != nullptr);

	hexrays_failure_t failure;
	cfuncptr_t functionPointer = decompile(function, &failure,
		DECOMP_NO_WAIT | DECOMP_NO_CACHE | DECOMP_NO_XREFS | DECOMP_NO_FRAME);
	if (failure.code != merror_t::MERR_OK)
		throw IDA::API::DecompilationException(failure.code, failure.errea, failure.desc().c_str());

	assert(functionPointer != nullptr);
	return functionPointer;
}

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

	void Function::IterateLocals(std::function<void(lvar_t&)> callback) const {
		auto funcPtr = get_cfunc_t(_rva);
		assert(funcPtr != nullptr);

		for (size_t i = 0; i < funcPtr->get_lvars()->size(); ++i)
			callback(funcPtr->get_lvars()->at(i));
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
		cfuncptr_t functionPointer = get_cfunc_t(_rva);

		if (filter != nullptr)
			filter(*functionPointer);

		functionPointer->build_c_tree();
		functionPointer->refresh_func_ctext();
		const strvec_t& pseudocodeLines = functionPointer->get_pseudocode();

		for (simpleline_t line : pseudocodeLines) {
			// Dynamically remove colons unless they are within a string
			bool fixColons = true;
			bool canPrintCharacter = true;
			int32_t parenthesisStack = 0;
			bool isCurrentCodeEscaped = false;

			const char* cursor = line.line.c_str();

			while (*cursor != 0) {
				if (isCurrentCodeEscaped) {
					// Shortcircuit if escaped, append, move ahead, and reset
					stream << *cursor;
					++cursor;
					isCurrentCodeEscaped = false;

					continue;
				}

				switch (*cursor) {
					case COLOR_ON:
					{
						char colorCode = *(cursor + 1);
						cursor = tag_skipcode(cursor);

						if (colorCode == COLOR_HIDNAME) {
							canPrintCharacter = false;

							// For some abscond reason, parentheses are tagged as COLOR_SYMBOL.
							// Manually remove them (by just seeking backwards)
							if (parenthesisStack > 1)
								stream.seekp(-1, std::ios::cur);
						}

						break;
					}
					case COLOR_OFF:
					{
						char colorCode = *(cursor + 1);
						cursor = tag_skipcode(cursor);

						if (colorCode == COLOR_HIDNAME) {
							canPrintCharacter = true;

							// Counterpart of the above (in COLOR_ON). Here the closing parenthesis
							// hasn't been written yet, so we immediately skip over it.
							if (parenthesisStack > 1) {
								cursor = tag_skipcode(cursor);

								// And finally skip the parenthesis.
								assert(*cursor == ')');
								++cursor;
							}
						}
						break;
					}
					case COLOR_ESC:
						isCurrentCodeEscaped = true;
						++cursor;
						break;
					case COLOR_INV:
						cursor = tag_skipcode(cursor);
						break;
					case '(':
						++parenthesisStack;
						goto DEFAULT_CASE; // Sue me
					case ')':
						--parenthesisStack;
						goto DEFAULT_CASE; // Sue me
					case ':':
						stream << (fixColons ? '_' : ':');
						++cursor;
						break;
					case '"':
						fixColons ^= true;
						[[fallthrough]];
					default:
					DEFAULT_CASE:
						if (canPrintCharacter || parenthesisStack <= 1)
							stream << *cursor;

						++cursor;
						break;
				}
			}
			stream << '\n';
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
				auto filter = [&block, &function, &xrefFlags](ea_t addr) {
					flags_t flags = get_full_flags(addr);
					if (!(xrefFlags & XREF_DATA) && is_func(flags))
						return true;

					// Also dump unexplored bytes here just in case
					if (!(xrefFlags & XREF_FAR) && (is_data(flags) || is_unknown(flags)))
						return true;

					return false;
				};

				if (filter(block.to))
					crossReferences.insert(block.to);

				uint64_t value = get_qword(block.to);
				if (filter(value))
					crossReferences.insert(value);
			}

			success = itr.next_addr();
		}

		// Unfortunately there are situations where IDA will fail to see data references
		// ADRL  X19, qword_7101CF3DC8
		// ADRL  X1,  aSources; "sources"
		// MOV   X0,  X19; int
		// MOV   W2,  #1
		// BL    sub_71000003D4
		// ADRP  X20, #off_7101C627A8@PAGE
		// LDR   X20, [X20, #off_7101C627A8@PAGEOFF]
		// ADRL  X21, off_71019C3000
		// MOV   X2,  X21
		// MOV   X0,  X20
		// MOV   X1,  X19
		// BL    sub_7100000250
		// ADD   X22, X19, #8 <-- This is X22 = &qword_7101CF3DC8 + 8
		//                                  Which Hex-Rays will show as &qword_7101CF3DD0
		// The only sort of reliable way to find these is to look through the ctree ... which we do.
		cfuncptr_t functionPointer = get_cfunc_t(_rva);

		// Do not attempt to fix casts and ctree text; just look through the lines

		struct ctree_visitor : public ctree_visitor_t {
			explicit ctree_visitor(int xrefFlags, std::unordered_set<uint64_t>& references) 
				: ctree_visitor_t(CV_FAST), _xrefFlags(xrefFlags) , _crossReferences(references)
			{ }
			
			int idaapi visit_expr(cexpr_t* expression) override {
				if (expression->op == ctype_t::cot_obj)
					processOne(expression);

				return 0;
			}

		private:
			bool processOne(cexpr_t* expr) {
				uint64_t objectAddress = expr->obj_ea;
				uint64_t objectFlags = get_full_flags(objectAddress);

				if (is_func(objectFlags) && _xrefFlags != XREF_DATA) {
					_crossReferences.emplace(objectAddress);
					return true;
				} else if ((is_data(objectFlags) || is_unknown(objectFlags)) && _xrefFlags != XREF_FAR) {
					_crossReferences.emplace(objectAddress);
					return true;
				}

				return false;
			};


			int _xrefFlags;
			std::unordered_set<uint64_t>& _crossReferences;
		} visitor(xrefFlags, crossReferences);

		visitor.apply_to(&functionPointer->body, nullptr);

		return crossReferences;
	}
}
