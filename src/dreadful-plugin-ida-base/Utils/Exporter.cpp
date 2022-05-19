#include "Exporter.hpp"

#include <IDA/API/Function.hpp>

#include <format>
#include <iostream>
#include <regex>

namespace Utils {
	Exporter::Exporter(std::ostream& outputStream) : _outputStream(outputStream) { }

	void Exporter::Run(IDA::API::Function const& functionInfo, std::function<void(tinfo_t&)> returnTypeTransform) {
		auto modifyArgCallback = [](tinfo_t& argType) {
			if (argType.is_struct()) {
				size_t argumentSize = argType.get_size();

				switch (argumentSize) {
					case BADSIZE: // ???
						break;
					case 16:
						argType = tinfo_t{ BTF_UINT128 };
						break;
					case 8:
						argType = tinfo_t{ BTF_UINT64 };
						break;
					case 4:
						argType = tinfo_t{ BTF_UINT32 };
						break;
					case 2:
						argType = tinfo_t{ BTF_UINT16 };
						break;
					case 1:
						argType = tinfo_t{ BTF_UINT8 };
						break;
					default:
					{
						// If the type is a struct, pretend it's the raw binary data
						// TODO: What about type alignment?
						array_type_data_t arrayData(0, argumentSize);
						arrayData.elem_type = tinfo_t{ BTF_UINT8 };

						argType.create_array(arrayData);
						break;
					}
				}
			}
			else if (argType.is_ptr()) {
				using namespace std::string_view_literals;

				// If it's a pointer to struct or function, change to uint64 
				// so that we can ignore it. Otherwise don't touch.
				tinfo_t pointedType = argType.get_pointed_object();
				if (!pointedType.is_scalar() || pointedType.is_func() || pointedType.is_struct() || pointedType.is_decl_struct())
					argType = tinfo_t{ BTF_UINT64 };
				// Also hide away guard variables
				else if (pointedType.dstr() == "__guard"sv)
					argType = tinfo_t{ BTF_UINT64 };
			}
		};

		functionInfo.ModifyType([&](tinfo_t& argType, size_t argIndex) {
			if (argIndex == std::numeric_limits<size_t>::max()) {
				returnTypeTransform(argType);
			}
			else {
				std::invoke(modifyArgCallback, std::ref(argType));
			}
		});

		std::stringstream assembledPseudocode;
		assembledPseudocode << "#include <" IDA_INCLUDE_DIR "/../../../plugins/defs.h>\n";

		assembledPseudocode << R"(
// Universally convertible to-and-from type.
struct AnyType {
    template <typename T> AnyType(T) { }

    AnyType() { }

    template <typename T>
    operator T() { return T {}; }

    template <typename T>
    operator T() const { return T {}; }
};

using _OWORD = unsigned __int128;

AnyType __ldar(AnyType);

unsigned __int64 vtable_for_base__reflection__CType;
unsigned __int64 vtable_for_base__reflection__CClass;
unsigned __int64 vtable_for_base__reflection__CEnum;
unsigned __int64 vtable_for_base__reflection__CCollectionType;

)";

		for (ea_t reference : functionInfo.GetReferencesFrom(XREF_FAR)) {
			IDA::API::Function callee{ reference };
			std::string calleeName = callee.GetName();
			if (calleeName.empty())
				continue;

			// Abuse the clang::annotate attribute to store offsets properly
			assembledPseudocode << '\n' << std::format(R"([[clang::annotate("0x{:016x}")]] )", reference);
			assembledPseudocode << "AnyType " << calleeName << '(';
			for (size_t i = 0; i < callee.GetArgumentCount(); ++i) {
				if (i > 0)
					assembledPseudocode << ", ";

				assembledPseudocode << "AnyType";
			}
			assembledPseudocode << ");";
		}

		assembledPseudocode << '\n';

		for (ea_t reference : functionInfo.GetReferencesFrom(XREF_DATA)) {
			std::string name = get_name(reference, GN_DEMANGLED).c_str();
			if (name.empty())
				continue;

			auto replaceString = [](std::string& input, std::string_view needle, std::string_view repl) {
				size_t pos = 0;
				while ((pos = input.find(needle, pos)) != std::string::npos) {
					input.replace(pos, needle.length(), repl);
					pos += repl.length();
				}
			};

			replaceString(name, "::", "__");

			// Set data type to uint64_t
			apply_tinfo(reference, tinfo_t{ BTF_UINT64 }, TINFO_DEFINITE);

			// Abuse clang::annotate so that we can later map from names

			// Generate the regular name
			assembledPseudocode << '\n' <<
				std::format(R"([[clang::annotate("0x{1:016x}")]] unsigned __int64 {0};)", name, reference);

			// Why does Hex-Rays do this?
			if (name[0] == '_') {
				// Also generate one with stripped first underscore if it exists
				assembledPseudocode << '\n' <<
					std::format(R"([[clang::annotate("0x{1:016x}")]] unsigned __int64 {0};)", name.substr(1), reference);
			}
			else {
				// Also generate one with extra underscore if it exists
				assembledPseudocode << '\n' <<
					std::format(R"([[clang::annotate("0x{1:016x}")]] unsigned __int64 _{0};)", name, reference);
			}
		}

		assembledPseudocode << "\n\n";
		functionInfo.Decompile(assembledPseudocode, [](cfunc_t& fn) {
			// 1. Make all pointer stack elements uint64
			lvars_t* localVariables = fn.get_lvars();
			assert(localVariables != nullptr);

			for (size_t i = 0; i < localVariables->size(); ++i) {
				lvar_t& localVariable = (*localVariables)[i];
				const tinfo_t& variableType = localVariable.type();

				if (variableType.is_ptr())
					localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT64 });
				else if (variableType.is_struct()) {
					size_t variableSize = variableType.get_size();
					switch (variableSize) {
						case BADSIZE: // ??? Send help
							break;
						case 16:
							localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT128 });
							break;
						case 8:
							localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT64 });
							break;
						case 4:
							localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT32 });
							break;
						case 2:
							localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT16 });
							break;
						case 1:
							localVariable.set_final_lvar_type(tinfo_t{ BTF_UINT8 });
							break;
						default:
						{
							// If it's a struct, set it to an array matching the size of the structure
							// TODO: type alignment?
							array_type_data_t arrType(0, variableType.get_size());
							arrType.elem_type = tinfo_t{ BTF_UINT8 };

							tinfo_t newType;
							newType.create_array(arrType);
							localVariable.set_final_lvar_type(newType);

							break;
						}
					}
				}
			}
			});

		std::string pseudocode = assembledPseudocode.str();

		auto replaceString = [](std::string& input, std::string_view needle, std::string_view repl) {
			size_t pos = 0;
			while ((pos = input.find(needle, pos)) != std::string::npos) {
				input.replace(pos, needle.length(), repl);
				pos += repl.length();
			}
		};

		replaceString(pseudocode, "&`vtable for'", "&vtable_for_");
		replaceString(pseudocode, "__~", "__dtor_");

		// Try **really** hard to get rid of casts
		// First pass removes casts to incomplete types
		pseudocode = std::regex_replace(pseudocode,
			std::regex{ R"(#[0-9]+ \*)" }, "AnyType");
		//pseudocode = std::regex_replace(pseudocode,
		//    std::regex{ R"((\([a-z0-9_ *&]+\))(&?\*?[a-z]))" }, "$2");

		// This is EVEN more stupid - HexRays won't always insert casts...
		pseudocode = std::regex_replace(pseudocode,
			std::regex{ R"(\) = (&?[^0-9~][^;]+);)" }, ") = (AnyType)($1);");

		_outputStream << pseudocode;
	}
}