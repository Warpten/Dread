#include "Exporter.hpp"

#include <IDA/API/Function.hpp>

#include <format>
#include <iostream>
#include <regex>
#include <span>

#include <CTRE/ctre.hpp>

namespace Utils {
    Exporter::Exporter(std::ostream& outputStream) : _outputStream(outputStream) { }

    tinfo_t SimplifyType(tinfo_t const& inputType, bool inPointerContext = false) {
        const char* src = inputType.dstr();

        if (inputType.is_ptr() && !inputType.is_funcptr()) {
            if (false /* || !inPointerContext */) {
                ptr_type_data_t pointerType;
                pointerType.obj_type = SimplifyType(inputType.get_pointed_object(), true);
                if (inputType.is_pvoid())
                    pointerType.obj_type = tinfo_t{ BTF_UINT64 };

                tinfo_t newType;
                newType.create_ptr(pointerType);
                return newType;
            }
            else {
                return tinfo_t{ BTF_UINT64 };
            }
        }

        if (inputType.is_scalar() || inputType.is_array() || inputType.is_funcptr())
            return inputType;

        size_t argumentSize = inputType.get_size();
        switch (argumentSize) {
            case BADSIZE:
                throw "send help";
            case 16:
                return tinfo_t{ BTF_UINT128 };
            case 8:
                return tinfo_t{ BTF_UINT64 };
            case 4:
                return tinfo_t{ BTF_UINT32 };
            case 2:
                return tinfo_t{ BTF_UINT16 };
            case 1:
                return tinfo_t{ BTF_UINT8 };
            default:
            {
                array_type_data_t arrayData(0, argumentSize);
                arrayData.elem_type = tinfo_t{ BTF_UINT8 };

                tinfo_t newType;
                newType.create_array(arrayData);
                return newType;
            }

        }
    }

    void Exporter::Run(IDA::API::Function const& functionInfo, std::function<void(tinfo_t&)> returnTypeTransform) {
        functionInfo.ModifyType([&](tinfo_t& argType, size_t argIndex) {
            if (argIndex == std::numeric_limits<size_t>::max()) {
                returnTypeTransform(argType);
            }
            else {
                argType = SimplifyType(argType);
            }
        });

        std::stringstream assembledPseudocode;
        assembledPseudocode << "#include <" IDA_INCLUDE_DIR "/../../../plugins/defs.h>\n";

        assembledPseudocode << R"(
// Evil universally convertible to-and-from type.
struct Any {
    Any();
    template <typename T> Any(T);

    // Equality operators
    template <typename T> bool operator != (T);
    template <typename T> bool operator == (T);

    operator bool();

    // Assignment operator
    template <typename T> Any operator = (T);

    // Explicit cast operator
    template <typename T> explicit operator T();

    // Arithmetic operators
    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator + (Any, T);
    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator + (T, Any);

    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator - (Any, T);
    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator - (T, Any);

    // Binary operators
    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator & (Any, T);
    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator & (T, Any);

    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator | (Any, T);
    template <typename T> friend std::enable_if_t<!std::is_same_v<T, Any>, Any&> operator | (T, Any);

    // Dereference & pointer-to operators
    Any operator * ();
    // Any operator & ();

    // Array subscript operator
    Any operator [] (int);

    // (Post-)increment
    Any operator ++ ();
    Any operator ++ (int);

    // (Post-)decrement
    Any operator -- ();
    Any operator -- (int);
};

// The missing space here is important - see the regex
using _OWORD= unsigned __int128;

Any __ldar(Any);

)";

        for (ea_t reference : functionInfo.GetReferencesFrom(XREF_FAR)) {
            IDA::API::Function callee{ reference };
            std::string calleeName = callee.GetName();
            if (calleeName.empty())
                continue;

            // Abuse the clang::annotate attribute to store offsets properly
            assembledPseudocode << '\n' << std::format(R"([[clang::annotate("0x{:016x}")]] )", reference);
#if 1
            assembledPseudocode << "Any " << calleeName << '(';
            for (size_t i = 0; i < callee.GetArgumentCount(); ++i) {
                if (i > 0)
                    assembledPseudocode << ", ";

                assembledPseudocode << "Any";
            }
            assembledPseudocode << ");";
#else
            assembledPseudocode << "AnyType " << calleeName << '(';
            for (size_t i = 0; i < callee.GetArgumentCount(); ++i) {
                if (i > 0)
                    assembledPseudocode << ", ";

                assembledPseudocode << "AnyType";
            }
            assembledPseudocode << ");";
#endif
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
            assembledPseudocode << '\n' <<
                std::format(R"([[clang::annotate("0x{:016x}")]] Any {};)", 
                    reference, name);
        }

        assembledPseudocode << "\n\n";

        functionInfo.Decompile(assembledPseudocode, [&](cfunc_t& fn) {
            // Encapsulate all local variables
            lvars_t* localVariables = fn.get_lvars();
            assert(localVariables != nullptr);

            for (size_t i = 0; i < localVariables->size(); ++i) {
                lvar_t& localVariable = (*localVariables)[i];
                const tinfo_t& variableType = localVariable.type();

                tinfo_t simplifiedType = SimplifyType(variableType);
                localVariable.set_final_lvar_type(simplifiedType);
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

        // Make every local variable FixedType<T>
        // Type information is almost lost, except it isn't, we shove it in the template
        functionInfo.IterateLocals([&](lvar_t& localVariable) {
            const tinfo_t& variableType = localVariable.type();
             size_t varTypeSize = variableType.get_size();

            pseudocode = std::regex_replace(pseudocode,
                std::regex{
                    std::format(R"(^ +(unsigned |signed )?([^ ]+) \*?{}; //)", localVariable.name.c_str())
                },
                std::format("  Any {}; //", localVariable.name.c_str())
            );
        
             // std::string searchBuffer = localVariable.dstr();
             // std::string replacementBuffer = adjustedTypes[searchBuffer];
             // replaceString(pseudocode, searchBuffer, replacementBuffer);
        });

        constexpr static const auto assignmentRegex = ctre::range<R"( = ([^;()]+);)">;
        for (auto matchResults : assignmentRegex(pseudocode)) {
            std::string_view needle{ matchResults.get<1>() };
            if (needle.ends_with("LL"))
                needle.remove_suffix(2);

            if (needle.size() > 2) {
                if (needle[0] == '0' && needle[1] == 'x')
                    continue;
            }

            bool isInteger = true;
            for (size_t i = 0; isInteger && i < needle.size(); ++i)
                isInteger &= (needle[i] >= '0' && needle[i] < '9');

            if (!isInteger)
                replaceString(pseudocode, matchResults.get<0>(), std::format(" = (Any){};", needle));
        }

        replaceString(pseudocode, "&`vtable for'", "&vtable_for_");
        replaceString(pseudocode, "__~", "__dtor_");

        _outputStream << pseudocode;
    }
}