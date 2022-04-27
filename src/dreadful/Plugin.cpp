#pragma warning( disable : 4267 4244 )

#include <hexrays.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <struct.hpp>
#include <loader.hpp>

#pragma warning( default : 4267 4244)

#include <algorithm>
#include <array>
#include <cassert>
#include <concepts>
#include <coroutine>
#include <format>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <tuple>
#include <utility>

#include "Analyzers/Analyzers.hpp"
#include "Analyzers/Mangler.hpp"
#include "IDA/API/API.hpp"
#include "IDA/Microcode/Instructions.hpp"
#include "IDA/Microcode/Microcode.hpp"
#include "utils/Generator.hpp"

hexdsp_t* hexdsp = nullptr;

namespace utils {
    template <typename R, typename Left, typename Right, typename... Ranges>
    auto set_intersection(R outputContainer, Left&& left, Right&& right, Ranges&&... ranges) {
        std::set_intersection(left.begin(), left.end(), right.begin(), right.end(), std::inserter(outputContainer, std::end(outputContainer)));
        if constexpr (sizeof...(Ranges) == 0)
            return outputContainer;
        else
            return set_intersection(R{}, outputContainer, std::forward<Ranges&&>(ranges)...);
    }
}

struct less_rule {
	constexpr bool operator () (const func_t* lhs, const func_t* rhs) const {
		if (lhs == nullptr || rhs == nullptr)
			return false;

		return lhs->start_ea < rhs->start_ea&& lhs->end_ea < rhs->end_ea;
	}
};

struct equal_rule {
	constexpr bool operator () (const func_t* lhs, const func_t* rhs) const {
		if (lhs == nullptr || rhs == nullptr)
			return lhs == rhs;

		return lhs->start_ea == rhs->start_ea&& lhs->end_ea == rhs->end_ea;
	}
};

template <typename T>
using adjusted_set = std::set<T, less_rule>;

struct IdaFunction {
    IdaFunction(func_t* fn) : _fn(fn) { }

    friend bool operator == (IdaFunction const& lhs, IdaFunction const& rhs) {
        if (lhs._fn == nullptr || rhs._fn == nullptr)
            return lhs._fn == rhs._fn;

        return lhs._fn->start_ea == rhs._fn->start_ea && lhs._fn->end_ea == rhs._fn->end_ea;
    }

    friend bool operator < (IdaFunction const& lhs, IdaFunction const& rhs) {
        if (lhs._fn == nullptr || rhs._fn == nullptr)
            return uintptr_t(rhs._fn) < 0uLL; // nauseated

        return lhs._fn->start_ea < rhs._fn->start_ea && lhs._fn->end_ea < rhs._fn->end_ea;
    }

    func_t* _fn;
};

// Plugin implementation ---
namespace Plugin {

struct Plugin : plugmod_t {
    bool idaapi run(size_t) override {
        using namespace IDA::API;

        auto callback = [this](func_t* function, size_t index, size_t total) {
            if (function == nullptr)
                return;

            // Prepare storage for analyzers
            auto&& functionInfo = _functionStore.FindEntry(function->start_ea);

            std::string functionName = IDA::API::ToString(get_name(function->start_ea, GN_DEMANGLED));
            IDA::API::LogMessage("(Info) ({}/{}) Analyzing on '{}' at 0x{:x}...\n",
                index,
                total,
                functionName,
                function->start_ea);

            // Get this function's microcode.
            functionInfo.GetReflInfo.Microcode = IDA::API::GenerateMicrocode(function->start_ea);
			if (!functionInfo.GetReflInfo.Microcode) {
				IDA::API::LogMessage("(Error) An error occurred while generating microcode.\n");
                return;
            }

            // InstructionVisitor<
            //     Analysis::Engine,
            //     base::global::CStrId::CStrId
            // > visitor {
            //     this->_functionStore, functionInfo.GetReflInfo.Microcode.get(), functionInfo
            // };
            
            if (InstructionVisitor<Analysis::Engine, base::global::CStrId::CStrId>::Run(functionInfo.GetReflInfo.Microcode.get(),
                _functionStore, functionInfo) != MERR_OK) {
                IDA::API::LogMessage("(Error) An error occurred while processing microcode.\n");
                return;
            }
        };

        auto collect_xref = [] <template <typename...> class Container> (ea_t address) {
            return cppcoro::accumulate(
                EnumerateXrefTo(address, XREF_ALL),
                [](ea_t xref, Container<IdaFunction>& container) {
                    func_t* func = IDA::API::GetFunction(xref);
                    if (func != nullptr)
                        container.insert(func);
                }, Container<IdaFunction>{});
        };

        // C++ is a bit stupid here ... Bite the bullet.
        // Find __cxa_guard_acquire and __cxa_guard_release, keep the set intersection.
        auto guardAcquireRefs = collect_xref.operator()<std::set>(/*__cxa_guard_acquire*/0x00000071011F3000uLL);
        auto guardReleaseRefs = collect_xref.operator()<std::set>(/*__cxa_guard_release*/0x00000071011F3010uLL);
        auto cstridRefs       = collect_xref.operator()<std::set>(base::global::CStrId::CStrId::Address);

		std::vector<IdaFunction> filteredReferences =
            ::utils::set_intersection(decltype(filteredReferences) {}, guardAcquireRefs, guardReleaseRefs, cstridRefs);
        
        size_t i = 0;
        for (auto&& xref : filteredReferences) {
            callback(xref._fn, ++i, filteredReferences.size());
            
#if _DEBUG
            if (i == 10)
                break;
#endif
        }

        _functionStore.Process();

        return MERR_OK;
    }

private:
    Analysis::Engine _functionStore;
};

    plugmod_t* idaapi Initialize() {
        // TODO: Check that we are loading Metroid Dread
        //       And select EAs depending on the version of the game
        //       Base this off of image MD5

#if defined(NO_OBSOLETE_FUNCS)
        if (!init_hexrays_plugin())
            return nullptr;

        static Plugin plugin;
        return &plugin;
#else
        if (!init_hexrays_plugin())
            return PLUGIN_SKIP;

        return PLUGIN_KEEP;
#endif
    }

#if defined(NO_OBSOLETE_FUNCS)
# if IDA_SDK_VERSION >= 700
    bool idaapi Run(size_t)
# else
    void idaapi Run()
# endif
    {
        Plugin{}.run(0);
        return true;
    }

    void idaapi Terminate() {
        assert(false && "Should not be called");
    }
#endif

}

extern plugin_t PLUGIN;

#if defined(NO_OBSOLETE_FUNCS) && defined(PLUGIN_MULTI)
#  if _DEBUG
#    define FLAGS PLUGIN_UNL | PLUGIN_MULTI
#  else
#    define FLAGS PLUGIN_MULTI
#  endif
#else
#  if _DEBUG
#    define FLAGS PLUGIN_UNL
#  else
#    define FLAGS 0
#  endif
#endif

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION, // IDA version
    FLAGS,
    Plugin::Initialize,    // Initializer
#if defined(NO_OBSOLETE_FUNCS)
    nullptr,
    nullptr,
#else
    Plugin::Terminate,     // Terminater
    Plugin::Run,           // Runner
#endif
    "",                    // Comment
    "",                    // Help
    "Metroid Dread",       // Plugin Name
    "",                    // Hotkey
};
