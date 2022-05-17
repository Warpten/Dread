#pragma warning(push)
#pragma warning(disable : 4267 4244)
#define USE_STANDARD_FILE_FUNCTIONS
#include <hexrays.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <struct.hpp>
#include <loader.hpp>
#pragma warning(pop)

#include <array>
#include <cstdint>
#include <string_view>
#include <unordered_set>
#include <fstream>
#include <iomanip>
#include <variant>

hexdsp_t* hexdsp = nullptr;

// Plugin implementation ---
namespace Plugin {
	struct PluginImpl {
		void Execute();
	};

	struct Plugin final : plugmod_t, PluginImpl {
		bool idaapi run(size_t) override {
			PluginImpl::Execute();

			return true;
		}
	};

#if defined(NO_OBSOLETE_FUNCS)
	constexpr static const auto Error = nullptr;
	static Plugin Instance;
	static auto PluginInstance = &Instance;
#else
	constexpr static const auto Error = PLUGIN_SKIP;
	static const auto PluginInstance = PLUGIN_KEEP;
#endif

	plugmod_t* idaapi Initialize() {
		// 1. Initialize HexRays.
		if (!init_hexrays_plugin())
			return Error;

#if defined(NO_OBSOLETE_FUNCS)
		return new Plugin();
#else
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
	Plugin::Initialize,  // Initializer
#if defined(NO_OBSOLETE_FUNCS)
	nullptr,
	nullptr,
#else
	Plugin::Terminate,   // Terminater
	Plugin::Run,         // Runner
#endif
	"",                  // Comment
	"",                  // Help
	"Dump Clang pseudocode", // Plugin Name
	"",                  // Hotkey
};

void Plugin::PluginImpl::Execute() {

}
