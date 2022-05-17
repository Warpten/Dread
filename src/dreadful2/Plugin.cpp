#pragma warning(push)
#pragma warning(disable : 4267 4244)
#define USE_STANDARD_FILE_FUNCTIONS
#include <hexrays.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <struct.hpp>
#include <loader.hpp>
#pragma warning(pop)

#include "Analyzer.hpp"
#include "Dread/CRC.hpp"
#include "IDA/API.hpp"
#include "IDA/API/Function.hpp"

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
    struct VersionInfo {
        std::array<uint8_t, 16> MD5;
        std::string_view Name;

        struct {
            ea_t CRC64;
        } Properties;
    };

    static const VersionInfo Versions[] = {
        VersionInfo {
            .MD5 = { 
                0xF5, 0xD9, 0xAA, 0x2A, 0xF3, 0xAB, 0xEF, 0x30, 0x70, 0x79, 0x10, 0x57, 0x06, 0x0E, 0xE9, 0x3C
            },
            .Name = "V1.0",
            .Properties = {
                .CRC64 = 0x0000007100001570uLL
            }
        }
    };

    struct PluginImpl {
        void Execute(VersionInfo const* versionInfo);
    };

    struct Plugin final : plugmod_t, PluginImpl {
        bool idaapi run(size_t) override {
            std::array<uint8_t, 16> checksum;
            if (!retrieve_input_file_md5(checksum.data()))
                return true;

            const VersionInfo* targetVersion = nullptr;
            for (VersionInfo const& versionInfo : Versions) {
                if (versionInfo.MD5 == checksum) {
                    targetVersion = std::addressof(versionInfo);
                    break;
                }
            }

            if (targetVersion == nullptr) {
                IDA::API::OpenMessageBox(IDA::API::MessageBoxLevel::Warning,
                    R"(This input file is not supported by Dreadful. 
It's either not a Metroid Dread ExeFS, or not a known version.)");
            } else {
                IDA::API::Message("Analyzing Metroid Dread {}...\n", targetVersion->Name);
                PluginImpl::Execute(targetVersion);
            }

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
    "Metroid, Dreadful", // Plugin Name
    "",                  // Hotkey
};

void Plugin::PluginImpl::Execute(VersionInfo const* versionInfo) {
    // Open a dialog asking for the name of the metadata type to generate
    constexpr static const std::string_view InputForm = R"(STARTITEM 0
BUTTON YES* Generate
BUTTON CANCEL Cancel

<Metadata type name:q>

)";
    qstring metadataTypeName;
    auto resultCode = ask_form(InputForm.data(), &metadataTypeName);
    if (resultCode == -1)
        return;

    // Corresponds to the game's CRC engine.
    using DreadEngine = CRC::Engine<0xFFFF'FFFF'FFFF'FFFFuLL, 0x42F0'E1BE'A9EA'3693uLL, 0x0uLL, true, true>;
    constexpr DreadEngine checksumEngine_;

    IDA::API::Message("Searching for references to {:#016x}.\n", versionInfo->Properties.CRC64);
    IDA::API::Function checksumFunction(versionInfo->Properties.CRC64);

    // TODO: Force CRC64 to uint64 (*)(const char*, size_t)
    std::unordered_map<IDA::API::Function, size_t> callers;

    for (ea_t callerRVA : checksumFunction.GetReferencesTo(XREF_FAR)) {
        // callerRVA = 0x000000710000D228uLL;

        auto [itr, success] = callers.try_emplace(IDA::API::Function{ callerRVA }, 1);
        if (!success)
            ++itr->second;

       // break;
    }

    IDA::API::Message("Found {} references to CRC64.\n", callers.size());
    if (callers.empty())
        return;

    std::stringstream analysisOutput;
	auto appendProperty = [&](std::string_view label, uint64_t value) {
		if (value == 0)
			return;

		analysisOutput << "    constexpr static const uint64_t "
			<< std::format("{:16} = 0x{:016x};", label, value) << '\n';
	};

    Analyzer analyzer;
    for (auto&& [reflCtor, referenceCount] : callers) {
        if (referenceCount != 1)
            break;

        Analyzer::ReflInfo reflInfo = analyzer.ProcessReflectionObjectConstruction(reflCtor);
        if (reflInfo.Name.empty())
            break;

        // Analyze the function corresponding to the callsite; it's the thread-safe
        // std::call_once usage.
        // analyzer.ProcessObject(IDA::API::Function{ callers.front() });

        IDA::API::Message("Found construction of metadata for '{}' at {:#016x}.\n", reflInfo.Name, reflCtor.GetAddress());

        uint64_t fnGet = reflInfo.Properties[0x68];
        if (fnGet != 0uLL && reflInfo.Self == 0x0uLL) {
            // Don't bother trying to get refl object if we have it already
            IDA::API::Function getReflInfo{ fnGet };
            while (getReflInfo.IsThunk()) {
                std::unordered_set<ea_t> calledFunctions = getReflInfo.GetReferencesFrom(XREF_FAR);
                assert(calledFunctions.size() == 1);

                getReflInfo = IDA::API::Function{ *calledFunctions.begin() };
            }

            analyzer.ProcessObject(getReflInfo, reflInfo);
        }

        if (reflInfo.Self == 0) {
            // If we couldn't find it, then try by looking at callers
            std::vector<ea_t> callers = reflCtor.GetReferencesTo(XREF_FAR);
            assert(callers.size() == 1);

            IDA::API::Function callerInfo{ callers.front() };
            analyzer.ProcessReflectionObjectConstructionCall(callerInfo, reflInfo, reflCtor.GetAddress());
        }

        if (reflInfo.Self == 0) {
            IDA::API::Message("Could not find global instance of metadata for '{}'.\n", reflInfo.Name);
            continue;
        }

		constexpr static const std::string_view MetadataTemplate = R"(
template <> struct Metadata<{}> {{
    constexpr static const std::string_view Name = "{}";
    constexpr static const uint64_t CRC64 = {:#016x};

    constexpr static const uint64_t Instance = {:#016x};

    constexpr static const uint64_t Constructor      = {:#016x};
    constexpr static const uint64_t CopyConstructor  = {:#016x};
    constexpr static const uint64_t MoveConstructor  = {:#016x};
    constexpr static const uint64_t Destructor       = {:#016x};
    // 0x48
    // 0x50
    constexpr static const uint64_t EqualityComparer = {:#016x};
    constexpr static const uint64_t GetHashCode      = {:#016x};
    constexpr static const uint64_t EnumerateMembers = {:#016x};
}};)";

        analysisOutput << std::format(MetadataTemplate,
            reflInfo.Name,
            reflInfo.Name,
            checksumEngine_(reflInfo.Name),
            reflInfo.Self,
            reflInfo.Properties[0x28],
            reflInfo.Properties[0x30],
            reflInfo.Properties[0x38],
            reflInfo.Properties[0x40],
            // reflInfo.Properties[0x48],
            // reflInfo.Properties[0x50],
            reflInfo.Properties[0x58],
            reflInfo.Properties[0x60],
            reflInfo.Properties[0x70]
        );
    }
}
