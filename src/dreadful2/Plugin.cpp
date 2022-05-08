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
    // Corresponds to the game's CRC engine.
    using DreadEngine = CRC::Engine<0xFFFF'FFFF'FFFF'FFFFuLL, 0x42F0'E1BE'A9EA'3693uLL, 0x0uLL, true, true>;
    constexpr DreadEngine checksumEngine_;

    IDA::API::Message("Searching for references to {:#016x}.\n", versionInfo->Properties.CRC64);
    IDA::API::Function checksumFunction(versionInfo->Properties.CRC64);

    // TODO: Force CRC64 to uint64 (*)(const char*, size_t)
    std::unordered_map<IDA::API::Function, size_t> callers;

    for (ea_t callerRVA : checksumFunction.GetReferencesTo(XREF_FAR)) {
        callerRVA = 0x000000710000D228uLL;

        auto [itr, success] = callers.try_emplace(IDA::API::Function{ callerRVA }, 1);
        if (!success)
            ++itr->second;

        break;
    }

    IDA::API::Message("Found {} references to CRC64.\n", callers.size());
    if (callers.empty())
        return;

    std::stringstream analysisOutput;

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

        IDA::API::Message("Found construction of '{}' at {:#08x}.\n", reflInfo.Name, reflCtor.GetAddress());

        std::stringstream typeOutput;

        constexpr static const std::string_view MetadataTemplate = R"(
template <> struct Metadata<{0}> {
    constexpr static const std::string_view Name = {0};
    constexpr static const uint64_t CRC64 = {1:#016x};

    constexpr static const uint64_t Constructor      = {2:#016x};
    constexpr static const uint64_t CopyConstructor  = {3:#016x};
    constexpr static const uint64_t MoveConstructor  = {4:#016x};
    constexpr static const uint64_t Destructor       = {5:#016x};
    // 0x48 Some sort of copy ctor?
    // 0x50 Some sort of copy ctor?
    constexpr static const uint64_t EqualityComparer = {6:#016x};
    constexpr static const uint64_t GetHashCode      = {7:#016x};
    constexpr static const uint64_t EnumerateMembers = {8:#016x};
};
)";

        typeOutput << std::format(MetadataTemplate, reflInfo.Name, checksumEngine_(reflInfo.Name),
            reflInfo.Properties[0x28],
            reflInfo.Properties[0x30],
            reflInfo.Properties[0x38],
            reflInfo.Properties[0x40],
            // reflInfo.Properties[0x48],
            // reflInfo.Properties[0x50],
            reflInfo.Properties[0x58],
            reflInfo.Properties[0x60],
            reflInfo.Properties[0x70]);

        analysisOutput << typeOutput.rdbuf();

        uint64_t fnGet = reflInfo.Properties[0x68];
    }
}
