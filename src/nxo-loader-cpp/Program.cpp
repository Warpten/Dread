#pragma warning(push)
#pragma warning(disable : 4267 4244)
#define USE_STANDARD_FILE_FUNCTIONS
#include <ida.hpp>
#include <idp.hpp> 
#include <loader.hpp>
#include <typeinf.hpp>
#pragma warning(pop)

#include <MIO/MIO.hpp>

// Plugin implementation ---
namespace Plugin {
    int idaapi AcceptFile(qstring* fileFormatName, qstring* processor, linput_t* inputFile, const char* fileName);
    void idaapi LoadFile(linput_t* inputFile, ushort flags, const char* fileName);
    int idaapi SaveFile(FILE* file, const char* fileName);
    int idaapi MoveSegment(ea_t from, ea_t to, asize_t size, const char* fileName);
    int idaapi ProcessArchive(qstring* temFile, linput_t* input, qstring* moduleName, ushort* flags, const char* fileName, const char* defaultMember, qstring* errorBuffer);
};

extern loader_t LOADER;

loader_t LOADER = {
	.version = IDP_INTERFACE_VERSION,
	.flags = 0,
	.accept_file = Plugin::AcceptFile,
	.load_file = Plugin::LoadFile,
	.save_file = Plugin::SaveFile,
	.move_segm = Plugin::MoveSegment,
	.process_archive = Plugin::ProcessArchive
};

namespace Plugin {
	void idaapi LoadFile(linput_t* inputFile, ushort flags, const char* fileName) {
		set_processor_type("arm", static_cast<setproc_level_t>(SETPROC_LOADER_NON_FATAL | SETPROC_LOADER));

		Module module_{ inputFile };

		setinf(INF_LFLAGS, getinf(INF_LFLAGS) | (module_.Is64Bits() ? LFLG_64BIT : LFLG_PC_FLAT));
		setinf(INF_DEMNAMES, DEMNAM_GCC3);
		set_compiler_id(COMP_GNU);
		add_til(module_.Is64Bits() ? "gnulnx_arm64" : "gnulnx_arm");

		size_t loadBase = module_.Is64Bits() ? 0x7100000000uLL : 0x60000000uLL;
	}
}