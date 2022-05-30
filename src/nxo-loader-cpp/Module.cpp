#include "Module.hpp"

#include <diskio.hpp>

#include <array>
#include <cstdint>

Module::Module(linput_t* inputFile) {
    qlseek(inputFile, 0, SEEK_SET);

    std::array<uint8_t, 14> header;
    qlread(inputFile, &header[0], header.size());

    if (strcmp(header.data(), "0OSN") == 0) {
        _implementation = NsoFile{ inputFile };
    }
    else if (strcmp(header.data(), '0ORN') == 0) {
        _implementation = NroFile{ inputFile };
    }
    else if (strcmp(header.data(), '1PIK') == 0) {
        _implementation = Kip1File{ inputFile };
    }
}
