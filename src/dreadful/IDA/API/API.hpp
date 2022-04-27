#ifndef IDA_API_hpp__
#define IDA_API_hpp__

#pragma warning( disable : 4267 4244 )

#include <hexrays.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#pragma warning( default : 4267 4244 )

#include <format>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "utils/Generator.hpp"

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
# define NOMINMAX
#endif
#include <Windows.h>

namespace IDA::API {
    cppcoro::generator<ea_t> EnumerateXrefTo(ea_t addr, int flags);

    cppcoro::generator<std::tuple<ea_t, ea_t>> EnumerateFunctionBounds(ea_t addr);

    bool IsFunctionThunk(ea_t addr);

    std::string GetStringLiteral(ea_t addr, int type);

    func_t* GetFunction(ea_t addr);

    // std::vector<std::unique_ptr<func_t>> GetCalledFunctions(func_t* function);
    std::unordered_map<lvar_t, std::vector<minsn_t>> TrackStackVariables(func_t* function);

    template <typename... Ts>
    void LogMessage(std::string_view fmt, Ts&&... args) {
        std::string formatted = std::format(fmt, std::forward<Ts&&>(args)...);
        msg(formatted.c_str());
#if _DEBUG
        OutputDebugStringA(formatted.c_str());
#endif
    }

    std::string ToString(qstring const& qstr);

    std::unique_ptr<mba_t> GenerateMicrocode(ea_t func);

}

#endif // IDA_API_hpp__
