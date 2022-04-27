#include "API.hpp"

#include <sstream>

namespace std {
    template <>
    struct hash<lvar_t> {
        size_t operator () (lvar_t const& left) const noexcept {
            return std::hash<const char*>{}(left.name.c_str());
        }
    };
}

namespace IDA::API {
    cppcoro::generator<ea_t> EnumerateXrefTo(ea_t addr, int flags) {
        xrefblk_t block;
        for (bool next = block.first_to(addr, flags); next; next = block.next_to())
            co_yield block.from;
    }

    cppcoro::generator<std::tuple<ea_t, ea_t>> EnumerateFunctionBounds(ea_t addr) {
        func_t* function = get_func(addr);
        if (function != nullptr) {
            rangeset_t bounds;
            auto end = get_func_ranges(&bounds, function);
            if (end != BADADDR) {
                for (const range_t& elem : bounds)
                    co_yield std::tuple { elem.start_ea, elem.end_ea };
            }
        }
    }

    bool IsFunctionThunk(ea_t addr) {
        func_t* function = get_func(addr);
        if (function == nullptr)
            return false;

        return (function->flags & FUNC_THUNK) != 0;
    }

    std::string GetStringLiteral(ea_t addr, int type) {
        qstring literalStr;
        size_t sz = get_strlit_contents(&literalStr, addr, -1, type, nullptr, 0);
        if (sz == -1 || sz == 0)
            return std::string {};

        return { literalStr.begin() };
    }

    func_t* GetFunction(ea_t addr) {
        return get_func(addr);
    }

    std::unordered_map<lvar_t, std::vector<minsn_t>> TrackStackVariables(func_t* function) {
        struct Visitor : minsn_visitor_t {
            lvars_t& _variables;

            std::unordered_map<lvar_t, std::vector<minsn_t>> _store;

            explicit Visitor(mba_t* microcode)
                : minsn_visitor_t(microcode, nullptr, nullptr), _variables{microcode->vars}
            {
                
            }

            int idaapi visit_minsn() override {
                process(curins, &curins->l);
                process(curins, &curins->r);
                process(curins, &curins->d);

                return false;
            }

            void process(minsn_t* i, mop_t* op) {
                if (op == nullptr)
                    return;

                if (op->t == mop_a)
                    return process(i, op->a);

                if (op->t == mop_p) {
                    process(i, &op->pair->hop);
                    process(i, &op->pair->lop);
                    return;
                }

                if (op->t == mop_l) {
                    lvar_t& key = _variables[op->l->idx];

                    auto it = _store.find(key);
                    if (it == _store.end()) {
                        _store[key] = std::vector<minsn_t> { *i };
                    } else {
                        it->second.push_back(*i);
                    }
                }
            }
        };

        std::unique_ptr<mba_t> microcode = GenerateMicrocode(function->start_ea);
        Visitor visitor { microcode.get() };

        if (microcode != nullptr)
            microcode->for_all_insns(visitor);

        
        microcode->for_all_insns(visitor);

        return visitor._store;
    }

    std::unique_ptr<mba_t> GenerateMicrocode(ea_t func) {
        func_t* function = GetFunction(func);
        if (function == nullptr)
            return nullptr;

        mba_ranges_t microcodeRanges;
        microcodeRanges.pfn = function;

        hexrays_failure_t failure;
        mlist_t registersList;

        mba_t* microcode = gen_microcode(microcodeRanges, &failure, &registersList, DECOMP_NO_CACHE | DECOMP_NO_WAIT, MMAT_LVARS);
        if (failure.code != MERR_OK)
            return nullptr;

        return std::unique_ptr<mba_t>{microcode};
    }

    std::string ToString(qstring const& qstr) {
        return { qstr.begin() };
    }
}