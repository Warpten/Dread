#include "Analyzers.hpp"

#include "IDA/API/API.hpp"

#include <array>
#include <optional>
#include <span>
#include <sstream>
#include <iomanip>
#include <utility>
#include <variant>

auto FindStorage(minsn_t* instruction, Analysis::Engine& engine) -> Analysis::Meta*
{
    func_t* function = IDA::API::GetFunction(instruction->ea);
    if (!function)
        return nullptr;

    return std::addressof(engine.FindEntry(function->start_ea));
}

ea_t GetStorageKey(minsn_t* instruction, Analysis::Engine& engine)
{
    func_t* function = IDA::API::GetFunction(instruction->ea);
    if (!function)
        throw std::runtime_error("Function not found at address");

    return function->start_ea;
}

void Analysis::Meta::Process(Analysis::Engine& pool) {
    if (CStrId.Value.empty())
        return;

    func_t* self = IDA::API::GetFunction(GetReflInfo.Base);

    // Also look for calls to CRC64 that make sense
    InstructionVisitor<Analysis::Engine, CRC64>::Run(GetReflInfo.Microcode.get(), pool, *this);

    // At this point, we know we are in a GetReflInfo function
    // (because the initial analysis looks for functions that acquire mutexes and call CStrId)
    // From there, two things can happen:
    // 1. Construction of the reflexpr object is inlined into a global variable.
    //    This is easily checked for by looking at the pseudocode and searching
    //    for sequential writes to some global addresses. Namely, there will be
    //    vtables assignments, which we can use to discriminate.
    //    Addentum from the future: Can also be checked for by looking at Type.
    // 2. Construction of the reflexpr object happens by calling into its static
    //    initializer. This usually happens if the type inherits a base type,
    //    in which case we will be calling the base type's GetReflInfo method ...
    //    which should be available in the analysis pool. Therefore this check
    //    is trivial to execute as well.
    // We rely on the vtable assignment check, since that is faster to search for.
    
    // Search for vtable assignments
    InstructionVisitor<
        Analysis::Engine,
        VtableAssignment
    >::Run(GetReflInfo.Microcode.get(), pool, *this);
    
    // If we haven't found the static reflexpr instance yet, look for a ctor call.
    // The instance will be its first argument.
    if (Base == 0) {
        InstructionVisitor<
            Analysis::Engine,
            ConstructorCall
        >::Run(GetReflInfo.Microcode.get(), pool, *this);

        // Still not found, opt out
        if (Base == 0)
            return;

        // Non-inlined ctor, rerun CRC64 on it to get the actual reflexpr object type
        if (Initialize.Base != 0)
            InstructionVisitor<Analysis::Engine, CRC64>::Run(Initialize.Microcode.get(), pool, *this);
    }

    // Prepare mangled names for all methods
    Mangler::Result mangledNames = Mangler{}.Execute(CStrId.Value, Type);

    bool validState = (Base != 0) != ReflObject.Register.has_value();
    assert(validState && "Invalid state for analysis");

    if (Parent.Variable != 0) {
        // There is a call to a parent's GetReflInfo; 
        //   The ConstructorCall analyzer saved the offset of the relevant
        //   stack variable in ParentProvider.
        // TODO: find the function - filtering by variable index in stk
        // Then, just save the function's address.
    
        struct ParentAssignment final {
            using Filter = IDA::API::MemoryXferInstruction<
                IDA::API::OperandFilter<mop_d>,
                IDA::API::OperandFilter<mop_l>
            >;
    
            explicit ParentAssignment(int variableIndex) : _variableIndex(variableIndex) { }
    
            bool TryProcess(minsn_t* instruction, Analysis::Engine& engine) {
                return Filter::TryProcess(instruction, [&instruction, &engine, this](minsn_t* instruction, lvar_ref_t* var) -> bool {
                    auto&& functionInfo = FindStorage(instruction, engine);
                    if (!functionInfo)
                        return false;
    
                    if (var->idx != this->_variableIndex)
                        return false;
    
                    // https://i.imgur.com/kbppXhg.png
                    if (instruction->opcode != mcode_t::m_call
                        || instruction->l.t != mop_v
                        || instruction->d.t != mop_f
                        || instruction->d.f->args.size() != 0)
                        return false;
    
                    functionInfo->Parent.GetReflInfo = instruction->l.g;
                    return true;
                });
            }
    
        private:
            int _variableIndex = 0;
        };
    
        InstructionVisitor<Analysis::Engine, ParentAssignment>::Run(GetReflInfo.Microcode.get(), 
            pool, *this, ParentAssignment {Parent.Variable});

        assert(Parent.Variable != 0);
    }

    // Constructor found, name it!
    // if (ReflObject.Constructor != 0) {
    //     IDA::API::LogMessage(R"(set_name(0x{:x}, "{}");)" "\n", ReflObject.Constructor, mangledNames.Initialize);
    // }

    IDA::API::LogMessage(R"(set_name(0x{:x}, "{}");)" "\n", GetReflInfo.Base, mangledNames.Get);
    IDA::API::LogMessage(R"(set_name(0x{:x}, "{}");)" "\n", Base, mangledNames.ObjectName);
    IDA::API::LogMessage(R"(set_name(0x{:x}, "{}");)" "\n", Initialize.Base,
        Initialize.ExtraParameters.size() == 2 ? mangledNames.Initialize : mangledNames.InitializeSimple);
}

/* static */ bool base::global::CStrId::CStrId::TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept {
    using Base = IDA::API::FunctionCallInstruction<
        Address,
        Filters::Pointer<false>, // Pointer to local variable
        Filters::GlobalPointer, // Pointer to .data
        Filters::ExpectedValueOperand<1uLL>
    >;

    return Base::TryProcess(instruction, [&storage](std::variant<ea_t, lvar_ref_t*> instance, ea_t stringAddress, size_t /* one */) -> bool {
        // Get the string value and assign it to this function.
        storage.CStrId.Value = IDA::API::GetStringLiteral(stringAddress, STRTYPE_C);

        std::visit([&](auto&& value) {
            using value_type = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<value_type, lvar_ref_t*>) {
                storage.CStrId.Variable = value->idx;
            } else if constexpr (std::is_same_v<value_type, ea_t>) {
                // Do we need to do anything?
            }
        }, instance);

        IDA::API::LogMessage("(Info) Found construction of CStrId (\"{}\")\n", storage.CStrId.Value);
        return true;
    });
}

bool CRC64::TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept {
    using Base = IDA::API::FunctionCallInstruction<
        Address,
        Filters::GlobalPointer,
        Filters::IntegerOperand
    >;

    return Base::TryProcess(instruction, [&storage](ea_t stringAddress, size_t length) {
        std::string checksumName = IDA::API::GetStringLiteral(stringAddress, STRTYPE_C);
        if (checksumName.size() != length)
            return false;

        static constexpr const struct {
            std::string_view Name;
            Analyzers::ReflectiveType Type;
        } types[] = {
            { "base::reflection::CClass", Analyzers::ReflectiveType::CClass },
            { "base::reflection::CType", Analyzers::ReflectiveType::CType },
            { "base::reflection::CEnumType", Analyzers::ReflectiveType::CEnumType },
            { "base::reflection::CPointerType", Analyzers::ReflectiveType::CPointerType },
            { "base::reflection::CCollectionType", Analyzers::ReflectiveType::CCollectionType },
            { "base::reflection::CEnumConstRef", Analyzers::ReflectiveType::CEnumConstRef },
            { "base::reflection::CFlagsetConstRef", Analyzers::ReflectiveType::CFlagsetConstRef },
            { "base::reflection::CFunction", Analyzers::ReflectiveType::CFunction },
            // This is a hack
            { "base::reflection::CFunction const*", Analyzers::ReflectiveType::CFunction_ConstPtr },
        };

        for (auto&& kv : types) {
            if (checksumName != kv.Name)
                continue;

            storage.Type = kv.Type;
            IDA::API::LogMessage("(Info) Reflection data is represented by a {}.", kv.Name);
            return true;
        }

        return true;
    });
}

namespace vtables {
    namespace base::reflection {
        constexpr static const ea_t CType  = 0x00000071019C5550uLL;
        constexpr static const ea_t CClass = 0x00000071019C52F0uLL;
    }
}

/* static */ bool VtableAssignment::TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept {
    using Local = IDA::API::Instruction<
        mcode_t::m_stx,
        Filters::GlobalPointer,
        IDA::API::OperandFilter<mop_r>,
        IDA::API::OperandFilter<mop_l>
    >;
    using LocalProperty = IDA::API::Instruction<
        mcode_t::m_stx,
        IDA::API::OperandFilter<mop_n, mop_a, mop_l>,
        IDA::API::OperandFilter<mop_r>,
        IDA::API::OperandFilter<mop_d>
    >;
    using Global = IDA::API::MemoryXferInstruction<
        Filters::GlobalPointer,
        Filters::GlobalPointer
    >;

    static auto handler = [](Analysis::Meta& functionInfo, ea_t offset, ea_t value) {
        // TODO:
        // functionInfo->ReflObject.Properties[offset] = value;
        return true;
    };

    return Local::TryProcess(instruction, [&storage](ea_t value, mreg_t reg, lvar_ref_t* var) {
        if (storage.ReflObject.Register.has_value()) {
            if (reg != storage.ReflObject.Register.value())
                return false;
        }

        switch (value) {
            case vtables::base::reflection::CType:
            case vtables::base::reflection::CClass:
                // Store the register since this is a local variable.
                // We will retrieve the actual instance from the microcode of the caller.
                storage.ReflObject.Register = reg;
                // Register the vtable nonetheless.
                return handler(storage, 0, value);
        }

        return false;
    }) || LocalProperty::TryProcess(instruction, [&storage](std::variant<mnumber_t*, mop_addr_t*, lvar_ref_t*> value, mreg_t reg, minsn_t* subins) {
        if (storage.ReflObject.Register.has_value()) {
            if (reg != storage.ReflObject.Register.value())
                return false;
        }

        // sub-instruction is an add on a register
        if (subins->opcode != mcode_t::m_add || subins->r.t != mop_n) 
            return false;

        return std::visit([&](auto&& value) {
            using value_type = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<value_type, mnumber_t*>) {
                return handler(storage, subins->r.t, value->value);
            } else if constexpr (std::is_same_v<value_type, mop_addr_t*>) {
                // Operand is a pointer to ...
                switch (value->t)
                {
                    case mop_v: // ... a global variable or function
                        return handler(storage, subins->r.t, value->g);
                    default: // ... Fuck if I know
                        return false;
                }
            } else if constexpr (std::is_same_v<lvar_ref_t*, value_type>) {
                // Value assigned from a local variable
                // !NYI
                return false;
            }
        }, value);
    }) || Global::TryProcess(instruction, [&storage](ea_t value, ea_t globalBase) {
        switch (value) {
            case vtables::base::reflection::CType:
            case vtables::base::reflection::CClass:
                storage.Base = globalBase;
                break;
        }

        if (storage.Base != 0)
            return handler(storage, globalBase - storage.Base, value);

        return false;
    });
}

/* static */ bool ConstructorCall::TryProcess(minsn_t* instruction, Analysis::Engine& engine, Analysis::Meta& storage) noexcept {
    // General purpose handler for most reflexpr object ctors.
    using Complex = IDA::API::AnyFunctionCallInstruction<
        Filters::GlobalPointer, // &unk_xxxx
        Filters::LocalPointer, // a2
        IDA::API::OperandFilter<mop_l, mop_n>, // pointer to parent type (or nullptr) through variable
        Filters::FunctionPointer,
        Filters::FunctionPointer
    >;

    // Handler for constructors to simple types that don't have lambda/parent arguments
    // See eg meta::string.
    using Simple = IDA::API::AnyFunctionCallInstruction<
        Filters::GlobalPointer, // &unk_xxx
        Filters::LocalPointer // a2
    >;

    return Complex::TryProcess(instruction, [&storage, &instruction](ea_t instance, lvar_ref_t* name, std::variant<lvar_ref_t*, mnumber_t*> parent, ea_t fn0, ea_t fn1) {
        storage.Base = instance;

        storage.Initialize.Base = Complex::GetCallee(instruction);
        storage.Initialize.ExtraParameters.emplace_back(fn0);
        storage.Initialize.ExtraParameters.emplace_back(fn1);
        storage.Initialize.Microcode = IDA::API::GenerateMicrocode(storage.Initialize.Base);

        return std::visit([&](auto&& value) {
            using value_type = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<value_type, lvar_ref_t*>) {
                storage.Parent.Variable = value->off;
                return true;
            } else if constexpr (std::is_same_v<value_type, mnumber_t*>) {
                // Assume nullptr
                return value->value == 0uLL;
            }
        }, parent);
    }) || Simple::TryProcess(instruction, [&instruction, &storage](ea_t instance, lvar_ref_t* name) {
        storage.Base = instance;

        storage.Initialize.Base = Simple::GetCallee(instruction);
        storage.Initialize.Microcode = IDA::API::GenerateMicrocode(storage.Initialize.Base);
        return true;
    });
}