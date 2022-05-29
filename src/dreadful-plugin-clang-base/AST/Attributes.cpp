#include "Attributes.hpp"

#include <clang/Sema/Sema.h>
#include <clang/Sema/SemaDiagnostic.h>

namespace AST {
	using namespace clang;

	IdaAddrAttribute::IdaAddrAttribute(ASTContext& context, const AttributeCommonInfo& commonInfo, uint64_t value)
		: InheritableParamAttr(context, commonInfo, attr::Kind::Annotate, false, false), Value(value)
	{

	}

	/* static */ IdaAddrAttribute* IdaAddrAttribute::Create(ASTContext& ctx, uint64_t annotation, SourceRange loc) 
	{
		AttributeCommonInfo commonInfo{ loc, clang::AttributeCommonInfo::Kind::NoSemaHandlerAttribute,
			clang::AttributeCommonInfo::Syntax::AS_CXX11 };
			
		auto* A = new (ctx) IdaAddrAttribute(ctx, commonInfo, annotation);
		return A;
	}

	AddressAttrInfo::AddressAttrInfo() : ParsedAttrInfo() {
		OptArgs = 0;
		NumArgs = 1;

		static constexpr Spelling spellings[] = {
			Spelling { ParsedAttr::AS_CXX11, "ida::addr" }
		};

		Spellings = spellings;
	}

	bool AddressAttrInfo::diagAppertainsToDecl(Sema& s, const ParsedAttr& attr, const Decl* d) const {
		// This attribute appertains to function or variable declarations.
		if (!isa<FunctionDecl>(d) && !isa<VarDecl>(d)) {
			s.Diag(attr.getLoc(), diag::warn_attribute_wrong_decl_type_str) << attr << "functions or variables";
			return false;
		}

		return true;
	}

	auto AddressAttrInfo::handleDeclAttribute(Sema& s, Decl* d, const ParsedAttr& attr) const -> AttrHandling {
		// TODO: Check again here?

		// 1. First argument is the offset in the IDB
		if (attr.getNumArgs() != 1) {
			unsigned ID = s.getDiagnostics().getCustomDiagID(
				DiagnosticsEngine::Error,
				"'ida::addr' attribute only accepts one argument");
			s.Diag(attr.getLoc(), ID);
			return AttributeNotApplied;
		}

		auto firstArg = dyn_cast<IntegerLiteral>(attr.getArgAsExpr(0));
		if (!firstArg) {
			unsigned ID = s.getDiagnostics().getCustomDiagID(
				DiagnosticsEngine::Error, "first argument to the 'ida::addr' "
				"attribute must be an integer literal");
			s.Diag(attr.getLoc(), ID);
			return AttributeNotApplied;
		}

		uint64_t value = firstArg->getValue().getZExtValue();

		d->addAttr(IdaAddrAttribute::Create(s.Context, value, attr.getLoc()));
		return AttributeApplied;
	}
}

static clang::ParsedAttrInfoRegistry::Add<AST::AddressAttrInfo> X_("ida::addr",
	"Annotates functions and variable declarations with their offset in the binary.");
