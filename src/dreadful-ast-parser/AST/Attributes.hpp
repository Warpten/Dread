#pragma once

#include <clang/AST/Attr.h>
#include <clang/Sema/ParsedAttr.h>

namespace AST {
	using namespace clang;

	class IdaAddrAttribute : public InheritableParamAttr {
		uint64_t Value;

	protected:
		IdaAddrAttribute(ASTContext& context, const AttributeCommonInfo& commonInfo, uint64_t value);

		uint64_t getValue() const { return Value; }

	public:
		static IdaAddrAttribute* Create(ASTContext& Ctx, uint64_t annotation, SourceRange Loc = SourceRange{ });

	};

	struct AddressAttrInfo : ParsedAttrInfo {
		AddressAttrInfo();

		bool diagAppertainsToDecl(Sema& s, const ParsedAttr& attr, const Decl* d) const override;

		AttrHandling handleDeclAttribute(Sema& s, Decl* d, const ParsedAttr& attr) const override;
	};
}
