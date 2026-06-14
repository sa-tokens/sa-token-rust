// Author: 金书记
//
//! 封禁检查宏

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Expr, ExprLit, ItemFn, Lit, LitInt, LitStr, MetaNameValue, Token,
};

struct DisableAttr {
    service: LitStr,
    level: LitInt,
}

impl Default for DisableAttr {
    fn default() -> Self {
        Self {
            service: LitStr::new("login", Span::call_site()),
            level: LitInt::new("1", Span::call_site()),
        }
    }
}

impl Parse for DisableAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(DisableAttr::default());
        }

        let mut attr = DisableAttr::default();

        if input.peek(LitStr) {
            attr.service = input.parse()?;
        }

        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let nv: MetaNameValue = input.parse()?;
            if nv.path.is_ident("level") {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Int(i),
                    ..
                }) = nv.value
                {
                    attr.level = i;
                }
            }
        }

        Ok(attr)
    }
}

/// `#[sa_check_disable]` / `#[sa_check_disable("login", level = 1)]`
pub fn sa_check_disable_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let disable_attr = parse_macro_input!(attr as DisableAttr);
    let input = parse_macro_input!(item as ItemFn);

    let service = &disable_attr.service;
    let level = &disable_attr.level;

    let fn_name = &input.sig.ident;
    if input.sig.asyncness.is_none() {
        return syn::Error::new_spanned(fn_name, "Macro requires async function")
            .to_compile_error()
            .into();
    }

    let fn_inputs = &input.sig.inputs;
    let fn_output = &input.sig.output;
    let fn_body = &input.block;
    let fn_attrs = &input.attrs;
    let fn_vis = &input.vis;
    let fn_asyncness = &input.sig.asyncness;
    let fn_generics = &input.sig.generics;
    let fn_where_clause = &input.sig.generics.where_clause;

    let check_code = quote! {
        let __login_id = sa_token_core::StpUtil::get_login_id_as_string().await?;
        sa_token_core::StpUtil::check_disable_level(&__login_id, #service, #level).await?;
    };

    quote! {
        #(#fn_attrs)*
        #[doc(hidden)]
        #fn_vis #fn_asyncness fn #fn_name #fn_generics(#fn_inputs) #fn_output #fn_where_clause {
            #check_code
            #fn_body
        }
    }
    .into()
}
