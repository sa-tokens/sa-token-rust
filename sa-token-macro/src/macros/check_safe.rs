// Author: 金书记
//
//! 二级认证检查宏

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, ItemFn, LitStr};

/// `#[sa_check_safe]` / `#[sa_check_safe("pay")]`
pub fn sa_check_safe_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let service = if attr.is_empty() {
        LitStr::new("", proc_macro2::Span::call_site())
    } else {
        parse_macro_input!(attr as LitStr)
    };

    let input = parse_macro_input!(item as ItemFn);
    expand_async_fn(&input, quote! {
        sa_token_core::StpUtil::check_safe(#service).await?;
    })
}

fn expand_async_fn(input: &ItemFn, check_code: TokenStream2) -> TokenStream {
    let fn_name = &input.sig.ident;
    let fn_inputs = &input.sig.inputs;
    let fn_output = &input.sig.output;
    let fn_body = &input.block;
    let fn_attrs = &input.attrs;
    let fn_vis = &input.vis;
    let fn_asyncness = &input.sig.asyncness;
    let fn_generics = &input.sig.generics;
    let fn_where_clause = &input.sig.generics.where_clause;

    if fn_asyncness.is_none() {
        return syn::Error::new_spanned(fn_name, "Macro requires async function")
            .to_compile_error()
            .into();
    }

    let expanded = quote! {
        #(#fn_attrs)*
        #[doc(hidden)]
        #fn_vis #fn_asyncness fn #fn_name #fn_generics(#fn_inputs) #fn_output #fn_where_clause {
            #check_code
            #fn_body
        }
    };

    expanded.into()
}
