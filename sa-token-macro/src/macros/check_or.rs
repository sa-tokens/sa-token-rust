// Author: 金书记
//
//! 组合鉴权 OR 宏（任一子检查通过即可）

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, ItemFn, LitInt, LitStr, Token,
};

struct OrCheck {
    kind: syn::Ident,
    value: LitStr,
    level: Option<LitInt>,
}

struct OrAttr {
    checks: Vec<OrCheck>,
}

impl Parse for OrAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut checks = Vec::new();

        while !input.is_empty() {
            let kind: syn::Ident = input.parse()?;

            if kind == "login" {
                checks.push(OrCheck {
                    kind,
                    value: LitStr::new("", Span::call_site()),
                    level: None,
                });
            } else {
                input.parse::<Token![=]>()?;

                if kind == "disable" {
                    let service: LitStr = input.parse()?;
                    let mut level = None;
                    if input.peek(Token![,]) {
                        let fork = input.fork();
                        fork.parse::<Token![,]>()?;
                        let level_kw: syn::Ident = fork.parse()?;
                        if level_kw == "level" {
                            input.parse::<Token![,]>()?;
                            input.parse::<syn::Ident>()?; // level
                            input.parse::<Token![=]>()?;
                            level = Some(input.parse()?);
                        }
                    }
                    checks.push(OrCheck {
                        kind,
                        value: service,
                        level,
                    });
                } else {
                    let value: LitStr = input.parse()?;
                    checks.push(OrCheck {
                        kind,
                        value,
                        level: None,
                    });
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        if checks.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                "At least one check is required, e.g. permission = \"a\", role = \"admin\"",
            ));
        }

        Ok(OrAttr { checks })
    }
}

/// `#[sa_check_or(permission = "a", role = "admin")]`
pub fn sa_check_or_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let or_attr = parse_macro_input!(attr as OrAttr);
    let input = parse_macro_input!(item as ItemFn);

    let fn_name = &input.sig.ident;
    if input.sig.asyncness.is_none() {
        return syn::Error::new_spanned(fn_name, "Macro requires async function")
            .to_compile_error()
            .into();
    }

    let mut branches: Vec<TokenStream2> = Vec::new();

    for check in &or_attr.checks {
        let branch = match check.kind.to_string().as_str() {
            "login" => quote! {
                if sa_token_core::StpUtil::check_login_current().is_ok() {
                    __sa_or_passed = true;
                }
            },
            "permission" => {
                let perm = &check.value;
                quote! {
                    {
                        if let Ok(__login_id) = sa_token_core::StpUtil::get_login_id_as_string().await {
                            if sa_token_core::StpUtil::has_permission(&__login_id, #perm).await {
                                __sa_or_passed = true;
                            }
                        }
                    }
                }
            }
            "role" => {
                let role = &check.value;
                quote! {
                    {
                        if let Ok(__login_id) = sa_token_core::StpUtil::get_login_id_as_string().await {
                            if sa_token_core::StpUtil::has_role(&__login_id, #role).await {
                                __sa_or_passed = true;
                            }
                        }
                    }
                }
            }
            "safe" => {
                let service = &check.value;
                quote! {
                    if sa_token_core::StpUtil::check_safe(#service).await.is_ok() {
                        __sa_or_passed = true;
                    }
                }
            }
            "disable" => {
                let service = &check.value;
                let level = check.level.as_ref().map(|l| quote! { #l }).unwrap_or_else(|| {
                    quote! { sa_token_core::MIN_DISABLE_LEVEL }
                });
                quote! {
                    {
                        if let Ok(__login_id) = sa_token_core::StpUtil::get_login_id_as_string().await {
                            if sa_token_core::StpUtil::check_disable_level(&__login_id, #service, #level)
                                .await
                                .is_ok()
                            {
                                __sa_or_passed = true;
                            }
                        }
                    }
                }
            }
            other => {
                return syn::Error::new_spanned(
                    &check.kind,
                    format!(
                        "Unsupported check kind '{}', use login|permission|role|safe|disable",
                        other
                    ),
                )
                .to_compile_error()
                .into();
            }
        };
        branches.push(branch);
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
        let mut __sa_or_passed = false;
        #(#branches)*
        if !__sa_or_passed {
            return Err(sa_token_core::SaTokenError::PermissionDenied.into());
        }
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
