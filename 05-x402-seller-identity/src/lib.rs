//! An x402 seller that asks who a paying agent acts for, with `aethel-auth`.
//!
//! `gate` is the seller's code. `demo` is the scaffolding a real deployment
//! replaces: an in-process facilitator, a fixed clock, and the owner and
//! agent signing their side. See the README.

pub mod demo;
pub mod gate;
