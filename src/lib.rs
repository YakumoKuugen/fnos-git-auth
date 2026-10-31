//! fnos-git-auth 的 Rust 实现。
//!
//! 通过 fnOS 的 WebSocket 协议获取 entry-token，并写入 Git 全局
//! `http.<url>.extraHeader`，从而免密访问 fnOS NAS 上的 Git 仓库。

pub mod auth;
pub mod cli;
pub mod client;
pub mod config;
pub mod credentials;
pub mod crypto;
pub mod diagnostic;
pub mod git;
pub mod hooks;
pub mod paths;
pub mod schedule;
pub mod update;
pub mod util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
