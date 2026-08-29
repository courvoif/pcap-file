//! Block types defined by the pcapng format.
//!
//! [`Block`] represents any decoded pcapng block. Individual modules expose
//! the structure and options for each supported block type. Use [`RawBlock`]
//! when a block body must remain unparsed, such as when handling malformed or
//! unsupported data.
//!
//! Shared block types and parsing traits are available in [`block_common`],
//! common options in [`opt_common`], and vendor-defined blocks and options in
//! [`custom`].

pub mod block_common;
pub mod custom;
pub mod enhanced_packet;
pub mod interface_description;
pub mod interface_statistics;
pub mod name_resolution;
pub mod opt_common;
pub mod packet;
pub mod section_header;
pub mod simple_packet;
pub mod systemd_journal_export;
pub mod unknown;

pub use block_common::*;
