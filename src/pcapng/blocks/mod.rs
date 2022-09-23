//! Contains the PcapNg blocks.


pub mod interface_description;
pub mod section_header;
pub mod enhanced_packet;
pub mod simple_packet;
pub(crate) mod block_common;
pub(crate) mod opt_common;
pub mod name_resolution;
pub mod interface_statistics;
pub mod systemd_journal_export;
pub mod packet;
pub mod unknown;

pub use block_common::*;