//! Contains the Pcap parser, reader and writer

mod header;
mod packet;
mod parser;
mod reader;
mod writer;

pub use header::*;
pub use packet::*;
pub use parser::*;
pub use reader::*;
pub use writer::*;

/// The tcpdump group has changed max snapshot length from 65535 to 262144 and used it as default.
/// see [code](https://github.com/the-tcpdump-group/tcpdump/blob/87c90012f079200b7d49979164e8e9ed89d93d9d/netdissect.h#L342C9-L342C25)
/// default snapshot length 262144 = 2^18
const MAXIMUM_SNAPLEN: u32 = 262144;
