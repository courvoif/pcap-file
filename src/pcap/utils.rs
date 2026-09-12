/// Timestamp resolution used by a pcap file.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PcapTsResolution {
    /// Microsecond resolution.
    Microsecond,
    /// Nanosecond resolution.
    Nanosecond,
}
