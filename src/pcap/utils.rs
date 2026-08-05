/// Timestamp resolution of the pcap
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PcapTsResolution {
    /// Microsecond resolution
    MicroSecond,
    /// Nanosecond resolution
    NanoSecond,
}
