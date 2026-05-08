/// Timestamp resolution of the pcap
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TsResolution {
    /// Microsecond resolution
    MicroSecond,
    /// Nanosecond resolution
    NanoSecond,
}