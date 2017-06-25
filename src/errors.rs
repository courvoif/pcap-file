//! Contains `error_chain` error handling materials

error_chain! {
    types {
        Error, ErrorKind, ResultExt, ResultChain;
    }

    errors {

        /// Invalid magic number for the global Pcap header
        BadMagicNumber(magic: u32) {
            description("Bad magic number")
            display("Bad magic number : {:X}", magic)
        }

        /// Bad header length value
        BadLength(length: u32) {
            description("Bad length")
            display("Bad length : {}", length)
        }

        /// Not enough space in the buffer to read the requested bytes
        BufferUnderflow(requested: u64, available: u64) {
            description("Buffer underflow")
            display("Buffer underflow: {} requested, {} available", requested, available)
        }
    }

    foreign_links {
        Io(::std::io::Error) #[doc = "::std::io::Error"];
    }
 }
