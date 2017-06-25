//! Contains `error_chain` error handling materials

error_chain! {
    types {
        Error, ErrorKind, ResultExt, ResultChain;
    }

    errors {
        BadMagicNumber(magic: u32) {
            description("Bad magic number")
            display("Bad magic number : {:X}", magic)
        }
        BadLength(length: u32) {
            description("Bad length")
            display("Bad length : {}", length)
        }
        BufferUnderflow(requested: u64, available: u64) {
            description("Buffer underflow")
            display("Buffer underflow: {} requested, {} available", requested, available)
        }
    }

    foreign_links {
        Io(::std::io::Error);
    }
 }
