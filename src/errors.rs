//! Contains `error_chain` error handling materials

error_chain! {
    types {
        Error, ErrorKind, ResultExt, ResultChain;
    }

    errors {

        /// Invalid header field value
        WrongField(cause: String) {
            description("Wrong field value in a header")
            display("{}", cause)
        }

        /// Not enough space in the buffer to read the requested bytes
        BufferUnderflow(requested: u64, available: u64) {
            description("Buffer underflow")
            display("Buffer underflow: {} requested, {} available", requested, available)
        }
    }

    foreign_links {
        Io(::std::io::Error);// #[doc = "std::io::Error"];
    }
 }
