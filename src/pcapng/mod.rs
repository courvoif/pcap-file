use std::io::Read;
use byteorder::{ByteOrder, BigEndian};
use crate::errors::{ResultParsing, PcapError};
use crate::pcapng::blocks::{Block, ParsedBlock};

mod blocks;

struct PcapngReader<R: Read> {
    reader: R,
    section: Block<'static>,
    interfaces: Vec<Block<'static>>
}

impl<R: Read> PcapngReader<R> {

    pub fn new(reader: R) -> Result<PcapngReader<R>, PcapError> {

        let section = Block::from_reader::<_, BigEndian>(reader)?;
        match section.parsed {
            ParsedBlock::SectionHeader(_) => {},
            _ => return Err(PcapError::InvalidField("SectionHeader missing"))
        }

        PcapngReader {
            reader,
            section,
            interfaces: vec![]
        }
    }
}

impl<R> Iterator for PcapngReader<R> {
    type Item = Block<'static>;

    fn next(&mut self) -> Option<Self::Item> {

        let mut block = Block::from_reader::<_, BigEndian>(reader)?;
        while block.is_interface_description() {
            self.interfaces.push(block);
            block = Block::from_reader::<_, BigEndian>(reader)?;
        }

        block

    }
}