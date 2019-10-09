use std::io::Read;
use byteorder::{BigEndian, LittleEndian};
use crate::errors::PcapError;
use crate::pcapng::blocks::{Block, ParsedBlock, EnhancedPacketBlock, SectionHeaderBlock, InterfaceDescriptionBlock};
use crate::Endianness;

pub struct PcapngReader<R: Read> {
    reader: R,
    section: Block<'static>,
    interfaces: Vec<Block<'static>>
}

impl<R: Read> PcapngReader<R> {

    pub fn new(mut reader: R) -> Result<PcapngReader<R>, PcapError> {

        let section = Block::from_reader::<_, BigEndian>(&mut reader)?;
        match section.parsed {
            ParsedBlock::SectionHeader(_) => {},
            _ => return Err(PcapError::InvalidField("SectionHeader missing"))
        }

        Ok(
            PcapngReader {
                reader,
                section,
                interfaces: vec![]
            }
        )
    }

    pub fn section(&self) -> &SectionHeaderBlock {
        self.section.section_header().unwrap()
    }

    pub fn interfaces(&self) -> &[Block] {
        &self.interfaces[..]
    }

    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces.get(packet.interface_id as usize).map(|block| block.interface_description().unwrap())
    }
}

impl<R: Read> Iterator for PcapngReader<R> {
    type Item = Block<'static>;

    fn next(&mut self) -> Option<Self::Item> {

        let endianess = self.section.section_header().unwrap().endianness();

        let block = if endianess == Endianness::Big {
            Block::from_reader::<_, BigEndian>(&mut self.reader).ok()?
        }
        else {
            Block::from_reader::<_, LittleEndian>(&mut self.reader).ok()?
        };

        if block.interface_description().is_some() {
            self.interfaces.push(block.clone());
        }

        Some(block)
    }
}