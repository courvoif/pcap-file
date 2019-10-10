use std::io::Read;
use byteorder::{BigEndian, LittleEndian};
use crate::errors::PcapError;
use crate::pcapng::blocks::{Block, ParsedBlock, EnhancedPacketBlock, SectionHeaderBlock, InterfaceDescriptionBlock};
use crate::Endianness;
use crate::peek_reader::PeekReader;

pub struct PcapngReader<R: Read> {
    reader: PeekReader<R>,
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
                reader: PeekReader::new(reader),
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
    type Item = Result<Block<'static>, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {

        match self.reader.is_empty() {
            Ok(is_empty) if is_empty => return None,
            Err(err) => return Some(Err(err.into())),
            _ => {}
        }

        let endianess = self.section.section_header().unwrap().endianness();

        let block_res = if endianess == Endianness::Big {
            Block::from_reader::<_, BigEndian>(&mut self.reader)
        }
        else {
            Block::from_reader::<_, LittleEndian>(&mut self.reader)
        };

        if let Ok(block) = block_res {

            if block.section_header().is_some() {
                self.section = block.clone();
                self.interfaces.clear();
            }
            else if block.interface_description().is_some() {
                self.interfaces.push(block.clone());
            }

            Some(Ok(block))
        }
        else {
            Some(block_res)
        }
    }
}