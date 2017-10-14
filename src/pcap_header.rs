//! This module contains the `PcapHeader` struct which represents a global pcap header.

use std::io::Read;

use byteorder::*;

use errors::*;

/// Struct that represents the global Pcap header of a Pcap file
#[derive(Copy, Clone, Debug)]
pub struct PcapHeader {

    /// Magic number
    pub magic_number: u32,

    /// Major version number
    pub version_major: u16,

    /// Minor version number
    pub version_minor: u16,

    /// GMT to local timezone correction, should always be 0
    pub ts_correction: i32,

    /// Timestamp accuracy, should always be 0
    pub ts_accuracy: u32,

    /// Max length of captured packet, typically 65535
    pub snaplen: u32,

    /// DataLink type (first layer in the packet (u32))
    pub datalink: DataLink
}


impl PcapHeader {

    /// Creates a new `PcapHeader` with the following parameters:
    ///
    /// ```rust,ignore
    /// PcapHeader {
    ///
    ///     magic_number : 0xa1b2c3d4,
    ///     version_major : 2,
    ///     version_minor : 4,
    ///     ts_correction : 0,
    ///     ts_accuracy : 0,
    ///     snaplen : 65535,
    ///     datalink : datalink
    /// };
    /// ```
    pub fn with_datalink(datalink: DataLink) -> PcapHeader {

        PcapHeader {
            magic_number: 0xA1B2C3D4,
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: datalink
        }
    }

    /// Parses a `Reader` and creates a new `PcapHeader` from it if possible
    pub fn from_reader<R: Read>(reader: &mut R) -> ResultChain<PcapHeader> {

        let magic_number = reader.read_u32::<BigEndian>()?;

        match magic_number {

            0xa1b2c3d4 | 0xa1b23c4d => return init_pcap_header::<_, BigEndian>(reader, magic_number),
            0xd4c3b2a1 | 0x4d3cb2a1 => return init_pcap_header::<_, LittleEndian>(reader, magic_number),
            _ => bail!(ErrorKind::WrongField(format!("Wrong PacketHeader.magic_number: {}", magic_number)))
        };

        // Inner function used for the initialisation of the `PcapHeader`
        fn init_pcap_header<R: Read, B: ByteOrder>(reader: &mut R, magic_number:u32) -> Result<PcapHeader, Error> {

            Ok(
                PcapHeader {

                    magic_number : magic_number,
                    version_major : reader.read_u16::<B>()?,
                    version_minor : reader.read_u16::<B>()?,
                    ts_correction : reader.read_i32::<B>()?,
                    ts_accuracy : reader.read_u32::<B>()?,
                    snaplen : reader.read_u32::<B>()?,
                    datalink : DataLink::from(reader.read_u32::<B>()?)
                }
            )
        }
    }

    /// Convert a `PcapHeader` to a `Vec<u8>`.
    pub fn to_array<B: ByteOrder>(&self) -> ResultChain<Vec<u8>> {

        let mut out = Vec::with_capacity(24);

        //The magic number is always read in BigEndian so it's always written in BigEndian too
        out.write_u32::<BigEndian>(self.magic_number)?;
        out.write_u16::<B>(self.version_major)?;
        out.write_u16::<B>(self.version_minor)?;
        out.write_i32::<B>(self.ts_correction)?;
        out.write_u32::<B>(self.ts_accuracy)?;
        out.write_u32::<B>(self.snaplen)?;
        out.write_u32::<B>(self.datalink.into())?;

        Ok(out)
    }

    /// Return the endianness of the global header
    ///
    /// # Panics
    ///
    /// Panics if the magic number is invalid
    pub fn endianness(&self) -> Endianness {

        match self.magic_number {

            0xa1b2c3d4 | 0xa1b23c4d => Endianness::Big,
            0xd4c3b2a1 | 0x4d3cb2a1 => Endianness::Little,
            _ => unreachable!("Wrong magic number, can't get the header's endianness")
        }
    }

    /// Return the timestamp resolution of the global header
    ///
    /// # Panics
    ///
    /// Panics if the magic number is invalid
    pub fn ts_resolution(&self) -> TsResolution {

        match self.magic_number {

            0xa1b2c3d4 | 0xd4c3b2a1 => TsResolution::MicroSecond,
            0xa1b23c4d | 0x4d3cb2a1 => TsResolution::NanoSecond,
            _ => unreachable!("Wrong magic number, can't get the header's timestamp resolution")
        }
    }
}

/// Represents the endianness of the global header
#[derive(Copy, Clone, Debug)]
pub enum Endianness {
    Big,
    Little
}

/// Represents each possible timestamp resolution of the global header
#[derive(Copy, Clone, Debug)]
pub enum TsResolution {
    MicroSecond,
    NanoSecond
}

/// Represents each possible Pcap datalink
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub enum DataLink {

    NULL,
    ETHERNET,
    AX25,
    IEEE802_5,
    ARCNET_BSD,
    SLIP,
    PPP,
    FDDI,
    PPP_HDLC,
    PPP_ETHER,
    ATM_RFC1483,
    RAW,
    C_HDLC,
    IEEE802_11,
    FRELAY,
    LOOP,
    LINUX_SLL,
    LTALK,
    PFLOG,
    IEEE802_11_PRISM,
    IP_OVER_FC,
    SUNATM,
    IEEE802_11_RADIOTAP,
    ARCNET_LINUX,
    APPLE_IP_OVER_IEEE1394,
    MTP2_WITH_PHDR,
    MTP2,
    MTP3,
    SCCP,
    DOCSIS,
    LINUX_IRDA,
    USER0,
    USER1,
    USER2,
    USER3,
    USER4,
    USER5,
    USER6,
    USER7,
    USER8,
    USER9,
    USER10,
    USER11,
    USER12,
    USER13,
    USER14,
    USER15,
    IEEE802_11_AVS,
    BACNET_MS_TP,
    PPP_PPPD,
    GPRS_LLC,
    GPF_T,
    GPF_F,
    LINUX_LAPD,
    BLUETOOTH_HCI_H4,
    USB_LINUX,
    PPI,
    IEEE802_15_4,
    SITA,
    ERF,
    BLUETOOTH_HCI_H4_WITH_PHDR,
    AX25_KISS,
    LAPD,
    PPP_WITH_DIR,
    C_HDLC_WITH_DIR,
    FRELAY_WITH_DIR,
    IPMB_LINUX,
    IEEE802_15_4_NONASK_PHY,
    USB_LINUX_MMAPPED,
    FC_2,
    FC_2_WITH_FRAME_DELIMS,
    IPNET,
    CAN_SOCKETCAN,
    IPV4,
    IPV6,
    IEEE802_15_4_NOFCS,
    DBUS,
    DVB_CI,
    MUX27010,
    STANAG_5066_D_PDU,
    NFLOG,
    NETANALYZER,
    NETANALYZER_TRANSPARENT,
    IPOIB,
    MPEG_2_TS,
    NG40,
    NFC_LLCP,
    INFINIBAND,
    SCTP,
    USBPCAP,
    RTAC_SERIAL,
    BLUETOOTH_LE_LL,
    NETLINK,
    BLUETOOTH_LINUX_MONITOR,
    BLUETOOTH_BREDR_BB,
    BLUETOOTH_LE_LL_WITH_PHDR,
    PROFIBUS_DL,
    PKTAP,
    EPON,
    IPMI_HPM_2,
    ZWAVE_R1_R2,
    ZWAVE_R3,
    WATTSTOPPER_DLM,
    ISO_14443,
    RDS,
    USB_DARWIN,
    SDLC,

    Unknown(u32)
}

impl From<u32> for DataLink {

    fn from(n: u32) -> DataLink {

        match n {
            0 => DataLink::NULL,
            1 => DataLink::ETHERNET,
            3 => DataLink::AX25,
            6 => DataLink::IEEE802_5,
            7 => DataLink::ARCNET_BSD,
            8 => DataLink::SLIP,
            9 => DataLink::PPP,
            10 => DataLink::FDDI,
            50 => DataLink::PPP_HDLC,
            51 => DataLink::PPP_ETHER,
            100 => DataLink::ATM_RFC1483,
            101 => DataLink::RAW,
            104 => DataLink::C_HDLC,
            105 => DataLink::IEEE802_11,
            107 => DataLink::FRELAY,
            108 => DataLink::LOOP,
            113 => DataLink::LINUX_SLL,
            114 => DataLink::LTALK,
            117 => DataLink::PFLOG,
            119 => DataLink::IEEE802_11_PRISM,
            122 => DataLink::IP_OVER_FC,
            123 => DataLink::SUNATM,
            127 => DataLink::IEEE802_11_RADIOTAP,
            129 => DataLink::ARCNET_LINUX,
            138 => DataLink::APPLE_IP_OVER_IEEE1394,
            139 => DataLink::MTP2_WITH_PHDR,
            140 => DataLink::MTP2,
            141 => DataLink::MTP3,
            142 => DataLink::SCCP,
            143 => DataLink::DOCSIS,
            144 => DataLink::LINUX_IRDA,
            147 => DataLink::USER0,
            148 => DataLink::USER1,
            149 => DataLink::USER2,
            150 => DataLink::USER3,
            151 => DataLink::USER4,
            152 => DataLink::USER5,
            153 => DataLink::USER6,
            154 => DataLink::USER7,
            155 => DataLink::USER8,
            156 => DataLink::USER9,
            157 => DataLink::USER10,
            158 => DataLink::USER11,
            159 => DataLink::USER12,
            160 => DataLink::USER13,
            161 => DataLink::USER14,
            162 => DataLink::USER15,
            163 => DataLink::IEEE802_11_AVS,
            165 => DataLink::BACNET_MS_TP,
            166 => DataLink::PPP_PPPD,
            169 => DataLink::GPRS_LLC,
            170 => DataLink::GPF_T,
            171 => DataLink::GPF_F,
            177 => DataLink::LINUX_LAPD,
            187 => DataLink::BLUETOOTH_HCI_H4,
            189 => DataLink::USB_LINUX,
            192 => DataLink::PPI,
            195 => DataLink::IEEE802_15_4,
            196 => DataLink::SITA,
            197 => DataLink::ERF,
            201 => DataLink::BLUETOOTH_HCI_H4_WITH_PHDR,
            202 => DataLink::AX25_KISS,
            203 => DataLink::LAPD,
            204 => DataLink::PPP_WITH_DIR,
            205 => DataLink::C_HDLC_WITH_DIR,
            206 => DataLink::FRELAY_WITH_DIR,
            209 => DataLink::IPMB_LINUX,
            215 => DataLink::IEEE802_15_4_NONASK_PHY,
            220 => DataLink::USB_LINUX_MMAPPED,
            224 => DataLink::FC_2,
            225 => DataLink::FC_2_WITH_FRAME_DELIMS,
            226 => DataLink::IPNET,
            227 => DataLink::CAN_SOCKETCAN,
            228 => DataLink::IPV4,
            229 => DataLink::IPV6,
            230 => DataLink::IEEE802_15_4_NOFCS,
            231 => DataLink::DBUS,
            235 => DataLink::DVB_CI,
            236 => DataLink::MUX27010,
            237 => DataLink::STANAG_5066_D_PDU,
            239 => DataLink::NFLOG,
            240 => DataLink::NETANALYZER,
            241 => DataLink::NETANALYZER_TRANSPARENT,
            242 => DataLink::IPOIB,
            243 => DataLink::MPEG_2_TS,
            244 => DataLink::NG40,
            245 => DataLink::NFC_LLCP,
            247 => DataLink::INFINIBAND,
            248 => DataLink::SCTP,
            249 => DataLink::USBPCAP,
            250 => DataLink::RTAC_SERIAL,
            251 => DataLink::BLUETOOTH_LE_LL,
            253 => DataLink::NETLINK,
            254 => DataLink::BLUETOOTH_LINUX_MONITOR,
            255 => DataLink::BLUETOOTH_BREDR_BB,
            256 => DataLink::BLUETOOTH_LE_LL_WITH_PHDR,
            257 => DataLink::PROFIBUS_DL,
            258 => DataLink::PKTAP,
            259 => DataLink::EPON,
            260 => DataLink::IPMI_HPM_2,
            261 => DataLink::ZWAVE_R1_R2,
            262 => DataLink::ZWAVE_R3,
            263 => DataLink::WATTSTOPPER_DLM,
            264 => DataLink::ISO_14443,
            265 => DataLink::RDS,
            266 => DataLink::USB_DARWIN,
            268 => DataLink::SDLC,

            _ => DataLink::Unknown(n)
        }
    }
}

impl From<DataLink> for u32 {

    fn from(link: DataLink) -> u32 {

        match link {

            DataLink::NULL => 0,
            DataLink::ETHERNET => 1,
            DataLink::AX25 => 3,
            DataLink::IEEE802_5 => 6,
            DataLink::ARCNET_BSD => 7,
            DataLink::SLIP => 8,
            DataLink::PPP => 9,
            DataLink::FDDI => 10,
            DataLink::PPP_HDLC => 50,
            DataLink::PPP_ETHER => 51,
            DataLink::ATM_RFC1483 => 100,
            DataLink::RAW => 101,
            DataLink::C_HDLC => 104,
            DataLink::IEEE802_11 => 105,
            DataLink::FRELAY => 107,
            DataLink::LOOP => 108,
            DataLink::LINUX_SLL => 113,
            DataLink::LTALK => 114,
            DataLink::PFLOG => 117,
            DataLink::IEEE802_11_PRISM => 119,
            DataLink::IP_OVER_FC => 122,
            DataLink::SUNATM => 123,
            DataLink::IEEE802_11_RADIOTAP => 127,
            DataLink::ARCNET_LINUX => 129,
            DataLink::APPLE_IP_OVER_IEEE1394 => 138,
            DataLink::MTP2_WITH_PHDR => 139,
            DataLink::MTP2 => 140,
            DataLink::MTP3 => 141,
            DataLink::SCCP => 142,
            DataLink::DOCSIS => 143,
            DataLink::LINUX_IRDA => 144,
            DataLink::USER0 => 147,
            DataLink::USER1 => 148,
            DataLink::USER2 => 149,
            DataLink::USER3 => 150,
            DataLink::USER4 => 151,
            DataLink::USER5 => 152,
            DataLink::USER6 => 153,
            DataLink::USER7 => 154,
            DataLink::USER8 => 155,
            DataLink::USER9 => 156,
            DataLink::USER10 => 157,
            DataLink::USER11 => 158,
            DataLink::USER12 => 159,
            DataLink::USER13 => 160,
            DataLink::USER14 => 161,
            DataLink::USER15 => 162,
            DataLink::IEEE802_11_AVS => 163,
            DataLink::BACNET_MS_TP => 165,
            DataLink::PPP_PPPD => 166,
            DataLink::GPRS_LLC => 169,
            DataLink::GPF_T => 170,
            DataLink::GPF_F => 171,
            DataLink::LINUX_LAPD => 177,
            DataLink::BLUETOOTH_HCI_H4 => 187,
            DataLink::USB_LINUX => 189,
            DataLink::PPI => 192,
            DataLink::IEEE802_15_4 => 195,
            DataLink::SITA => 196,
            DataLink::ERF => 197,
            DataLink::BLUETOOTH_HCI_H4_WITH_PHDR => 201,
            DataLink::AX25_KISS => 202,
            DataLink::LAPD => 203,
            DataLink::PPP_WITH_DIR => 204,
            DataLink::C_HDLC_WITH_DIR => 205,
            DataLink::FRELAY_WITH_DIR => 206,
            DataLink::IPMB_LINUX => 209,
            DataLink::IEEE802_15_4_NONASK_PHY => 215,
            DataLink::USB_LINUX_MMAPPED => 220,
            DataLink::FC_2 => 224,
            DataLink::FC_2_WITH_FRAME_DELIMS => 225,
            DataLink::IPNET => 226,
            DataLink::CAN_SOCKETCAN => 227,
            DataLink::IPV4 => 228,
            DataLink::IPV6 => 229,
            DataLink::IEEE802_15_4_NOFCS => 230,
            DataLink::DBUS => 231,
            DataLink::DVB_CI => 235,
            DataLink::MUX27010 => 236,
            DataLink::STANAG_5066_D_PDU => 237,
            DataLink::NFLOG => 239,
            DataLink::NETANALYZER => 240,
            DataLink::NETANALYZER_TRANSPARENT => 241,
            DataLink::IPOIB => 242,
            DataLink::MPEG_2_TS => 243,
            DataLink::NG40 => 244,
            DataLink::NFC_LLCP => 245,
            DataLink::INFINIBAND => 247,
            DataLink::SCTP => 248,
            DataLink::USBPCAP => 249,
            DataLink::RTAC_SERIAL => 250,
            DataLink::BLUETOOTH_LE_LL => 251,
            DataLink::NETLINK => 253,
            DataLink::BLUETOOTH_LINUX_MONITOR => 254,
            DataLink::BLUETOOTH_BREDR_BB => 255,
            DataLink::BLUETOOTH_LE_LL_WITH_PHDR => 256,
            DataLink::PROFIBUS_DL => 257,
            DataLink::PKTAP => 258,
            DataLink::EPON => 259,
            DataLink::IPMI_HPM_2 => 260,
            DataLink::ZWAVE_R1_R2 => 261,
            DataLink::ZWAVE_R3 => 262,
            DataLink::WATTSTOPPER_DLM => 263,
            DataLink::ISO_14443 => 264,
            DataLink::RDS => 265,
            DataLink::USB_DARWIN => 266,
            DataLink::SDLC => 268,

            DataLink::Unknown(n) => n
        }
    }
}