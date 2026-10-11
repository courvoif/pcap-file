//! Shared capture byte order and link-layer types.

/* ----- Imports ----- */

use byteorder_slice::ByteOrder;

/* ----- Byte order ----- */

/// Byte order of capture header fields.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Endianness {
    /// Big endian
    Big,
    /// Little endian
    Little,
}

impl Endianness {
    /// Returns whether the byte order is little endian.
    pub fn is_little(self) -> bool {
        match self {
            Endianness::Big => false,
            Endianness::Little => true,
        }
    }

    /// Returns whether the byte order is big endian.
    pub fn is_big(self) -> bool {
        match self {
            Endianness::Big => true,
            Endianness::Little => false,
        }
    }

    /// Returns the byte order represented by `B`.
    pub fn from_byteorder<B: ByteOrder>() -> Self {
        if B::read_u32(&[0, 0, 0, 1]) == 1 {
            Endianness::Big
        } else {
            Endianness::Little
        }
    }

    /// Returns the native byte order of the current target.
    pub fn native() -> Self {
        #[cfg(target_endian = "big")]
        return Endianness::Big;

        #[cfg(target_endian = "little")]
        return Endianness::Little;
    }
}

impl Default for Endianness {
    /// Returns the native byte order of the current target.
    fn default() -> Self {
        Self::native()
    }
}

/* ----- Link-layer types ----- */

/// Link-layer header type of captured packet data.
///
/// The link-layer header type specifies the first protocol of the packet.
///
/// See [http://www.tcpdump.org/linktypes.html](http://www.tcpdump.org/linktypes.html)
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataLink {
    /// Link-layer type code `0`.
    NULL,
    /// Link-layer type code `1`.
    ETHERNET,
    /// Link-layer type code `2`.
    EXP_ETHERNET,
    /// Link-layer type code `3`.
    AX25,
    /// Link-layer type code `4`.
    PRONET,
    /// Link-layer type code `5`.
    CHAOS,
    /// Link-layer type code `6`.
    IEEE802_5,
    /// Link-layer type code `7`.
    ARCNET_BSD,
    /// Link-layer type code `8`.
    SLIP,
    /// Link-layer type code `9`.
    PPP,
    /// Link-layer type code `10`.
    FDDI,
    /// Link-layer type code `32`.
    REDBACK_SMARTEDGE,
    /// Link-layer type code `50`.
    PPP_HDLC,
    /// Link-layer type code `51`.
    PPP_ETHER,
    /// Link-layer type code `99`.
    SYMANTEC_FIREWALL,
    /// Link-layer type code `100`.
    ATM_RFC1483,
    /// Link-layer type code `101`.
    RAW,
    /// Link-layer type code `102`.
    SLIP_BSDOS,
    /// Link-layer type code `103`.
    PPP_BSDOS,
    /// Link-layer type code `104`.
    MATCHING_MIN,
    /// Link-layer type code `104`.
    C_HDLC,
    /// Link-layer type code `105`.
    IEEE802_11,
    /// Link-layer type code `106`.
    ATM_CLIP,
    /// Link-layer type code `107`.
    FRELAY,
    /// Link-layer type code `108`.
    LOOP,
    /// Link-layer type code `109`.
    ENC,
    /// Link-layer type code `110`.
    LANE8023,
    /// Link-layer type code `111`.
    HIPPI,
    /// Link-layer type code `112`.
    NETBSD_HDLC,
    /// Link-layer type code `113`.
    LINUX_SLL,
    /// Link-layer type code `114`.
    LTALK,
    /// Link-layer type code `115`.
    ECONET,
    /// Link-layer type code `116`.
    IPFILTER,
    /// Link-layer type code `117`.
    PFLOG,
    /// Link-layer type code `118`.
    CISCO_IOS,
    /// Link-layer type code `119`.
    IEEE802_11_PRISM,
    /// Link-layer type code `120`.
    IEEE802_11_AIRONET,
    /// Link-layer type code `121`.
    HHDLC,
    /// Link-layer type code `122`.
    IP_OVER_FC,
    /// Link-layer type code `123`.
    SUNATM,
    /// Link-layer type code `124`.
    RIO,
    /// Link-layer type code `125`.
    PCI_EXP,
    /// Link-layer type code `126`.
    AURORA,
    /// Link-layer type code `127`.
    IEEE802_11_RADIOTAP,
    /// Link-layer type code `128`.
    TZSP,
    /// Link-layer type code `129`.
    ARCNET_LINUX,
    /// Link-layer type code `130`.
    JUNIPER_MLPPP,
    /// Link-layer type code `131`.
    JUNIPER_MLFR,
    /// Link-layer type code `132`.
    JUNIPER_ES,
    /// Link-layer type code `133`.
    JUNIPER_GGSN,
    /// Link-layer type code `134`.
    JUNIPER_MFR,
    /// Link-layer type code `135`.
    JUNIPER_ATM2,
    /// Link-layer type code `136`.
    JUNIPER_SERVICES,
    /// Link-layer type code `137`.
    JUNIPER_ATM1,
    /// Link-layer type code `138`.
    APPLE_IP_OVER_IEEE1394,
    /// Link-layer type code `139`.
    MTP2_WITH_PHDR,
    /// Link-layer type code `140`.
    MTP2,
    /// Link-layer type code `141`.
    MTP3,
    /// Link-layer type code `142`.
    SCCP,
    /// Link-layer type code `143`.
    DOCSIS,
    /// Link-layer type code `144`.
    LINUX_IRDA,
    /// Link-layer type code `145`.
    IBM_SP,
    /// Link-layer type code `146`.
    IBM_SN,
    /// Link-layer type code `147`.
    USER0,
    /// Link-layer type code `148`.
    USER1,
    /// Link-layer type code `149`.
    USER2,
    /// Link-layer type code `150`.
    USER3,
    /// Link-layer type code `151`.
    USER4,
    /// Link-layer type code `152`.
    USER5,
    /// Link-layer type code `153`.
    USER6,
    /// Link-layer type code `154`.
    USER7,
    /// Link-layer type code `155`.
    USER8,
    /// Link-layer type code `156`.
    USER9,
    /// Link-layer type code `157`.
    USER10,
    /// Link-layer type code `158`.
    USER11,
    /// Link-layer type code `159`.
    USER12,
    /// Link-layer type code `160`.
    USER13,
    /// Link-layer type code `161`.
    USER14,
    /// Link-layer type code `162`.
    USER15,
    /// Link-layer type code `163`.
    IEEE802_11_AVS,
    /// Link-layer type code `164`.
    JUNIPER_MONITOR,
    /// Link-layer type code `165`.
    BACNET_MS_TP,
    /// Link-layer type code `166`.
    PPP_PPPD,
    /// Link-layer type code `167`.
    JUNIPER_PPPOE,
    /// Link-layer type code `168`.
    JUNIPER_PPPOE_ATM,
    /// Link-layer type code `169`.
    GPRS_LLC,
    /// Link-layer type code `170`.
    GPF_T,
    /// Link-layer type code `171`.
    GPF_F,
    /// Link-layer type code `172`.
    GCOM_T1E1,
    /// Link-layer type code `173`.
    GCOM_SERIAL,
    /// Link-layer type code `174`.
    JUNIPER_PIC_PEER,
    /// Link-layer type code `175`.
    ERF_ETH,
    /// Link-layer type code `176`.
    ERF_POS,
    /// Link-layer type code `177`.
    LINUX_LAPD,
    /// Link-layer type code `178`.
    JUNIPER_ETHER,
    /// Link-layer type code `179`.
    JUNIPER_PPP,
    /// Link-layer type code `180`.
    JUNIPER_FRELAY,
    /// Link-layer type code `181`.
    JUNIPER_CHDLC,
    /// Link-layer type code `182`.
    MFR,
    /// Link-layer type code `183`.
    JUNIPER_VP,
    /// Link-layer type code `184`.
    A429,
    /// Link-layer type code `185`.
    A653_ICM,
    /// Link-layer type code `186`.
    USB_FREEBSD,
    /// Link-layer type code `187`.
    BLUETOOTH_HCI_H4,
    /// Link-layer type code `188`.
    IEEE802_16_MAC_CPS,
    /// Link-layer type code `189`.
    USB_LINUX,
    /// Link-layer type code `190`.
    CAN20B,
    /// Link-layer type code `191`.
    IEEE802_15_4_LINUX,
    /// Link-layer type code `192`.
    PPI,
    /// Link-layer type code `193`.
    IEEE802_16_MAC_CPS_RADIO,
    /// Link-layer type code `194`.
    JUNIPER_ISM,
    /// Link-layer type code `195`.
    IEEE802_15_4,
    /// Link-layer type code `196`.
    SITA,
    /// Link-layer type code `197`.
    ERF,
    /// Link-layer type code `198`.
    RAIF1,
    /// Link-layer type code `199`.
    IPMB_KONTRON,
    /// Link-layer type code `200`.
    JUNIPER_ST,
    /// Link-layer type code `201`.
    BLUETOOTH_HCI_H4_WITH_PHDR,
    /// Link-layer type code `202`.
    AX25_KISS,
    /// Link-layer type code `203`.
    LAPD,
    /// Link-layer type code `204`.
    PPP_WITH_DIR,
    /// Link-layer type code `205`.
    C_HDLC_WITH_DIR,
    /// Link-layer type code `206`.
    FRELAY_WITH_DIR,
    /// Link-layer type code `207`.
    LAPB_WITH_DIR,
    /// Link-layer type code `209`.
    IPMB_LINUX,
    /// Link-layer type code `210`.
    FLEXRAY,
    /// Link-layer type code `211`.
    MOST,
    /// Link-layer type code `212`.
    LIN,
    /// Link-layer type code `213`.
    X2E_SERIAL,
    /// Link-layer type code `214`.
    X2E_XORAYA,
    /// Link-layer type code `215`.
    IEEE802_15_4_NONASK_PHY,
    /// Link-layer type code `216`.
    LINUX_EVDEV,
    /// Link-layer type code `217`.
    GSMTAP_UM,
    /// Link-layer type code `218`.
    GSMTAP_ABIS,
    /// Link-layer type code `219`.
    MPLS,
    /// Link-layer type code `220`.
    USB_LINUX_MMAPPED,
    /// Link-layer type code `221`.
    DECT,
    /// Link-layer type code `222`.
    AOS,
    /// Link-layer type code `223`.
    WIHART,
    /// Link-layer type code `224`.
    FC_2,
    /// Link-layer type code `225`.
    FC_2_WITH_FRAME_DELIMS,
    /// Link-layer type code `226`.
    IPNET,
    /// Link-layer type code `227`.
    CAN_SOCKETCAN,
    /// Link-layer type code `228`.
    IPV4,
    /// Link-layer type code `229`.
    IPV6,
    /// Link-layer type code `230`.
    IEEE802_15_4_NOFCS,
    /// Link-layer type code `231`.
    DBUS,
    /// Link-layer type code `232`.
    JUNIPER_VS,
    /// Link-layer type code `233`.
    JUNIPER_SRX_E2E,
    /// Link-layer type code `234`.
    JUNIPER_FIBRECHANNEL,
    /// Link-layer type code `235`.
    DVB_CI,
    /// Link-layer type code `236`.
    MUX27010,
    /// Link-layer type code `237`.
    STANAG_5066_D_PDU,
    /// Link-layer type code `238`.
    JUNIPER_ATM_CEMIC,
    /// Link-layer type code `239`.
    NFLOG,
    /// Link-layer type code `240`.
    NETANALYZER,
    /// Link-layer type code `241`.
    NETANALYZER_TRANSPARENT,
    /// Link-layer type code `242`.
    IPOIB,
    /// Link-layer type code `243`.
    MPEG_2_TS,
    /// Link-layer type code `244`.
    NG40,
    /// Link-layer type code `245`.
    NFC_LLCP,
    /// Link-layer type code `246`.
    PFSYNC,
    /// Link-layer type code `247`.
    INFINIBAND,
    /// Link-layer type code `248`.
    SCTP,
    /// Link-layer type code `249`.
    USBPCAP,
    /// Link-layer type code `250`.
    RTAC_SERIAL,
    /// Link-layer type code `251`.
    BLUETOOTH_LE_LL,
    /// Link-layer type code `252`.
    WIRESHARK_UPPER_PDU,
    /// Link-layer type code `253`.
    NETLINK,
    /// Link-layer type code `254`.
    BLUETOOTH_LINUX_MONITOR,
    /// Link-layer type code `255`.
    BLUETOOTH_BREDR_BB,
    /// Link-layer type code `256`.
    BLUETOOTH_LE_LL_WITH_PHDR,
    /// Link-layer type code `257`.
    PROFIBUS_DL,
    /// Link-layer type code `258`.
    PKTAP,
    /// Link-layer type code `259`.
    EPON,
    /// Link-layer type code `260`.
    IPMI_HPM_2,
    /// Link-layer type code `261`.
    ZWAVE_R1_R2,
    /// Link-layer type code `262`.
    ZWAVE_R3,
    /// Link-layer type code `263`.
    WATTSTOPPER_DLM,
    /// Link-layer type code `264`.
    ISO_14443,
    /// Link-layer type code `265`.
    RDS,
    /// Link-layer type code `266`.
    USB_DARWIN,
    /// Link-layer type code `267`.
    OPENFLOW,
    /// Link-layer type code `268`.
    SDLC,
    /// Link-layer type code `269`.
    TI_LLN_SNIFFER,
    /// Link-layer type code `270`.
    LORATAP,
    /// Link-layer type code `271`.
    VSOCK,
    /// Link-layer type code `272`.
    NORDIC_BLE,
    /// Link-layer type code `273`.
    DOCSIS31_XRA31,
    /// Link-layer type code `274`.
    ETHERNET_MPACKET,
    /// Link-layer type code `275`.
    DISPLAYPORT_AUX,
    /// Link-layer type code `276`.
    LINUX_SLL2,
    /// Link-layer type code `277`.
    SERCOS_MONITOR,
    /// Link-layer type code `278`.
    OPENVIZSLA,
    /// Link-layer type code `279`.
    EBHSCR,
    /// Link-layer type code `280`.
    VPP_DISPATCH,
    /// Link-layer type code `281`.
    DSA_TAG_BRCM,
    /// Link-layer type code `282`.
    DSA_TAG_BRCM_PREPEND,
    /// Link-layer type code `283`.
    IEEE802_15_4_TAP,
    /// Link-layer type code `284`.
    DSA_TAG_DSA,
    /// Link-layer type code `285`.
    DSA_TAG_EDSA,
    /// Link-layer type code `286`.
    ELEE,
    /// Link-layer type code `287`.
    Z_WAVE_SERIAL,
    /// Link-layer type code `288`.
    USB_2_0,
    /// Link-layer type code `289`.
    ATSC_ALP,
    /// Link-layer type code `290`.
    ETW,
    /// Link-layer type code `291`.
    NETANALYZER_NG,
    /// Link-layer type code `292`.
    ZBOSS_NCP,
    /// Link-layer type code `293`.
    USB_2_0_LOW_SPEED,
    /// Link-layer type code `294`.
    USB_2_0_FULL_SPEED,
    /// Link-layer type code `295`.
    USB_2_0_HIGH_SPEED,
    /// Link-layer type code `296`.
    AUERSWALD_LOG,
    /// Link-layer type code `297`.
    ZWAVE_TAP,
    /// Link-layer type code `298`.
    SILABS_DEBUG_CHANNEL,
    /// Link-layer type code `299`.
    FIRA_UCI,
    /// Link-layer type code `300`.
    MDB,
    /// Link-layer type code `301`.
    DECT_NR,
    /// Link-layer type code `302`.
    EDK2_MM,
    /// Link-layer type code `303`.
    DEBUG_ONLY,

    /// Unrecognized link-layer code, preserved for round trips.
    Unknown(u32),
}

/* ----- Link-layer conversions ----- */

impl From<u32> for DataLink {
    /// Returns the link-layer type for a code, preserving unrecognized codes as `UNKNOWN`.
    fn from(n: u32) -> DataLink {
        match n {
            0 => DataLink::NULL,
            1 => DataLink::ETHERNET,
            2 => DataLink::EXP_ETHERNET,
            3 => DataLink::AX25,
            4 => DataLink::PRONET,
            5 => DataLink::CHAOS,
            6 => DataLink::IEEE802_5,
            7 => DataLink::ARCNET_BSD,
            8 => DataLink::SLIP,
            9 => DataLink::PPP,
            10 => DataLink::FDDI,
            32 => DataLink::REDBACK_SMARTEDGE,
            50 => DataLink::PPP_HDLC,
            51 => DataLink::PPP_ETHER,
            99 => DataLink::SYMANTEC_FIREWALL,
            100 => DataLink::ATM_RFC1483,
            101 => DataLink::RAW,
            102 => DataLink::SLIP_BSDOS,
            103 => DataLink::PPP_BSDOS,
            104 => DataLink::C_HDLC,
            105 => DataLink::IEEE802_11,
            106 => DataLink::ATM_CLIP,
            107 => DataLink::FRELAY,
            108 => DataLink::LOOP,
            109 => DataLink::ENC,
            110 => DataLink::LANE8023,
            111 => DataLink::HIPPI,
            112 => DataLink::NETBSD_HDLC,
            113 => DataLink::LINUX_SLL,
            114 => DataLink::LTALK,
            115 => DataLink::ECONET,
            116 => DataLink::IPFILTER,
            117 => DataLink::PFLOG,
            118 => DataLink::CISCO_IOS,
            119 => DataLink::IEEE802_11_PRISM,
            120 => DataLink::IEEE802_11_AIRONET,
            121 => DataLink::HHDLC,
            122 => DataLink::IP_OVER_FC,
            123 => DataLink::SUNATM,
            124 => DataLink::RIO,
            125 => DataLink::PCI_EXP,
            126 => DataLink::AURORA,
            127 => DataLink::IEEE802_11_RADIOTAP,
            128 => DataLink::TZSP,
            129 => DataLink::ARCNET_LINUX,
            130 => DataLink::JUNIPER_MLPPP,
            131 => DataLink::JUNIPER_MLFR,
            132 => DataLink::JUNIPER_ES,
            133 => DataLink::JUNIPER_GGSN,
            134 => DataLink::JUNIPER_MFR,
            135 => DataLink::JUNIPER_ATM2,
            136 => DataLink::JUNIPER_SERVICES,
            137 => DataLink::JUNIPER_ATM1,
            138 => DataLink::APPLE_IP_OVER_IEEE1394,
            139 => DataLink::MTP2_WITH_PHDR,
            140 => DataLink::MTP2,
            141 => DataLink::MTP3,
            142 => DataLink::SCCP,
            143 => DataLink::DOCSIS,
            144 => DataLink::LINUX_IRDA,
            145 => DataLink::IBM_SP,
            146 => DataLink::IBM_SN,
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
            164 => DataLink::JUNIPER_MONITOR,
            165 => DataLink::BACNET_MS_TP,
            166 => DataLink::PPP_PPPD,
            167 => DataLink::JUNIPER_PPPOE,
            168 => DataLink::JUNIPER_PPPOE_ATM,
            169 => DataLink::GPRS_LLC,
            170 => DataLink::GPF_T,
            171 => DataLink::GPF_F,
            172 => DataLink::GCOM_T1E1,
            173 => DataLink::GCOM_SERIAL,
            174 => DataLink::JUNIPER_PIC_PEER,
            175 => DataLink::ERF_ETH,
            176 => DataLink::ERF_POS,
            177 => DataLink::LINUX_LAPD,
            178 => DataLink::JUNIPER_ETHER,
            179 => DataLink::JUNIPER_PPP,
            180 => DataLink::JUNIPER_FRELAY,
            181 => DataLink::JUNIPER_CHDLC,
            182 => DataLink::MFR,
            183 => DataLink::JUNIPER_VP,
            184 => DataLink::A429,
            185 => DataLink::A653_ICM,
            186 => DataLink::USB_FREEBSD,
            187 => DataLink::BLUETOOTH_HCI_H4,
            188 => DataLink::IEEE802_16_MAC_CPS,
            189 => DataLink::USB_LINUX,
            190 => DataLink::CAN20B,
            191 => DataLink::IEEE802_15_4_LINUX,
            192 => DataLink::PPI,
            193 => DataLink::IEEE802_16_MAC_CPS_RADIO,
            194 => DataLink::JUNIPER_ISM,
            195 => DataLink::IEEE802_15_4,
            196 => DataLink::SITA,
            197 => DataLink::ERF,
            198 => DataLink::RAIF1,
            199 => DataLink::IPMB_KONTRON,
            200 => DataLink::JUNIPER_ST,
            201 => DataLink::BLUETOOTH_HCI_H4_WITH_PHDR,
            202 => DataLink::AX25_KISS,
            203 => DataLink::LAPD,
            204 => DataLink::PPP_WITH_DIR,
            205 => DataLink::C_HDLC_WITH_DIR,
            206 => DataLink::FRELAY_WITH_DIR,
            207 => DataLink::LAPB_WITH_DIR,
            209 => DataLink::IPMB_LINUX,
            210 => DataLink::FLEXRAY,
            211 => DataLink::MOST,
            212 => DataLink::LIN,
            213 => DataLink::X2E_SERIAL,
            214 => DataLink::X2E_XORAYA,
            215 => DataLink::IEEE802_15_4_NONASK_PHY,
            216 => DataLink::LINUX_EVDEV,
            217 => DataLink::GSMTAP_UM,
            218 => DataLink::GSMTAP_ABIS,
            219 => DataLink::MPLS,
            220 => DataLink::USB_LINUX_MMAPPED,
            221 => DataLink::DECT,
            222 => DataLink::AOS,
            223 => DataLink::WIHART,
            224 => DataLink::FC_2,
            225 => DataLink::FC_2_WITH_FRAME_DELIMS,
            226 => DataLink::IPNET,
            227 => DataLink::CAN_SOCKETCAN,
            228 => DataLink::IPV4,
            229 => DataLink::IPV6,
            230 => DataLink::IEEE802_15_4_NOFCS,
            231 => DataLink::DBUS,
            232 => DataLink::JUNIPER_VS,
            233 => DataLink::JUNIPER_SRX_E2E,
            234 => DataLink::JUNIPER_FIBRECHANNEL,
            235 => DataLink::DVB_CI,
            236 => DataLink::MUX27010,
            237 => DataLink::STANAG_5066_D_PDU,
            238 => DataLink::JUNIPER_ATM_CEMIC,
            239 => DataLink::NFLOG,
            240 => DataLink::NETANALYZER,
            241 => DataLink::NETANALYZER_TRANSPARENT,
            242 => DataLink::IPOIB,
            243 => DataLink::MPEG_2_TS,
            244 => DataLink::NG40,
            245 => DataLink::NFC_LLCP,
            246 => DataLink::PFSYNC,
            247 => DataLink::INFINIBAND,
            248 => DataLink::SCTP,
            249 => DataLink::USBPCAP,
            250 => DataLink::RTAC_SERIAL,
            251 => DataLink::BLUETOOTH_LE_LL,
            252 => DataLink::WIRESHARK_UPPER_PDU,
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
            267 => DataLink::OPENFLOW,
            268 => DataLink::SDLC,
            269 => DataLink::TI_LLN_SNIFFER,
            270 => DataLink::LORATAP,
            271 => DataLink::VSOCK,
            272 => DataLink::NORDIC_BLE,
            273 => DataLink::DOCSIS31_XRA31,
            274 => DataLink::ETHERNET_MPACKET,
            275 => DataLink::DISPLAYPORT_AUX,
            276 => DataLink::LINUX_SLL2,
            277 => DataLink::SERCOS_MONITOR,
            278 => DataLink::OPENVIZSLA,
            279 => DataLink::EBHSCR,
            280 => DataLink::VPP_DISPATCH,
            281 => DataLink::DSA_TAG_BRCM,
            282 => DataLink::DSA_TAG_BRCM_PREPEND,
            283 => DataLink::IEEE802_15_4_TAP,
            284 => DataLink::DSA_TAG_DSA,
            285 => DataLink::DSA_TAG_EDSA,
            286 => DataLink::ELEE,
            287 => DataLink::Z_WAVE_SERIAL,
            288 => DataLink::USB_2_0,
            289 => DataLink::ATSC_ALP,
            290 => DataLink::ETW,
            291 => DataLink::NETANALYZER_NG,
            292 => DataLink::ZBOSS_NCP,
            293 => DataLink::USB_2_0_LOW_SPEED,
            294 => DataLink::USB_2_0_FULL_SPEED,
            295 => DataLink::USB_2_0_HIGH_SPEED,
            296 => DataLink::AUERSWALD_LOG,
            297 => DataLink::ZWAVE_TAP,
            298 => DataLink::SILABS_DEBUG_CHANNEL,
            299 => DataLink::FIRA_UCI,
            300 => DataLink::MDB,
            301 => DataLink::DECT_NR,
            302 => DataLink::EDK2_MM,
            303 => DataLink::DEBUG_ONLY,

            _ => DataLink::Unknown(n),
        }
    }
}

impl From<DataLink> for u32 {
    /// Returns the encoded link-layer code, preserving the value carried by `UNKNOWN`.
    fn from(link: DataLink) -> u32 {
        match link {
            DataLink::NULL => 0,
            DataLink::ETHERNET => 1,
            DataLink::EXP_ETHERNET => 2,
            DataLink::AX25 => 3,
            DataLink::PRONET => 4,
            DataLink::CHAOS => 5,
            DataLink::IEEE802_5 => 6,
            DataLink::ARCNET_BSD => 7,
            DataLink::SLIP => 8,
            DataLink::PPP => 9,
            DataLink::FDDI => 10,
            DataLink::REDBACK_SMARTEDGE => 32,
            DataLink::PPP_HDLC => 50,
            DataLink::PPP_ETHER => 51,
            DataLink::SYMANTEC_FIREWALL => 99,
            DataLink::ATM_RFC1483 => 100,
            DataLink::RAW => 101,
            DataLink::SLIP_BSDOS => 102,
            DataLink::PPP_BSDOS => 103,
            DataLink::MATCHING_MIN => 104,
            DataLink::C_HDLC => 104,
            DataLink::IEEE802_11 => 105,
            DataLink::ATM_CLIP => 106,
            DataLink::FRELAY => 107,
            DataLink::LOOP => 108,
            DataLink::ENC => 109,
            DataLink::LANE8023 => 110,
            DataLink::HIPPI => 111,
            DataLink::NETBSD_HDLC => 112,
            DataLink::LINUX_SLL => 113,
            DataLink::LTALK => 114,
            DataLink::ECONET => 115,
            DataLink::IPFILTER => 116,
            DataLink::PFLOG => 117,
            DataLink::CISCO_IOS => 118,
            DataLink::IEEE802_11_PRISM => 119,
            DataLink::IEEE802_11_AIRONET => 120,
            DataLink::HHDLC => 121,
            DataLink::IP_OVER_FC => 122,
            DataLink::SUNATM => 123,
            DataLink::RIO => 124,
            DataLink::PCI_EXP => 125,
            DataLink::AURORA => 126,
            DataLink::IEEE802_11_RADIOTAP => 127,
            DataLink::TZSP => 128,
            DataLink::ARCNET_LINUX => 129,
            DataLink::JUNIPER_MLPPP => 130,
            DataLink::JUNIPER_MLFR => 131,
            DataLink::JUNIPER_ES => 132,
            DataLink::JUNIPER_GGSN => 133,
            DataLink::JUNIPER_MFR => 134,
            DataLink::JUNIPER_ATM2 => 135,
            DataLink::JUNIPER_SERVICES => 136,
            DataLink::JUNIPER_ATM1 => 137,
            DataLink::APPLE_IP_OVER_IEEE1394 => 138,
            DataLink::MTP2_WITH_PHDR => 139,
            DataLink::MTP2 => 140,
            DataLink::MTP3 => 141,
            DataLink::SCCP => 142,
            DataLink::DOCSIS => 143,
            DataLink::LINUX_IRDA => 144,
            DataLink::IBM_SP => 145,
            DataLink::IBM_SN => 146,
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
            DataLink::JUNIPER_MONITOR => 164,
            DataLink::BACNET_MS_TP => 165,
            DataLink::PPP_PPPD => 166,
            DataLink::JUNIPER_PPPOE => 167,
            DataLink::JUNIPER_PPPOE_ATM => 168,
            DataLink::GPRS_LLC => 169,
            DataLink::GPF_T => 170,
            DataLink::GPF_F => 171,
            DataLink::GCOM_T1E1 => 172,
            DataLink::GCOM_SERIAL => 173,
            DataLink::JUNIPER_PIC_PEER => 174,
            DataLink::ERF_ETH => 175,
            DataLink::ERF_POS => 176,
            DataLink::LINUX_LAPD => 177,
            DataLink::JUNIPER_ETHER => 178,
            DataLink::JUNIPER_PPP => 179,
            DataLink::JUNIPER_FRELAY => 180,
            DataLink::JUNIPER_CHDLC => 181,
            DataLink::MFR => 182,
            DataLink::JUNIPER_VP => 183,
            DataLink::A429 => 184,
            DataLink::A653_ICM => 185,
            DataLink::USB_FREEBSD => 186,
            DataLink::BLUETOOTH_HCI_H4 => 187,
            DataLink::IEEE802_16_MAC_CPS => 188,
            DataLink::USB_LINUX => 189,
            DataLink::CAN20B => 190,
            DataLink::IEEE802_15_4_LINUX => 191,
            DataLink::PPI => 192,
            DataLink::IEEE802_16_MAC_CPS_RADIO => 193,
            DataLink::JUNIPER_ISM => 194,
            DataLink::IEEE802_15_4 => 195,
            DataLink::SITA => 196,
            DataLink::ERF => 197,
            DataLink::RAIF1 => 198,
            DataLink::IPMB_KONTRON => 199,
            DataLink::JUNIPER_ST => 200,
            DataLink::BLUETOOTH_HCI_H4_WITH_PHDR => 201,
            DataLink::AX25_KISS => 202,
            DataLink::LAPD => 203,
            DataLink::PPP_WITH_DIR => 204,
            DataLink::C_HDLC_WITH_DIR => 205,
            DataLink::FRELAY_WITH_DIR => 206,
            DataLink::LAPB_WITH_DIR => 207,
            DataLink::IPMB_LINUX => 209,
            DataLink::FLEXRAY => 210,
            DataLink::MOST => 211,
            DataLink::LIN => 212,
            DataLink::X2E_SERIAL => 213,
            DataLink::X2E_XORAYA => 214,
            DataLink::IEEE802_15_4_NONASK_PHY => 215,
            DataLink::LINUX_EVDEV => 216,
            DataLink::GSMTAP_UM => 217,
            DataLink::GSMTAP_ABIS => 218,
            DataLink::MPLS => 219,
            DataLink::USB_LINUX_MMAPPED => 220,
            DataLink::DECT => 221,
            DataLink::AOS => 222,
            DataLink::WIHART => 223,
            DataLink::FC_2 => 224,
            DataLink::FC_2_WITH_FRAME_DELIMS => 225,
            DataLink::IPNET => 226,
            DataLink::CAN_SOCKETCAN => 227,
            DataLink::IPV4 => 228,
            DataLink::IPV6 => 229,
            DataLink::IEEE802_15_4_NOFCS => 230,
            DataLink::DBUS => 231,
            DataLink::JUNIPER_VS => 232,
            DataLink::JUNIPER_SRX_E2E => 233,
            DataLink::JUNIPER_FIBRECHANNEL => 234,
            DataLink::DVB_CI => 235,
            DataLink::MUX27010 => 236,
            DataLink::STANAG_5066_D_PDU => 237,
            DataLink::JUNIPER_ATM_CEMIC => 238,
            DataLink::NFLOG => 239,
            DataLink::NETANALYZER => 240,
            DataLink::NETANALYZER_TRANSPARENT => 241,
            DataLink::IPOIB => 242,
            DataLink::MPEG_2_TS => 243,
            DataLink::NG40 => 244,
            DataLink::NFC_LLCP => 245,
            DataLink::PFSYNC => 246,
            DataLink::INFINIBAND => 247,
            DataLink::SCTP => 248,
            DataLink::USBPCAP => 249,
            DataLink::RTAC_SERIAL => 250,
            DataLink::BLUETOOTH_LE_LL => 251,
            DataLink::WIRESHARK_UPPER_PDU => 252,
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
            DataLink::OPENFLOW => 267,
            DataLink::SDLC => 268,
            DataLink::TI_LLN_SNIFFER => 269,
            DataLink::LORATAP => 270,
            DataLink::VSOCK => 271,
            DataLink::NORDIC_BLE => 272,
            DataLink::DOCSIS31_XRA31 => 273,
            DataLink::ETHERNET_MPACKET => 274,
            DataLink::DISPLAYPORT_AUX => 275,
            DataLink::LINUX_SLL2 => 276,
            DataLink::SERCOS_MONITOR => 277,
            DataLink::OPENVIZSLA => 278,
            DataLink::EBHSCR => 279,
            DataLink::VPP_DISPATCH => 280,
            DataLink::DSA_TAG_BRCM => 281,
            DataLink::DSA_TAG_BRCM_PREPEND => 282,
            DataLink::IEEE802_15_4_TAP => 283,
            DataLink::DSA_TAG_DSA => 284,
            DataLink::DSA_TAG_EDSA => 285,
            DataLink::ELEE => 286,
            DataLink::Z_WAVE_SERIAL => 287,
            DataLink::USB_2_0 => 288,
            DataLink::ATSC_ALP => 289,
            DataLink::ETW => 290,
            DataLink::NETANALYZER_NG => 291,
            DataLink::ZBOSS_NCP => 292,
            DataLink::USB_2_0_LOW_SPEED => 293,
            DataLink::USB_2_0_FULL_SPEED => 294,
            DataLink::USB_2_0_HIGH_SPEED => 295,
            DataLink::AUERSWALD_LOG => 296,
            DataLink::ZWAVE_TAP => 297,
            DataLink::SILABS_DEBUG_CHANNEL => 298,
            DataLink::FIRA_UCI => 299,
            DataLink::MDB => 300,
            DataLink::DECT_NR => 301,
            DataLink::EDK2_MM => 302,
            DataLink::DEBUG_ONLY => 303,

            DataLink::Unknown(n) => n,
        }
    }
}
