// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Canonical ADNL packet policy, retaining wire flags before identity/admission checks.
use super::wire_keys::NetworkPublicKey;
use anyhow::Result;
use rtos_api::{
    ton::{
        self,
        adnl::{
            addresslist::AddressList as TlAddressList, packetcontents::PacketContents, Address,
            Message,
        },
    },
    BoxedDeserialize, Constructor, Deserializer, IntoBoxed, WireProfile,
};
use std::net::{Ipv4Addr, SocketAddrV4};
#[derive(Debug)]
pub struct Refusal(pub &'static str);
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Refusal {}
fn reject(reason: &'static str) -> anyhow::Error {
    Refusal(reason).into()
}
fn decode<T: BoxedDeserialize>(bytes: &[u8]) -> Result<T> {
    super::wire::decode(bytes, reject)
}

#[derive(Clone, Debug)]
pub struct AddressList {
    canonical: TlAddressList,
    addresses: Vec<Address>,
    quic: Vec<SocketAddrV4>,
    reverse: bool,
    size: u32,
}
impl AddressList {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let value: ton::adnl::AddressList = decode(bytes)?;
        Self::from_tl(value.only())
    }
    pub fn from_tl(mut value: TlAddressList) -> Result<Self> {
        let mut addresses = Vec::new();
        let mut quic = Vec::new();
        let mut reverse = false;
        let mut size = 24u32;
        for mut address in std::mem::take(&mut value.addrs) {
            match &mut address {
                Address::Adnl_Address_Reverse => {
                    reverse = true;
                    continue;
                }
                Address::Adnl_Address_Quic(v) => {
                    quic.push(SocketAddrV4::new(Ipv4Addr::from(v.ip as u32), v.port as u16));
                    continue;
                }
                Address::Adnl_Address_Udp(v) => {
                    v.port = v.port as u16 as i32;
                    size = size.wrapping_add(12);
                }
                Address::Adnl_Address_Udp6(v) => {
                    v.port = v.port as u16 as i32;
                    size = size.wrapping_add(24);
                }
                Address::Adnl_Address_Tunnel(v) => {
                    let key = NetworkPublicKey::from_wire(&WireProfile::T0.serialize(&v.pubkey)?)?;
                    size = size.wrapping_add(36).wrapping_add(key.serialized_size_estimate());
                }
            }
            addresses.push(address);
        }
        size = size
            .wrapping_add(if reverse { 4 } else { 0 })
            .wrapping_add((quic.len() as u32).wrapping_mul(12));
        if size > 128 {
            return Err(reject("address_list_oversize"));
        }
        value.addrs = addresses.clone();
        if reverse {
            value.addrs.push(Address::Adnl_Address_Reverse);
        }
        for address in &quic {
            value.addrs.push(Address::Adnl_Address_Quic(ton::adnl::address::address::Quic {
                ip: u32::from(*address.ip()) as i32,
                port: address.port() as i32,
            }));
        }
        Ok(Self { canonical: value, addresses, quic, reverse, size })
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        WireProfile::T0.serialize(&self.canonical.clone().into_boxed())
    }
    pub fn version(&self) -> i32 {
        self.canonical.version
    }
    pub fn reinit_date(&self) -> i32 {
        self.canonical.reinit_date
    }
    pub fn priority(&self) -> i32 {
        self.canonical.priority
    }
    pub fn expire_at(&self) -> i32 {
        self.canonical.expire_at
    }
    pub fn empty(&self) -> bool {
        self.version() == -1
    }
    pub fn public_only(&self) -> bool {
        self.addresses.iter().all(|a| !matches!(a, Address::Adnl_Address_Tunnel(_)))
    }
    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }
    pub fn quic(&self) -> &[SocketAddrV4] {
        &self.quic
    }
    pub fn has_reverse(&self) -> bool {
        self.reverse
    }
    pub fn serialized_size(&self) -> u32 {
        self.size
    }
}

/// Message sizing includes constructor and padded TL byte lengths, as the sender uses it.
#[derive(Clone, Debug)]
pub struct NetworkMessage(Message);
impl NetworkMessage {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        Ok(Self(decode(bytes)?))
    }
    pub fn from_tl(value: Message) -> Self {
        Self(value)
    }
    pub fn tl(&self) -> &Message {
        &self.0
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        WireProfile::T0.serialize(&self.0)
    }
    pub fn part_range(&self) -> Option<(u32, u32)> {
        match &self.0 {
            Message::Adnl_Message_Part(value) => {
                Some((value.total_size as u32, value.offset as u32))
            }
            _ => None,
        }
    }
    pub fn serialized_size(&self) -> u32 {
        fn bytes(n: usize) -> u32 {
            ((n + if n < 254 {
                1
            } else if n < 1 << 24 {
                4
            } else {
                8
            } + 3)
                & !3) as u32
        }
        match &self.0 {
            Message::Adnl_Message_CreateChannel(_) => 40,
            Message::Adnl_Message_ConfirmChannel(_) => 72,
            Message::Adnl_Message_Custom(v) => 4u32.wrapping_add(bytes(v.data.len())),
            Message::Adnl_Message_Nop => 4,
            Message::Adnl_Message_Reinit(_) => 8,
            Message::Adnl_Message_Query(v) => 36u32.wrapping_add(bytes(v.query.len())),
            Message::Adnl_Message_Answer(v) => 36u32.wrapping_add(bytes(v.answer.len())),
            Message::Adnl_Message_Part(v) => 44u32.wrapping_add(bytes(v.data.len())),
        }
    }
}

// The generated PacketContents intentionally derives flags from field presence.
// This receive codec keeps raw flags (including priority) while reusing typed TL
// field readers; validation and canonical signing belong to Packet below.
struct WirePacket {
    flags: u32,
    value: PacketContents,
}
impl BoxedDeserialize for WirePacket {
    fn possible_constructors() -> Vec<u32> {
        vec![PacketContents::constructor_const()]
    }
    fn deserialize_boxed(id: u32, de: &mut Deserializer) -> Result<Self> {
        if id != PacketContents::constructor_const() {
            return Err(rtos_api::InvalidConstructor {
                expected: Self::possible_constructors(),
                received: id,
            }
            .into());
        }
        let rand1 = de.read_bare()?;
        let flags: u32 = de.read_bare()?;
        if (flags as i32) < 0 {
            return Err(reject("tl_negative_flags"));
        }
        let from = if flags & 1 != 0 { Some(de.read_boxed()?) } else { None };
        let from_short = if flags & 2 != 0 { Some(de.read_bare()?) } else { None };
        let message = if flags & 4 != 0 { Some(de.read_boxed()?) } else { None };
        let messages = if flags & 8 != 0 {
            Some(<Vec<Message> as ton::VectoredBoxed<Message>>::deserialize(de)?)
        } else {
            None
        };
        let address = if flags & 16 != 0 { Some(de.read_bare()?) } else { None };
        let priority_address = if flags & 32 != 0 { Some(de.read_bare()?) } else { None };
        let seqno = if flags & 64 != 0 { Some(de.read_bare()?) } else { None };
        let confirm_seqno = if flags & 128 != 0 { Some(de.read_bare()?) } else { None };
        let recv_addr_list_version = if flags & 256 != 0 { Some(de.read_bare()?) } else { None };
        let recv_priority_addr_list_version =
            if flags & 512 != 0 { Some(de.read_bare()?) } else { None };
        let reinit_date = if flags & 1024 != 0 { Some(de.read_bare()?) } else { None };
        let dst_reinit_date = if flags & 1024 != 0 { Some(de.read_bare()?) } else { None };
        let signature = if flags & 2048 != 0 { Some(de.read_bare()?) } else { None };
        let rand2 = de.read_bare()?;
        Ok(Self {
            flags,
            value: PacketContents {
                rand1,
                from,
                from_short,
                message,
                messages,
                address,
                priority_address,
                seqno,
                confirm_seqno,
                recv_addr_list_version,
                recv_priority_addr_list_version,
                reinit_date,
                dst_reinit_date,
                signature,
                rand2,
            },
        })
    }
}

pub struct Packet {
    flags: u32,
    value: PacketContents,
    source: Option<NetworkPublicKey>,
    source_short: Option<[u8; 32]>,
    messages: Vec<NetworkMessage>,
    address: Option<AddressList>,
    priority_address: Option<AddressList>,
}
impl Packet {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let WirePacket { flags, mut value } = decode(bytes)?;
        let source = if let Some(key) = &value.from {
            if !matches!(key, ton::PublicKey::Pub_Ed25519(_)) {
                return Err(reject("not_ed25519"));
            }
            Some(NetworkPublicKey::from_wire(&WireProfile::T0.serialize(key)?)?)
        } else {
            None
        };
        let source_short = if let Some(id) = &value.from_short {
            Some(*id.id.as_array())
        } else {
            source.as_ref().map(NetworkPublicKey::short_id).transpose()?
        };
        let messages: Vec<NetworkMessage> = if let Some(values) = &value.messages {
            values.iter().cloned().map(NetworkMessage::from_tl).collect()
        } else {
            value.message.iter().cloned().map(NetworkMessage::from_tl).collect()
        };
        let address = value.address.take().map(AddressList::from_tl).transpose()?;
        let priority_address =
            value.priority_address.take().map(AddressList::from_tl).transpose()?;
        if flags & !0x1fff != 0 {
            return Err(reject("packet_bad_flags"));
        }
        if flags & 12 == 12 {
            return Err(reject("packet_message_flags"));
        }
        if flags & 4 != 0 && messages.len() != 1 {
            return Err(reject("packet_message_flags"));
        }
        if let (Some(source), Some(id)) = (&source, &value.from_short) {
            if source.short_id()? != *id.id.as_array() {
                return Err(reject("packet_source_mismatch"));
            }
        }
        if address.as_ref().is_some_and(AddressList::empty)
            || priority_address.as_ref().is_some_and(AddressList::empty)
        {
            return Err(reject("packet_address_list_empty"));
        }
        value.address = address.as_ref().map(|v| v.canonical.clone());
        value.priority_address = priority_address.as_ref().map(|v| v.canonical.clone());
        Ok(Self { flags, value, source, source_short, messages, address, priority_address })
    }
    pub fn flags(&self) -> u32 {
        self.flags
    }
    pub fn priority(&self) -> bool {
        self.flags & 4096 != 0
    }
    pub fn source(&self) -> Option<&NetworkPublicKey> {
        self.source.as_ref()
    }
    pub fn source_short(&self) -> Option<[u8; 32]> {
        self.source_short
    }
    pub fn messages(&self) -> &[NetworkMessage] {
        &self.messages
    }
    pub fn address(&self) -> Option<&AddressList> {
        self.address.as_ref()
    }
    pub fn priority_address(&self) -> Option<&AddressList> {
        self.priority_address.as_ref()
    }
    pub fn seqno(&self) -> u64 {
        self.value.seqno.unwrap_or(0) as u64
    }
    pub fn confirm_seqno(&self) -> u64 {
        self.value.confirm_seqno.unwrap_or(0) as u64
    }
    pub fn recv_addr_list_version(&self) -> i32 {
        self.value.recv_addr_list_version.unwrap_or(0)
    }
    pub fn recv_priority_addr_list_version(&self) -> i32 {
        self.value.recv_priority_addr_list_version.unwrap_or(0)
    }
    pub fn reinit_date(&self) -> i32 {
        self.value.reinit_date.unwrap_or(0)
    }
    pub fn dst_reinit_date(&self) -> i32 {
        self.value.dst_reinit_date.unwrap_or(0)
    }
    pub fn signature(&self) -> &[u8] {
        self.value.signature.as_deref().unwrap_or_default()
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        WireProfile::T0.serialize(&self.value.clone().into_boxed())
    }
    pub fn to_sign(&self) -> Result<Vec<u8>> {
        let mut value = self.value.clone();
        value.signature = None;
        WireProfile::T0.serialize(&value.into_boxed())
    }
    pub fn verify_signature(&self) -> Result<()> {
        self.source
            .as_ref()
            .ok_or_else(|| reject("source_unknown"))?
            .verify(&self.to_sign()?, self.signature())
    }
    /// Used after packet validation in the local-id receive path, before any peer installation.
    pub fn from_datagram(
        key: &super::wire_keys::NetworkPrivateKey,
        datagram: &[u8],
    ) -> Result<Self> {
        if datagram.len() < 32 {
            return Err(reject("datagram_short"));
        }
        let public = key.public_key()?;
        if datagram[..32] != public.short_id()? {
            return Err(reject("unknown_destination"));
        }
        // A local key without a decryptor is configuration failure, not a
        // peer packet refusal (the reference creates its decryptor here).
        if public.kind() == "overlay" {
            anyhow::bail!("local private key cannot decrypt ADNL datagrams");
        }
        let plain = key.decrypt(&datagram[32..])?;
        let packet = Self::from_wire(&plain)?;
        if packet.source_short.is_none() {
            return Err(reject("source_missing"));
        }
        if packet.source.is_none() {
            return Err(reject("source_unknown"));
        }
        packet.verify_signature()?;
        Ok(packet)
    }
}
