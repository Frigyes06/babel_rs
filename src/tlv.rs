//! Babel TLV parsing and serialization based on RFC 8966
//!
//! This module provides types and functions to work with Babel TLVs and sub-TLVs:
//! - `Tlv`: enum of all Babel TLV types (0‒10 plus Unknown)
//! - `SubTlv`: enum for sub-TLV types (Pad1, PadN, Unknown)
//! - `parse_all` / `parse`: routines to decode TLVs from a byte buffer
//! - `to_bytes`: routines to encode TLVs back to wire format
//!
//! References:
//! - <https://tools.ietf.org/html/rfc8966#section-4.3> (TLV types)
//! - <https://tools.ietf.org/html/rfc8966#section-4.7> (sub-TLVs)

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::vec;

/// A Babel TLV (Type-Length-Value), per RFC 8966 §4.3.
///
/// Each variant holds the TLV-specific fields. Unrecognized TLV types
/// are captured in the `Unknown` variant for forward compatibility.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Tlv {
    /// Pad1 (Type = 0): single-byte padding.
    Pad1,
    /// PadN (Type = 1): multi-byte padding.
    PadN { n: u8 },
    /// AckRequest (Type = 2): [Reserved(2), Opaque(2), Interval(2), Sub-TLVs...]
    AckRequest {
        opaque: u16,
        interval: u16,
        sub_tlvs: Vec<SubTlv>,
    },
    /// Ack (Type = 3): [Opaque(2), Sub-TLVs...]
    Ack { opaque: u16, sub_tlvs: Vec<SubTlv> },
    /// Hello (Type = 4): [Flags(2), Seqno(2), Interval(2), Sub-TLVs...]
    Hello {
        flags: u16,
        seqno: u16,
        interval: u16,
        sub_tlvs: Vec<SubTlv>,
    },
    /// IHU (Type = 5): [AE(1), Reserved(1), RxCost(2), Interval(2), Address?, Sub-TLVs...]
    Ihu {
        ae: u8,
        rxcost: u16,
        interval: u16,
        addr: Option<IpAddr>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// RouterId (Type = 6): [Reserved(2), RouterID(8), Sub-TLVs...]
    RouterId {
        router_id: [u8; 8],
        sub_tlvs: Vec<SubTlv>,
    },
    /// NextHop (Type = 7): [AE(1), Reserved(1), Address?, Sub-TLVs...]
    NextHop {
        ae: u8,
        addr: Option<IpAddr>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// Update (Type = 8): fields + prefix + sub-TLVs
    Update {
        ae: u8,
        flags: u8,
        plen: u8,
        omitted: u8,
        interval: u16,
        seqno: u16,
        metric: u16,
        prefix: Vec<u8>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// RouteRequest (Type = 9): [AE, PLen, Prefix, Sub-TLVs]
    RouteRequest {
        ae: u8,
        plen: u8,
        prefix: Vec<u8>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// SeqnoRequest (Type = 10): fields + router_id + prefix + sub-TLVs
    SeqnoRequest {
        ae: u8,
        plen: u8,
        seqno: u16,
        hop_count: u8,
        router_id: [u8; 8],
        prefix: Vec<u8>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// Any other, unrecognized TLV: raw type byte + data.
    Unknown { tlv_type: u8, data: Vec<u8> },
}

/// A sub-TLV inside certain TLVs, per RFC 8966 §4.7.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SubTlv {
    /// Pad1 (SType = 0)
    Pad1,
    /// PadN (SType = 1)
    PadN { n: u8 },
    /// Any other, unrecognized sub-TLV: SType + data.
    Unknown { stype: u8, data: Vec<u8> },
}

impl Tlv {
    /// Parse all TLVs found in `buf`, stopping at EOF or error.
    ///
    /// Returns `Ok(Vec<Tlv>)` if parsing succeeds (possibly empty),
    /// or `Err(String)` on malformed data.
    pub fn parse_all(buf: &[u8]) -> Result<Vec<Tlv>, String> {
        let mut out = Vec::new();
        let mut cur = Cursor::new(buf);
        while let Ok(t) = Tlv::parse(&mut cur) {
            out.push(t);
        }
        Ok(out)
    }

    /// Parse a single TLV at the cursor position, advancing the cursor.
    ///
    /// Returns `Err("EOF")` on end-of-buffer, or other error strings on failure.
    pub fn parse(cur: &mut Cursor<&[u8]>) -> Result<Tlv, String> {
        let start = cur.position() as usize;
        let total = cur.get_ref().len();
        if start >= total {
            return Err("EOF".into());
        }
        // Read type byte
        let t = cur.read_u8().map_err(|e| e.to_string())?;
        if t == 0 {
            // Pad1 is a single byte, no length field
            return Ok(Tlv::Pad1);
        }
        // Read length
        let length = cur.read_u8().map_err(|e| e.to_string())? as usize;
        let pos = cur.position() as usize;
        if pos + length > total {
            return Err("Length exceeds buffer".into());
        }
        // Extract payload slice
        let payload = cur.get_ref()[pos..pos + length].to_vec();
        cur.set_position((pos + length) as u64);

        // Dispatch by TLV type
        // Values 0 and >10 are treated as Pad1 (0) or Unknown respectively
        // t==0 handled earlier, so here t ∈ 1..=255 except 0
        let result: Tlv = match t {
            1 => {
                // PadN: we already consumed `length` bytes into `payload`.
                // For our representation, we just remember how many padding bytes there were.
                let n = length as u8;
                Tlv::PadN { n }
            }
            2 => {
                let mut p = Cursor::new(&payload);
                p.read_u16::<BigEndian>().map_err(|e| e.to_string())?; // reserved
                let opaque = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::AckRequest {
                    opaque,
                    interval,
                    sub_tlvs: subs,
                }
            }
            3 => {
                let mut p = Cursor::new(&payload);
                let opaque = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Ack {
                    opaque,
                    sub_tlvs: subs,
                }
            }
            4 => {
                let mut p = Cursor::new(&payload);
                let flags = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let seqno = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Hello {
                    flags,
                    seqno,
                    interval,
                    sub_tlvs: subs,
                }
            }
            5 => {
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                p.read_u8().map_err(|e| e.to_string())?;
                let rxcost = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let addr = match ae {
                    1 => {
                        let mut o = [0; 4];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V4(Ipv4Addr::from(o)))
                    }
                    2 | 3 => {
                        let mut o = [0; 16];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V6(Ipv6Addr::from(o)))
                    }
                    _ => None,
                };
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Ihu {
                    ae,
                    rxcost,
                    interval,
                    addr,
                    sub_tlvs: subs,
                }
            }
            6 => {
                let mut p = Cursor::new(&payload);
                p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let mut router_id = [0; 8];
                p.read_exact(&mut router_id).map_err(|e| e.to_string())?;
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::RouterId {
                    router_id,
                    sub_tlvs: subs,
                }
            }
            7 => {
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                p.read_u8().map_err(|e| e.to_string())?;
                let addr = match ae {
                    1 => {
                        let mut o = [0; 4];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V4(Ipv4Addr::from(o)))
                    }
                    2 | 3 => {
                        let mut o = [0; 16];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V6(Ipv6Addr::from(o)))
                    }
                    _ => None,
                };
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::NextHop {
                    ae,
                    addr,
                    sub_tlvs: subs,
                }
            }
            8 => {
                // Update TLV: AE, Flags, PLen, Omitted, Interval, Seqno, Metric, Prefix, Sub-TLVs
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                let flags = p.read_u8().map_err(|e| e.to_string())?;
                let plen = p.read_u8().map_err(|e| e.to_string())?;
                let omitted = p.read_u8().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let seqno = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let metric = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                // Calculate prefix length in bytes
                let prefix_len = ((plen as usize + 7) / 8).saturating_sub(omitted as usize);
                let mut prefix = vec![0u8; prefix_len];
                p.read_exact(&mut prefix).map_err(|e| e.to_string())?;
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Update {
                    ae,
                    flags,
                    plen,
                    omitted,
                    interval,
                    seqno,
                    metric,
                    prefix,
                    sub_tlvs: subs,
                }
            }
            9 => {
                // RouteRequest TLV: AE, PLen, Prefix, Sub-TLVs
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                let plen = p.read_u8().map_err(|e| e.to_string())?;
                let prefix_len = (plen as usize + 7) / 8;
                let mut prefix = vec![0u8; prefix_len];
                p.read_exact(&mut prefix).map_err(|e| e.to_string())?;
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::RouteRequest {
                    ae,
                    plen,
                    prefix,
                    sub_tlvs: subs,
                }
            }
            10 => {
                // SeqnoRequest TLV: AE, PLen, Seqno, HopCount, Reserved, RouterID, Prefix, Sub-TLVs
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                let plen = p.read_u8().map_err(|e| e.to_string())?;
                let seqno = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let hop_count = p.read_u8().map_err(|e| e.to_string())?;
                p.read_u8().map_err(|e| e.to_string())?; // reserved
                let mut router_id = [0u8; 8];
                p.read_exact(&mut router_id).map_err(|e| e.to_string())?;
                let prefix_len = (plen as usize + 7) / 8;
                let mut prefix = vec![0u8; prefix_len];
                p.read_exact(&mut prefix).map_err(|e| e.to_string())?;
                let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::SeqnoRequest {
                    ae,
                    plen,
                    seqno,
                    hop_count,
                    router_id,
                    prefix,
                    sub_tlvs: subs,
                }
            }
            other => Tlv::Unknown {
                tlv_type: other,
                data: payload.clone(),
            },
        };
        Ok(result)
    }

    /// Encode this Tlv into wire-format bytes: type, length, payload, sub-TLVs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Tlv::Pad1 => buf.push(0),
            Tlv::PadN { n } => {
                buf.push(1);
                buf.push(*n as u8);
                let mbz = vec![0; usize::from(*n)];
                buf.extend(mbz);
            }
            Tlv::AckRequest {
                opaque,
                interval,
                sub_tlvs,
            } => {
                buf.push(2);
                let body_len = 6 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.extend(&[0; 2]);
                buf.write_u16::<BigEndian>(*opaque).unwrap();
                buf.write_u16::<BigEndian>(*interval).unwrap();
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Ack { opaque, sub_tlvs } => {
                buf.push(3);
                let body_len = 2 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.write_u16::<BigEndian>(*opaque).unwrap();
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Hello {
                flags,
                seqno,
                interval,
                sub_tlvs,
            } => {
                buf.push(4);
                let body_len = 2 + 2 + 2 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.write_u16::<BigEndian>(*flags).unwrap();
                buf.write_u16::<BigEndian>(*seqno).unwrap();
                buf.write_u16::<BigEndian>(*interval).unwrap();
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Ihu {
                ae,
                rxcost,
                interval,
                addr,
                sub_tlvs,
            } => {
                buf.push(5);
                let addr_len = match addr {
                    Some(IpAddr::V4(_)) => 4,
                    Some(IpAddr::V6(_)) => 16,
                    _ => 0,
                };
                let body_len =
                    1 + 1 + 2 + 2 + addr_len + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(0);
                buf.write_u16::<BigEndian>(*rxcost).unwrap();
                buf.write_u16::<BigEndian>(*interval).unwrap();
                if let Some(a) = addr {
                    match a {
                        IpAddr::V4(v4) => buf.extend(&v4.octets()),
                        IpAddr::V6(v6) => buf.extend(&v6.octets()),
                        _ => {}
                    }
                }
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::RouterId {
                router_id,
                sub_tlvs,
            } => {
                buf.push(6);
                let body_len = 2 + 8 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.extend(&[0, 0]);
                buf.extend(router_id);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::NextHop { ae, addr, sub_tlvs } => {
                buf.push(7);
                let addr_len = match addr {
                    Some(IpAddr::V4(_)) => 4,
                    Some(IpAddr::V6(_)) => 16,
                    _ => 0,
                };
                let body_len = 1 + 1 + addr_len + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(0);
                if let Some(a) = addr {
                    match a {
                        IpAddr::V4(v4) => buf.extend(&v4.octets()),
                        IpAddr::V6(v6) => buf.extend(&v6.octets()),
                        _ => {}
                    }
                }
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Update {
                ae,
                flags,
                plen,
                omitted,
                interval,
                seqno,
                metric,
                prefix,
                sub_tlvs,
            } => {
                buf.push(8);
                let body_len = 1
                    + 1
                    + 1
                    + 1
                    + 2
                    + 2
                    + 2
                    + prefix.len()
                    + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(*flags);
                buf.push(*plen);
                buf.push(*omitted);
                buf.write_u16::<BigEndian>(*interval).unwrap();
                buf.write_u16::<BigEndian>(*seqno).unwrap();
                buf.write_u16::<BigEndian>(*metric).unwrap();
                buf.extend(prefix);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::RouteRequest {
                ae,
                plen,
                prefix,
                sub_tlvs,
            } => {
                buf.push(9);
                let body_len =
                    1 + 1 + prefix.len() + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(*plen);
                buf.extend(prefix);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::SeqnoRequest {
                ae,
                plen,
                seqno,
                hop_count,
                router_id,
                prefix,
                sub_tlvs,
            } => {
                buf.push(10);
                let body_len = 1
                    + 1
                    + 2
                    + 1
                    + 1
                    + 8
                    + prefix.len()
                    + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(*plen);
                buf.write_u16::<BigEndian>(*seqno).unwrap();
                buf.push(*hop_count);
                buf.push(0);
                buf.extend(router_id);
                buf.extend(prefix);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Unknown { tlv_type, data } => {
                buf.push(*tlv_type);
                buf.push(data.len() as u8);
                buf.extend(data);
            }
        }
        buf
    }
}

impl SubTlv {
    /// Parse a sequence of sub-TLVs from a slice.
    /// Stops at end-of-buffer; errors on malformed fields.
    pub fn parse_list(buf: &[u8]) -> Result<Vec<SubTlv>, String> {
        let mut out = Vec::new();
        let mut cur = Cursor::new(buf);

        while (cur.position() as usize) < buf.len() {
            let stype = cur.read_u8().map_err(|e| e.to_string())?;

            if stype == 0 {
                // Pad1: single byte, no length
                out.push(SubTlv::Pad1);
                continue;
            }

            let slen = cur.read_u8().map_err(|e| e.to_string())? as usize;
            let mut data = vec![0u8; slen];
            cur.read_exact(&mut data).map_err(|e| e.to_string())?;

            let s = match stype {
                1 => {
                    // PadN sub-TLV: content is MBZ, we only keep the count
                    SubTlv::PadN { n: slen as u8 }
                }
                other => SubTlv::Unknown { stype: other, data },
            };

            out.push(s);
        }

        Ok(out)
    }

    /// Compute the full wire length of this sub-TLV (including header).
    fn len(&self) -> usize {
        match self {
            SubTlv::Pad1 => 1,
            SubTlv::PadN { n } => 2 + (*n as usize),
            SubTlv::Unknown { data, .. } => 2 + data.len(),
        }
    }

    /// Serialize this sub-TLV into wire-format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            SubTlv::Pad1 => buf.push(0),
            SubTlv::PadN { n } => {
                buf.push(1);
                buf.push(*n as u8);
                let mbz = vec![0; usize::from(*n)];
                buf.extend(mbz);
            }
            SubTlv::Unknown { stype, data } => {
                buf.push(*stype);
                buf.push(data.len() as u8);
                buf.extend(data);
            }
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // --- Basic TLVs ---

    #[test]
    fn pad1_to_bytes() {
        let pad1 = Tlv::Pad1;
        assert_eq!(pad1.to_bytes(), vec![0]);
    }

    #[test]
    fn padn_to_bytes() {
        let pad4 = Tlv::PadN { n: 4 };
        assert_eq!(pad4.to_bytes(), vec![1, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn padn_roundtrip() {
        let original = Tlv::PadN { n: 3 };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn ack_request_to_bytes() {
        let ackreq = Tlv::AckRequest {
            opaque: 278,
            interval: 400,
            sub_tlvs: Vec::new(),
        };
        assert_eq!(ackreq.to_bytes(), vec![2, 6, 0, 0, 1, 22, 1, 144]);
    }

    #[test]
    fn ack_to_bytes() {
        let ack = Tlv::Ack {
            opaque: 278,
            sub_tlvs: Vec::new(),
        };
        assert_eq!(ack.to_bytes(), vec![3, 2, 1, 22]);
    }

    #[test]
    fn hello_to_bytes() {
        let hello = Tlv::Hello {
            flags: 0,
            seqno: 278,
            interval: 400,
            sub_tlvs: Vec::new(),
        };
        assert_eq!(hello.to_bytes(), vec![4, 6, 0, 0, 1, 22, 1, 144]);
    }

    #[test]
    fn hello_roundtrip() {
        let original = Tlv::Hello {
            flags: 0x0102,
            seqno: 0x2030,
            interval: 1000,
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    // --- TLVs with addresses ---

    #[test]
    fn ihu_ipv4_roundtrip() {
        let original = Tlv::Ihu {
            ae: 1,
            rxcost: 256,
            interval: 200,
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn ihu_ipv6_roundtrip() {
        let original = Tlv::Ihu {
            ae: 2,
            rxcost: 100,
            interval: 50,
            addr: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn nexthop_ipv4_roundtrip() {
        let original = Tlv::NextHop {
            ae: 1,
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn router_id_roundtrip() {
        let original = Tlv::RouterId {
            router_id: [1, 2, 3, 4, 5, 6, 7, 8],
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    // --- Prefix-carrying TLVs ---

    #[test]
    fn update_roundtrip_simple_prefix() {
        // /24 IPv4-like prefix: 192.0.2.0/24 -> 3 bytes of prefix
        let original = Tlv::Update {
            ae: 1,
            flags: 0,
            plen: 24,
            omitted: 0,
            interval: 500,
            seqno: 10,
            metric: 256,
            prefix: vec![192, 0, 2],
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn route_request_roundtrip() {
        let original = Tlv::RouteRequest {
            ae: 1,
            plen: 16,
            prefix: vec![10, 0],
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn seqno_request_roundtrip() {
        let original = Tlv::SeqnoRequest {
            ae: 1,
            plen: 24,
            seqno: 42,
            hop_count: 3,
            router_id: [0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4],
            prefix: vec![192, 0, 2],
            sub_tlvs: Vec::new(),
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    // --- Unknown TLV ---

    #[test]
    fn unknown_tlv_roundtrip() {
        let original = Tlv::Unknown {
            tlv_type: 250,
            data: vec![1, 2, 3, 4],
        };
        let bytes = original.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, original);
    }

    // --- Sub-TLVs ---

    #[test]
    fn subtlv_pad1_to_bytes_and_parse() {
        let st = SubTlv::Pad1;
        let bytes = st.to_bytes();
        assert_eq!(bytes, vec![0]);

        let parsed = SubTlv::parse_list(&bytes).unwrap();
        assert_eq!(parsed, vec![SubTlv::Pad1]);
    }

    #[test]
    fn subtlv_padn_to_bytes_and_parse() {
        let st = SubTlv::PadN { n: 3 };
        let bytes = st.to_bytes();
        // type=1, len=3, then 3 MBZ bytes
        assert_eq!(bytes, vec![1, 3, 0, 0, 0]);

        let parsed = SubTlv::parse_list(&bytes).unwrap();
        assert_eq!(parsed, vec![SubTlv::PadN { n: 3 }]);
    }

    #[test]
    fn subtlv_unknown_roundtrip() {
        let st = SubTlv::Unknown {
            stype: 99,
            data: vec![0xaa, 0xbb],
        };
        let bytes = st.to_bytes();
        let parsed = SubTlv::parse_list(&bytes).unwrap();
        assert_eq!(parsed, vec![st]);
    }

    #[test]
    fn tlv_with_subtlvs_roundtrip() {
        let hello = Tlv::Hello {
            flags: 1,
            seqno: 2,
            interval: 3,
            sub_tlvs: vec![
                SubTlv::Pad1,
                SubTlv::PadN { n: 2 },
                SubTlv::Unknown {
                    stype: 10,
                    data: vec![0xde, 0xad],
                },
            ],
        };

        let bytes = hello.to_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let parsed = Tlv::parse(&mut cur).unwrap();
        assert_eq!(parsed, hello);
    }

    // --- parse_all ---

    #[test]
    fn parse_all_multiple_tlvs() {
        let t1 = Tlv::Pad1;
        let t2 = Tlv::PadN { n: 2 };
        let t3 = Tlv::Ack {
            opaque: 42,
            sub_tlvs: Vec::new(),
        };

        let mut buf = Vec::new();
        buf.extend(t1.to_bytes());
        buf.extend(t2.to_bytes());
        buf.extend(t3.to_bytes());

        let parsed = Tlv::parse_all(&buf).unwrap();
        assert_eq!(parsed, vec![t1, t2, t3]);
    }
}

