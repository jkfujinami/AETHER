//! Onion パケット（Sphinx 方式の固定長ヘッダ）
//!
//! # なぜ固定長か
//!
//! 素朴な層構造（各層 = 一時鍵 + nonce + 暗号文）は、ホップを 1 つ剥がすたびに
//! パケットが一定量ずつ短くなる。中継は受け取った長さから「自分は何番目か・残り何ホップか」
//! が分かり、入口と出口を突き合わせる足場になる。ここでは
//!
//! - **ヘッダは固定長**。各ホップは自分の分を読んだら先頭を詰め、末尾に擬似乱数を足して
//!   同じ長さに戻す（送信者は後のホップが足す分を先に計算して MAC に含める＝filler）。
//! - **本文は長さを変えないストリーム暗号**で層を重ね、改ざんは出口の AEAD で検出する。
//!
//! どのホップから見ても、パケットは同じ長さ・同じ形になる。
//!
//! # その他
//!
//! - **一時鍵はパケットごとに作り直す。** 回路で使い回すと、中継が同じ回路のパケットを
//!   公開鍵で結び付けられる。
//! - **経路情報に時刻を入れる。** 古いパケットの再送は時刻で弾き、窓の中の再送は
//!   一時公開鍵を覚えて弾く（[`crate::node::router`]）。
//! - **鍵は DH の出力を HKDF で用途ごとに分けてから使う**（ヘッダ・MAC・本文）。
//!
//! # ワイヤ形式
//!
//! ```text
//! [α 一時公開鍵 32][γ MAC 16][β 経路ブロック HEADER_BLOCK][本文 (バケット長 + 16)]
//! ```
//!
//! β は各ホップ分のスロット（経路 24 + 次の α 32 + 次の γ 16 = 72）を最大 [`MAX_HOPS`] 個並べた長さ。

use crate::error::{AetherError, Result};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Onion 回路の最大ホップ数
pub const MAX_HOPS: usize = 3;

/// 経路情報の長さ: [種別 1][次のアドレス 18][時刻(分) 4][予約 1]
const ROUTE_LEN: usize = 24;
/// 1 ホップ分のスロット: 経路 + 次の α + 次の γ
const SLOT: usize = ROUTE_LEN + 32 + MAC_LEN;
/// 経路ブロック β の長さ
const HEADER_BLOCK: usize = MAX_HOPS * SLOT;
const MAC_LEN: usize = 16;
/// ヘッダ全体の長さ
pub const HEADER_LEN: usize = 32 + MAC_LEN + HEADER_BLOCK;
/// 本文の AEAD タグ
const TAG_LEN: usize = 16;

const ROUTE_FORWARD: u8 = 0x01;
const ROUTE_EXIT: u8 = 0x00;

/// 経路の時刻と受け手の時計のずれをどこまで許すか（分）
///
/// これより古いパケットは再送とみなして捨てる。窓の中の再送は一時公開鍵で弾く。
pub const MAX_CLOCK_SKEW_MINUTES: u32 = 10;

/// 本文の最小サイズ（これ未満は切り上げる）
///
/// Hint・MailboxGet・小さな私信シャードは全部この 1 バケットに収まり、
/// 中継から見て区別できなくなる。
const MIN_PADDED_LEN: usize = 1024;

/// これを超えるとバケットを 2 の冪でなくこの刻みにする（大きな本体で倍近く膨らませない）
const LARGE_PAD_STEP: usize = 256 * 1024;

/// 本文を切り上げるバケットの大きさ
///
/// **中継は転送するパケットの長さを見ている。** 長さが中身そのままだと役割の分類と
/// セッション相関の足場になる。1KB から 2 の冪、256KB 超は 256KB 刻みに正規化する。
pub fn padded_len(n: usize) -> usize {
    if n <= MIN_PADDED_LEN {
        MIN_PADDED_LEN
    } else if n <= LARGE_PAD_STEP {
        n.next_power_of_two()
    } else {
        n.div_ceil(LARGE_PAD_STEP) * LARGE_PAD_STEP
    }
}

/// ホップごとの鍵（DH の出力から HKDF で用途別に導出）
struct HopKeys {
    header: [u8; 32],
    mac: [u8; 32],
    payload: [u8; 32],
}

impl HopKeys {
    fn derive(shared: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"aether_onion_v2"), shared);
        let mut k = Self {
            header: [0; 32],
            mac: [0; 32],
            payload: [0; 32],
        };
        hk.expand(b"header", &mut k.header).expect("32 バイトは HKDF の上限内");
        hk.expand(b"mac", &mut k.mac).expect("32 バイトは HKDF の上限内");
        hk.expand(b"payload", &mut k.payload).expect("32 バイトは HKDF の上限内");
        k
    }
}

/// 鍵ストリーム（鍵はパケットごとに一度きりなので nonce は 0 固定でよい）
fn keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    xor_stream(key, &mut buf);
    buf
}

fn xor_stream(key: &[u8; 32], data: &mut [u8]) {
    let mut c = ChaCha20::new(key.into(), &[0u8; 12].into());
    c.apply_keystream(data);
}

fn mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC は任意長の鍵を取れる");
    m.update(data);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// アドレスを固定 18 バイトにする（v4 は v6 写像。長さで v4/v6 が漏れない）
fn encode_addr(addr: &SocketAddr) -> [u8; 18] {
    let v6 = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    let mut out = [0u8; 18];
    out[..16].copy_from_slice(&v6.octets());
    out[16..].copy_from_slice(&addr.port().to_be_bytes());
    out
}

fn decode_addr(b: &[u8]) -> SocketAddr {
    let octets: [u8; 16] = b[..16].try_into().expect("16 バイト");
    let port = u16::from_be_bytes([b[16], b[17]]);
    let v6 = Ipv6Addr::from(octets);
    let ip = match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    };
    SocketAddr::new(ip, port)
}

fn now_minutes() -> u32 {
    (crate::protocol::hint::current_timestamp() / 60) as u32
}

fn encode_route(next: Option<&SocketAddr>, minute: u32) -> [u8; ROUTE_LEN] {
    let mut r = [0u8; ROUTE_LEN];
    match next {
        Some(addr) => {
            r[0] = ROUTE_FORWARD;
            r[1..19].copy_from_slice(&encode_addr(addr));
        }
        None => r[0] = ROUTE_EXIT,
    }
    r[19..23].copy_from_slice(&minute.to_be_bytes());
    r
}

/// 回路内の各ホップ
#[derive(Debug, Clone)]
struct Hop {
    addr: SocketAddr,
    pubkey: [u8; 32],
}

/// クライアント側の Onion 回路（経路と各ホップの公開鍵）
///
/// 一時鍵は持たない。パケットごとに作り直す。
#[derive(Debug, Clone, Default)]
pub struct OnionCircuit {
    hops: Vec<Hop>,
}

impl OnionCircuit {
    pub fn new() -> Self {
        Self::default()
    }

    /// ホップを追加する（入口から順に）
    pub fn add_hop(&mut self, addr: SocketAddr, peer_pubkey: [u8; 32]) -> Result<()> {
        if self.hops.len() >= MAX_HOPS {
            return Err(AetherError::Config(format!(
                "Onion circuit supports at most {} hops",
                MAX_HOPS
            )));
        }
        self.hops.push(Hop {
            addr,
            pubkey: peer_pubkey,
        });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// ペイロードを Onion で包む（入口へそのまま送る形）
    ///
    /// 最終宛先は Onion 層ではなく最内層のペイロード（`InnerPacketType`）が持つ。
    /// 出口リレーだけがそれを読める。
    pub fn wrap_packet(&self, final_payload: &[u8]) -> Result<Vec<u8>> {
        self.wrap_at(final_payload, now_minutes())
    }

    fn wrap_at(&self, final_payload: &[u8], minute: u32) -> Result<Vec<u8>> {
        let n = self.hops.len();
        if n == 0 {
            return Err(AetherError::Config("No hops in circuit".into()));
        }

        // --- ホップごとに新しい一時鍵で共有秘密を作る ---
        let mut alphas = Vec::with_capacity(n);
        let mut keys = Vec::with_capacity(n);
        for hop in &self.hops {
            let eph = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
            alphas.push(PublicKey::from(&eph).to_bytes());
            let shared = eph.diffie_hellman(&PublicKey::from(hop.pubkey)).to_bytes();
            keys.push(HopKeys::derive(&shared));
        }

        // --- filler：後のホップが末尾に足す擬似乱数を先に計算しておく ---
        let mut filler: Vec<u8> = Vec::new();
        for k in keys.iter().take(n - 1) {
            let stream = keystream(&k.header, HEADER_BLOCK + SLOT);
            filler.extend_from_slice(&[0u8; SLOT]);
            let from = HEADER_BLOCK + SLOT - filler.len();
            xor_into(&mut filler, &stream[from..]);
        }

        // --- 最内（出口）から外へ β と γ を組む ---
        let last = n - 1;
        let mut beta = {
            let mut plain = vec![0u8; HEADER_BLOCK - filler.len()];
            plain[..ROUTE_LEN].copy_from_slice(&encode_route(None, minute));
            // 経路の後ろ（未使用部分）は乱数で埋める（0 だと出口にホップ数の手掛かりを与える）
            rand::Rng::fill(&mut rand::thread_rng(), &mut plain[SLOT..]);
            let stream = keystream(&keys[last].header, plain.len());
            xor_into(&mut plain, &stream);
            plain.extend_from_slice(&filler);
            plain
        };
        let mut gamma = mac(&keys[last].mac, &beta);

        for i in (0..last).rev() {
            let mut plain = Vec::with_capacity(HEADER_BLOCK);
            plain.extend_from_slice(&encode_route(Some(&self.hops[i + 1].addr), minute));
            plain.extend_from_slice(&alphas[i + 1]);
            plain.extend_from_slice(&gamma);
            plain.extend_from_slice(&beta[..HEADER_BLOCK - SLOT]);
            let stream = keystream(&keys[i].header, HEADER_BLOCK);
            xor_into(&mut plain, &stream);
            beta = plain;
            gamma = mac(&keys[i].mac, &beta);
        }

        // --- 本文：出口向けに AEAD で封じ、残りのホップ分を長さの変わらない暗号で重ねる ---
        let len = u32::try_from(final_payload.len())
            .map_err(|_| AetherError::Protocol("Onion payload too large".into()))?;
        let bucket = padded_len(4 + final_payload.len());
        let mut inner = Vec::with_capacity(bucket);
        inner.extend_from_slice(&len.to_be_bytes());
        inner.extend_from_slice(final_payload);
        let mut pad = vec![0u8; bucket - inner.len()];
        rand::Rng::fill(&mut rand::thread_rng(), &mut pad[..]);
        inner.extend_from_slice(&pad);

        let mut body = ChaCha20Poly1305::new((&keys[last].payload).into())
            .encrypt(&[0u8; 12].into(), inner.as_slice())
            .map_err(|e| AetherError::Crypto(format!("Onion payload seal failed: {}", e)))?;
        for k in keys.iter().take(last) {
            xor_stream(&k.payload, &mut body);
        }

        let mut packet = Vec::with_capacity(HEADER_LEN + body.len());
        packet.extend_from_slice(&alphas[0]);
        packet.extend_from_slice(&gamma);
        packet.extend_from_slice(&beta);
        packet.extend_from_slice(&body);
        Ok(packet)
    }
}

/// 中継が 1 層を処理した結果
#[derive(Debug)]
pub enum OnionAction {
    /// 次のホップへ送る（長さは受け取ったものと同じ）
    Forward { next: SocketAddr, packet: Vec<u8> },
    /// 自分が出口。中身（`InnerPacketType` 付きのペイロード）
    Exit { payload: Vec<u8> },
}

/// 受け取ったパケットの 1 層を処理する（中継・出口用）
///
/// 返り値の先頭は**このパケットの一時公開鍵 α**。再送検出の鍵にする
/// （パケットごとに作り直されるので、同じ α が 2 度来たら再送）。
pub fn process_layer(secret: &StaticSecret, packet: &[u8]) -> Result<([u8; 32], OnionAction)> {
    process_layer_at(secret, packet, now_minutes())
}

fn process_layer_at(
    secret: &StaticSecret,
    packet: &[u8],
    now_minute: u32,
) -> Result<([u8; 32], OnionAction)> {
    if packet.len() < HEADER_LEN + TAG_LEN {
        return Err(AetherError::Crypto("Onion packet too short".into()));
    }
    let alpha: [u8; 32] = packet[..32].try_into().expect("長さ確認済み");
    let gamma = &packet[32..32 + MAC_LEN];
    let beta = &packet[32 + MAC_LEN..HEADER_LEN];
    let body = &packet[HEADER_LEN..];

    let shared = secret.diffie_hellman(&PublicKey::from(alpha)).to_bytes();
    let keys = HopKeys::derive(&shared);

    // ヘッダの改ざんを先に弾く（γ は定数時間比較）
    use subtle::ConstantTimeEq;
    if !bool::from(mac(&keys.mac, beta).ct_eq(gamma)) {
        return Err(AetherError::Crypto("Onion header MAC mismatch".into()));
    }

    // β を復号し、先頭のスロットを読む。末尾には擬似乱数を足して長さを戻す
    let mut plain = beta.to_vec();
    plain.extend_from_slice(&[0u8; SLOT]);
    let stream = keystream(&keys.header, HEADER_BLOCK + SLOT);
    xor_into(&mut plain, &stream);

    let route = &plain[..ROUTE_LEN];
    let minute = u32::from_be_bytes(route[19..23].try_into().expect("4 バイト"));
    if now_minute.abs_diff(minute) > MAX_CLOCK_SKEW_MINUTES {
        return Err(AetherError::Protocol("Onion packet outside the time window".into()));
    }

    match route[0] {
        ROUTE_EXIT => {
            let inner = ChaCha20Poly1305::new((&keys.payload).into())
                .decrypt(&[0u8; 12].into(), body)
                .map_err(|_| AetherError::Crypto("Onion payload authentication failed".into()))?;
            let len = u32::from_be_bytes(inner[..4].try_into().expect("バケットは 4 バイト以上")) as usize;
            let payload = inner
                .get(4..4 + len)
                .ok_or_else(|| AetherError::Protocol("Onion payload length out of range".into()))?
                .to_vec();
            Ok((alpha, OnionAction::Exit { payload }))
        }
        ROUTE_FORWARD => {
            let next = decode_addr(&route[1..19]);
            let mut out = Vec::with_capacity(packet.len());
            out.extend_from_slice(&plain[ROUTE_LEN..ROUTE_LEN + 32]); // 次の α
            out.extend_from_slice(&plain[ROUTE_LEN + 32..SLOT]); // 次の γ
            out.extend_from_slice(&plain[SLOT..SLOT + HEADER_BLOCK]); // 次の β
            let mut next_body = body.to_vec();
            xor_stream(&keys.payload, &mut next_body);
            out.extend_from_slice(&next_body);
            Ok((alpha, OnionAction::Forward { next, packet: out }))
        }
        other => Err(AetherError::Protocol(format!("Unknown onion route type 0x{:02x}", other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relays(n: usize) -> (OnionCircuit, Vec<StaticSecret>, Vec<SocketAddr>) {
        let mut circuit = OnionCircuit::new();
        let mut secrets = Vec::new();
        let mut addrs = Vec::new();
        for i in 0..n {
            let s = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let addr: SocketAddr = if i == 1 {
                "[2001:db8::7]:9443".parse().unwrap()
            } else {
                format!("10.0.0.{}:900{}", i + 1, i).parse().unwrap()
            };
            circuit.add_hop(addr, PublicKey::from(&s).to_bytes()).unwrap();
            secrets.push(s);
            addrs.push(addr);
        }
        (circuit, secrets, addrs)
    }

    /// 回路を端から端まで流し、各ホップで見えた (長さ, 次の宛先) と出口の中身を返す
    fn traverse(packet: Vec<u8>, secrets: &[StaticSecret]) -> (Vec<usize>, Vec<SocketAddr>, Vec<u8>) {
        let mut lens = Vec::new();
        let mut nexts = Vec::new();
        let mut current = packet;
        for (i, s) in secrets.iter().enumerate() {
            lens.push(current.len());
            match process_layer(s, &current).unwrap().1 {
                OnionAction::Forward { next, packet } => {
                    assert!(i + 1 < secrets.len(), "出口が転送しようとした");
                    nexts.push(next);
                    current = packet;
                }
                OnionAction::Exit { payload } => {
                    assert_eq!(i + 1, secrets.len(), "出口より手前で終わった");
                    return (lens, nexts, payload);
                }
            }
        }
        panic!("出口に着かなかった");
    }

    #[test]
    fn three_hop_roundtrip_with_constant_length() {
        let (circuit, secrets, addrs) = relays(3);
        let msg = b"three hops, same length at every hop".to_vec();
        let (lens, nexts, out) = traverse(circuit.wrap_packet(&msg).unwrap(), &secrets);

        assert_eq!(out, msg);
        assert_eq!(nexts, vec![addrs[1], addrs[2]], "v6 のアドレスも正しく運ぶ");
        assert!(lens.windows(2).all(|w| w[0] == w[1]), "ホップごとに長さが変わった: {:?}", lens);
    }

    #[test]
    fn packet_length_does_not_reveal_hop_count() {
        // 1 ホップと 3 ホップで、入口が見る長さは同じ（ヘッダは常に MAX_HOPS 分）
        let (c1, _, _) = relays(1);
        let (c3, _, _) = relays(3);
        let msg = [0u8; 100];
        assert_eq!(c1.wrap_packet(&msg).unwrap().len(), c3.wrap_packet(&msg).unwrap().len());
    }

    #[test]
    fn small_payloads_are_indistinguishable_by_length() {
        let (circuit, _, _) = relays(3);
        let a = circuit.wrap_packet(&[0x10; 40]).unwrap();
        let b = circuit.wrap_packet(&[0x21; 700]).unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn fresh_ephemeral_key_per_packet() {
        // 同じ回路のパケットを中継が α で結び付けられないこと
        let (circuit, _, _) = relays(3);
        let a = circuit.wrap_packet(b"x").unwrap();
        let b = circuit.wrap_packet(b"x").unwrap();
        assert_ne!(a[..32], b[..32]);
    }

    #[test]
    fn tampered_header_is_rejected() {
        let (circuit, secrets, _) = relays(3);
        let mut p = circuit.wrap_packet(b"x").unwrap();
        p[40] ^= 1; // γ
        assert!(process_layer(&secrets[0], &p).is_err());
        let mut p = circuit.wrap_packet(b"x").unwrap();
        p[100] ^= 1; // β
        assert!(process_layer(&secrets[0], &p).is_err());
    }

    #[test]
    fn tampered_payload_is_caught_at_the_exit() {
        let (circuit, secrets, _) = relays(3);
        let mut p = circuit.wrap_packet(b"secret").unwrap();
        let last = p.len() - 1;
        p[last] ^= 1;
        let OnionAction::Forward { packet: p, .. } = process_layer(&secrets[0], &p).unwrap().1 else {
            panic!()
        };
        let OnionAction::Forward { packet: p, .. } = process_layer(&secrets[1], &p).unwrap().1 else {
            panic!()
        };
        assert!(process_layer(&secrets[2], &p).is_err(), "改ざんされた本文を出口が受け取った");
    }

    #[test]
    fn wrong_relay_cannot_open_the_layer() {
        let (circuit, _, _) = relays(3);
        let stranger = StaticSecret::random_from_rng(rand::rngs::OsRng);
        assert!(process_layer(&stranger, &circuit.wrap_packet(b"x").unwrap()).is_err());
    }

    #[test]
    fn stale_packets_are_rejected() {
        let (circuit, secrets, _) = relays(1);
        let now = now_minutes();
        let old = circuit.wrap_at(b"x", now - MAX_CLOCK_SKEW_MINUTES - 1).unwrap();
        assert!(process_layer_at(&secrets[0], &old, now).is_err());
        let fresh = circuit.wrap_at(b"x", now - 1).unwrap();
        assert!(process_layer_at(&secrets[0], &fresh, now).is_ok());
    }

    #[test]
    fn padding_is_stripped_at_the_exit() {
        let (circuit, secrets, _) = relays(2);
        for size in [0usize, 1, 1019, 1020, 5000, 300 * 1024] {
            let msg: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let (_, _, out) = traverse(circuit.wrap_packet(&msg).unwrap(), &secrets);
            assert_eq!(out, msg, "size {}", size);
        }
    }

    #[test]
    fn padded_len_buckets() {
        assert_eq!(padded_len(0), 1024);
        assert_eq!(padded_len(1024), 1024);
        assert_eq!(padded_len(1025), 2048);
        assert_eq!(padded_len(200 * 1024), 256 * 1024);
        assert_eq!(padded_len(256 * 1024 + 1), 512 * 1024);
        assert_eq!(padded_len(1024 * 1024 + 1), 1024 * 1024 + 256 * 1024);
    }

    #[test]
    fn too_many_hops_is_an_error() {
        let (mut circuit, _, _) = relays(3);
        assert!(circuit.add_hop("10.0.0.9:9".parse().unwrap(), [1; 32]).is_err());
    }
}
