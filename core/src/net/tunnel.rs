//! I2P風 Inbound Tunnel 実装
//!
//! 受信専用のトンネルを構築し、送信者に Gateway アドレスだけを公開する。
//! これにより、送信者は受信者の実IPを知ることなくメッセージを送れる。
//!
//! # 長さを変えない
//!
//! 各ホップが AEAD で包み直すと、1 ホップごとに nonce とタグの分だけ長くなり、
//! 中継は長さから「自分は gateway から何番目か」を知れる。ここでは
//!
//! - **gateway**（外からデータを受ける最初のホップ）が長さをバケットに切り上げ、乱数の nonce を付ける
//! - **以降のホップ**は長さを変えないストリーム暗号を重ね、nonce をホップ固有の値で置き換える
//!
//! どのホップから見ても `[nonce 12][本文 (バケット長)]` で同じ長さになり、隣り合わない
//! ホップどうしは nonce でメッセージを突き合わせられない。改ざんは中継では検出しない
//! （本体のシャードは封で守られていて、終端で弾かれる）。
//!
//! gateway かどうかは、**gateway 用の tunnel_id の先頭ビット**で示す（[`GATEWAY_ID_BIT`]）。

use crate::error::{Result, AetherError};
use crate::crypto::{key_exchange, cipher};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// 登録済みトンネルの有効期間
///
/// これが無いと、10分ごとの張り替えでも古いエントリが溜まり続け、
/// かつ誰でも任意の ID を登録できるので無制限の蓄積 DoS になる。
/// 過ぎたものは `process_tunnel_data` で無効扱いにし、登録時にも掃除する。
const TUNNEL_TTL: Duration = Duration::from_secs(30 * 60);

/// 登録を受け付けるトンネル数の上限
///
/// TTL だけでは、TTL 内に大量登録されると防げない。
const MAX_TUNNELS: usize = 100_000;

/// gateway 用の tunnel_id は先頭バイトの最下位ビットが 1（他のホップは 0）
///
/// gateway は外（保持者）から素のデータを受け、他のホップは `[nonce][本文]` を受ける。
/// どちらの形かを受け手が知るための取り決め。
pub const GATEWAY_ID_BIT: u8 = 0x01;

/// トンネルの nonce の長さ
const NONCE_LEN: usize = 12;

fn is_gateway_id(id: &[u8; 32]) -> bool {
    id[0] & GATEWAY_ID_BIT != 0
}

/// DH の出力から、用途ごとの鍵を HKDF で導出する
struct TunnelKeys {
    /// 本文のストリーム暗号の鍵
    stream: [u8; 32],
    /// 次のホップへ渡す nonce を作るための値（nonce をこれで XOR する）
    nonce_mask: [u8; NONCE_LEN],
}

impl TunnelKeys {
    fn derive(shared: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"aether_tunnel_v2"), shared);
        let mut k = Self {
            stream: [0; 32],
            nonce_mask: [0; NONCE_LEN],
        };
        hk.expand(b"stream", &mut k.stream).expect("HKDF の上限内");
        hk.expand(b"nonce", &mut k.nonce_mask).expect("HKDF の上限内");
        k
    }
}

/// 構築指示を封じる鍵（DH の出力をそのまま使わない）
fn instruction_key(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"aether_tunnel_v2"), shared);
    let mut k = [0u8; 32];
    hk.expand(b"instruction", &mut k).expect("HKDF の上限内");
    k
}

fn xor_stream(key: &[u8; 32], nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    ChaCha20::new(key.into(), nonce.into()).apply_keystream(data);
}

fn xor_nonce(n: &[u8; NONCE_LEN], mask: &[u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
    let mut out = *n;
    for (o, m) in out.iter_mut().zip(mask) {
        *o ^= m;
    }
    out
}

/// 受け取った構築指示を開く（中継ノード用）
///
/// 形式: `[TunnelID 32][一時公開鍵 32][Nonce 12][暗号化された HopInstruction]`。
/// 返り値の共有秘密は [`TunnelRelay::register_tunnel`] に渡す。
pub fn open_build(secret: &StaticSecret, payload: &[u8]) -> Result<([u8; 32], [u8; 32], HopInstruction)> {
    if payload.len() < 32 + 32 + NONCE_LEN {
        return Err(AetherError::Protocol("TunnelBuild packet too short".into()));
    }
    let tunnel_id: [u8; 32] = payload[0..32].try_into().expect("長さ確認済み");
    let eph: [u8; 32] = payload[32..64].try_into().expect("長さ確認済み");
    let nonce: [u8; NONCE_LEN] = payload[64..76].try_into().expect("長さ確認済み");
    let shared = secret.diffie_hellman(&PublicKey::from(eph)).to_bytes();
    let plain = cipher::decrypt(&instruction_key(&shared), &nonce, &payload[76..])?;
    let inst: HopInstruction = bincode::deserialize(&plain)
        .map_err(|e| AetherError::Protocol(format!("Invalid instruction: {}", e)))?;
    Ok((tunnel_id, shared, inst))
}

/// トンネル構築の結果: (トンネル本体, 各ホップへの命令)
pub type BuildResult = Result<(InboundTunnel, Vec<(SocketAddr, Vec<u8>)>)>;

/// 中継情報の詳細: (中継先アドレス, 中継用識別子, 暗号化済みデータ)
pub type ForwardingInstruction = (SocketAddr, [u8; 32], Vec<u8>);

/// Inbound Tunnel の公開情報
/// これを他のノードに伝えることで、相手はこのトンネル経由でメッセージを送れる
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEndpoint {
    /// トンネルの入口 (Gateway) アドレス
    pub gateway: SocketAddr,

    /// トンネル識別子 (Gateway がルーティングに使用)
    pub tunnel_id: [u8; 32],
}

/// Inbound Tunnel の構築情報 (所有者のみが持つ)
#[derive(Debug)]
pub struct InboundTunnel {
    /// 公開情報
    pub endpoint: TunnelEndpoint,

    /// 各ホップでの復号に必要な共有秘密 (自分に近い順)
    /// 最後の要素が Gateway との共有秘密
    decrypt_keys: Vec<[u8; 32]>,

    /// 自分が受信する際の Tunnel ID (Alice が待ち受ける ID)
    pub receive_tunnel_id: [u8; 32],

    /// トンネル経路 (デバッグ用、運用時は持たなくてもよい)
    #[allow(dead_code)]
    path: Vec<SocketAddr>,
}

/// トンネル内を流れるデータのヘッダ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelHeader {
    /// トンネル識別子
    pub tunnel_id: [u8; 32],

    /// 一時公開鍵 (各ホップでの鍵導出用)
    pub ephemeral_pk: [u8; 32],
}

/// 各ホップが持つ、次のホップへの転送情報
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInstruction {
    /// 次のホップのアドレス
    ///
    /// `None` は「この TunnelBuild を運んできた接続の相手へ返す」。
    /// 終端の手前（ガード）が、NAT の内側にいる構築者へ届けるのに使う。
    pub next_hop: Option<SocketAddr>,

    /// 次のホップ用の tunnel_id
    pub next_tunnel_id: [u8; 32],
}

impl InboundTunnel {
    /// 新しい Inbound Tunnel を構築する
    ///
    /// # Arguments
    /// * `path` - トンネル経路 (Gateway, Relay1, Relay2, ..., 最後が自分)
    ///   最低2ホップ必要 (Gateway + 自分)
    /// * `hop_pubkeys` - 各ホップの公開鍵 (path と同じ順序、自分も含む)
    ///
    /// # Returns
    /// * `InboundTunnel` - 構築されたトンネル
    /// * `Vec<(SocketAddr, Vec<u8>)>` - 各ホップへ配布するべき暗号化命令
    pub fn build(
        path: Vec<SocketAddr>,
        hop_pubkeys: Vec<[u8; 32]>,
    ) -> BuildResult {
        Self::build_inner(path, hop_pubkeys, false)
    }

    /// 終端（自分）の手前のホップが「構築指示を送ってきた接続」へ返す Inbound Tunnel
    ///
    /// `path` の最後は自分。その手前（通常はガード）の指示は `next_hop = None` になり、
    /// 受けたノードは**TunnelBuild を運んできた接続の送信元**へ転送する
    /// （[`HopInstruction::next_hop`] 参照）。そのホップへの指示は自分で直接送ること。
    ///
    /// 自分の広告アドレスが無い／NAT の内側でも受信できる。アドレス宛てに返させると、
    /// 一回限りのクライアント（広告アドレス 127.0.0.1）には届かない。
    pub fn build_to_builder(
        path: Vec<SocketAddr>,
        hop_pubkeys: Vec<[u8; 32]>,
    ) -> BuildResult {
        if path.len() < 3 {
            return Err(AetherError::Config(
                "Builder-terminated tunnel needs at least one relay before the last hop".into(),
            ));
        }
        Self::build_inner(path, hop_pubkeys, true)
    }

    fn build_inner(
        path: Vec<SocketAddr>,
        hop_pubkeys: Vec<[u8; 32]>,
        return_to_builder: bool,
    ) -> BuildResult {
        if path.len() < 2 {
            return Err(AetherError::Config("Tunnel path must have at least 2 hops".into()));
        }
        if hop_pubkeys.len() != path.len() {
            return Err(AetherError::Config("hop_pubkeys length mismatch".into()));
        }

        let mut decrypt_keys = Vec::new();
        let mut hop_instructions: Vec<(SocketAddr, Vec<u8>)> = Vec::new();

        // トンネルIDを生成（gateway 用は先頭ビットを立てる）
        let mut tunnel_id: [u8; 32] = rand::random();
        tunnel_id[0] |= GATEWAY_ID_BIT;

        // Alice が受信する際の Tunnel ID を保存
        let mut receive_tunnel_id = [0u8; 32];

        // 各ホップ用の命令を構築 (逆順: 終端から Gateway へ)
        // path: [Gateway, Relay1, Relay2, Self]
        // pubkeys: [Gateway_pk, Relay1_pk, Relay2_pk]

        // 次のホップへ渡すためのTunnelID (初期値はAlice=自分向けなのでダミー [0;32])
        let mut next_hop_tunnel_id = [0u8; 32];

        for i in (0..hop_pubkeys.len()).rev() {
            let hop_addr = path[i];
            let hop_pk_bytes = hop_pubkeys[i];
            let hop_pk = PublicKey::from(hop_pk_bytes);

            // 自分が待ち受けるID
            let listen_tunnel_id = if i == 0 {
                tunnel_id // Gatewayは公開IDを使う
            } else {
                // RelayはランダムID（gateway のビットは下ろす）
                let mut id: [u8; 32] = rand::random();
                id[0] &= !GATEWAY_ID_BIT;
                id
            };

            // Alice (最後のホップ) の場合、receive_tunnel_id を保存
            if i == hop_pubkeys.len() - 1 {
                receive_tunnel_id = listen_tunnel_id;
            }

            // 次のホップ情報
            let next_hop = if return_to_builder && i + 2 == path.len() {
                None
            } else if i + 1 < path.len() {
                Some(path[i + 1])
            } else {
                // Last hop (Alice) - next_hop is self
                Some(path[i])
            };

            let instruction = HopInstruction {
                next_hop,
                next_tunnel_id: next_hop_tunnel_id,
            };

            // EphemeralKey を生成して共有秘密を導出
            let ephemeral = key_exchange::EphemeralKey::generate();
            let ephemeral_pk_bytes = ephemeral.public_bytes();
            let shared_secret = ephemeral.diffie_hellman(&hop_pk);

            // 命令を暗号化
            let instruction_bytes = bincode::serialize(&instruction)
                .map_err(|e| AetherError::Config(e.to_string()))?;

            let (encrypted_instruction, nonce) =
                cipher::encrypt(&instruction_key(&shared_secret), &instruction_bytes)?;

            // Hop に渡すデータ: [TunnelID][EphemeralPK][Nonce][EncInstruction]
            let mut hop_data = Vec::new();
            hop_data.extend_from_slice(&listen_tunnel_id);
            hop_data.extend_from_slice(&ephemeral_pk_bytes);
            hop_data.extend_from_slice(&nonce);
            hop_data.extend_from_slice(&encrypted_instruction);

            hop_instructions.push((hop_addr, hop_data));

            // 復号鍵を記録 (自分に近い順に追加)
            decrypt_keys.push(shared_secret);

            // 次のループのために tunnel_id を更新
            next_hop_tunnel_id = listen_tunnel_id;
        }

        // hop_instructions を逆順にして Gateway からの順序にする
        hop_instructions.reverse();
        // decrypt_keys は既に自分に近い順なのでそのまま

        let tunnel = InboundTunnel {
            endpoint: TunnelEndpoint {
                gateway: path[0],
                tunnel_id,
            },
            decrypt_keys,
            receive_tunnel_id,
            path,
        };

        Ok((tunnel, hop_instructions))
    }

    /// トンネル経由で受信したデータを復号する
    ///
    /// # Arguments
    /// * `encrypted_data` - Gateway から転送されてきた暗号化データ
    ///
    /// # Returns
    /// * 復号されたペイロード
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        // 形式: [最後のホップが付けた nonce 12][本文]
        if encrypted_data.len() < NONCE_LEN + 4 {
            return Err(AetherError::Crypto("Tunnel data too short".into()));
        }
        let mut nonce: [u8; NONCE_LEN] = encrypted_data[..NONCE_LEN].try_into().expect("長さ確認済み");
        let mut body = encrypted_data[NONCE_LEN..].to_vec();

        // 自分に近いホップから順に剥がす。各ホップは「受けた nonce」で暗号化し、
        // nonce を自分の値で XOR して渡しているので、逆にたどれる
        for shared in &self.decrypt_keys {
            let keys = TunnelKeys::derive(shared);
            nonce = xor_nonce(&nonce, &keys.nonce_mask);
            xor_stream(&keys.stream, &nonce, &mut body);
        }

        // gateway が付けた [長さ][データ][パディング] から取り出す
        let len = u32::from_be_bytes(body[..4].try_into().expect("長さ確認済み")) as usize;
        body.get(4..4 + len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| AetherError::Crypto("Tunnel data length out of range".into()))
    }

    /// 公開用のエンドポイント情報を取得
    pub fn endpoint(&self) -> &TunnelEndpoint {
        &self.endpoint
    }
}

/// 登録済みトンネル1件分: (共有秘密, 次ホップ, 次のトンネルID, 登録時刻)
type TunnelEntry = ([u8; 32], SocketAddr, [u8; 32], Instant);

/// トンネル中継ノードの処理
pub struct TunnelRelay {
    /// 登録されたトンネル: tunnel_id -> エントリ
    tunnels: std::collections::HashMap<[u8; 32], TunnelEntry>,
}

impl Default for TunnelRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelRelay {
    pub fn new() -> Self {
        Self {
            tunnels: std::collections::HashMap::new(),
        }
    }

    /// 登録済みトンネル数
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }

    /// トンネルを登録する (Gateway がトンネル構築時に呼ばれる)
    ///
    /// **既存の tunnel_id は上書きしない。** gateway の tunnel_id は
    /// 保持者や出口に見える値なので、同じ ID で TunnelBuild を送りつければ
    /// 返信トンネルを乗っ取れてしまう。呼び出し側は戻り値が `false` なら
    /// 登録が拒否されたことをログに残すこと。
    ///
    /// 登録のたびに期限切れエントリを掃除し、上限（[`MAX_TUNNELS`]）を超える
    /// 新規登録も拒否する（誰でも登録できる以上、無制限の蓄積を防ぐ必要がある）。
    #[must_use = "登録が拒否された場合、呼び出し側はログに残すこと"]
    pub fn register_tunnel(
        &mut self,
        tunnel_id: [u8; 32],
        shared_key: [u8; 32],
        next_hop: SocketAddr,
        next_tunnel_id: [u8; 32],
    ) -> bool {
        self.cleanup_expired();

        if self.tunnels.contains_key(&tunnel_id) {
            return false;
        }
        if self.tunnels.len() >= MAX_TUNNELS {
            return false;
        }

        self.tunnels.insert(tunnel_id, (shared_key, next_hop, next_tunnel_id, Instant::now()));
        true
    }

    /// 期限切れ（[`TUNNEL_TTL`] を過ぎた）エントリを取り除く
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.tunnels.retain(|_, (_, _, _, registered_at)| now.duration_since(*registered_at) < TUNNEL_TTL);
    }

    /// テスト用: 登録時刻を `age` 前にずらして直接挿入する（TTL 切れの状態を作る）
    #[cfg(test)]
    fn insert_raw(
        &mut self,
        tunnel_id: [u8; 32],
        shared_key: [u8; 32],
        next_hop: SocketAddr,
        next_tunnel_id: [u8; 32],
        age: Duration,
    ) {
        let registered_at = Instant::now() - age;
        self.tunnels.insert(tunnel_id, (shared_key, next_hop, next_tunnel_id, registered_at));
    }

    /// トンネルデータを処理する
    ///
    /// # Returns
    /// * `Ok(Some((next_hop, next_tunnel_id, forwarded_data)))` - 転送先情報
    /// * `Ok(None)` - 最終宛先 (自分)
    /// * `Err` - 処理失敗
    pub fn process_tunnel_data(
        &self,
        tunnel_id: &[u8; 32],
        data: &[u8],
    ) -> Result<Option<ForwardingInstruction>> {
        let (shared, next_hop, next_tunnel_id, registered_at) = self.tunnels.get(tunnel_id)
            .ok_or_else(|| AetherError::Config("Unknown tunnel ID".into()))?;
        if registered_at.elapsed() >= TUNNEL_TTL {
            return Err(AetherError::Config("Tunnel expired".into()));
        }
        let keys = TunnelKeys::derive(shared);

        let (nonce, mut body) = if is_gateway_id(tunnel_id) {
            // gateway：外から来た素のデータを [長さ][データ][乱数] でバケットに切り上げ、
            // 乱数の nonce を付ける（以降のホップはこの長さのまま運ぶ）
            let len = u32::try_from(data.len())
                .map_err(|_| AetherError::Protocol("Tunnel data too large".into()))?;
            let bucket = crate::net::onion::padded_len(4 + data.len());
            let mut body = Vec::with_capacity(bucket);
            body.extend_from_slice(&len.to_be_bytes());
            body.extend_from_slice(data);
            let mut pad = vec![0u8; bucket - body.len()];
            rand::Rng::fill(&mut rand::thread_rng(), &mut pad[..]);
            body.extend_from_slice(&pad);
            (rand::random::<[u8; NONCE_LEN]>(), body)
        } else {
            if data.len() < NONCE_LEN {
                return Err(AetherError::Protocol("Tunnel data too short".into()));
            }
            let nonce: [u8; NONCE_LEN] = data[..NONCE_LEN].try_into().expect("長さ確認済み");
            (nonce, data[NONCE_LEN..].to_vec())
        };

        // 長さを変えずに暗号化を重ね、nonce を自分の値で置き換えて渡す
        xor_stream(&keys.stream, &nonce, &mut body);
        let mut forwarded_data = Vec::with_capacity(NONCE_LEN + body.len());
        forwarded_data.extend_from_slice(&xor_nonce(&nonce, &keys.nonce_mask));
        forwarded_data.extend_from_slice(&body);

        // 次のホップに転送
        Ok(Some((*next_hop, *next_tunnel_id, forwarded_data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_endpoint_serialization() {
        let endpoint = TunnelEndpoint {
            gateway: "127.0.0.1:9000".parse().unwrap(),
            tunnel_id: [1u8; 32],
        };

        let serialized = bincode::serialize(&endpoint).unwrap();
        let deserialized: TunnelEndpoint = bincode::deserialize(&serialized).unwrap();

        assert_eq!(endpoint.gateway, deserialized.gateway);
        assert_eq!(endpoint.tunnel_id, deserialized.tunnel_id);
    }

    /// 経路を組み、各ホップを登録した TunnelRelay を返す
    fn setup(n: usize) -> (InboundTunnel, Vec<([u8; 32], TunnelRelay)>) {
        let secrets: Vec<StaticSecret> =
            (0..n).map(|_| StaticSecret::random_from_rng(rand::rngs::OsRng)).collect();
        let path: Vec<SocketAddr> =
            (1..=n).map(|i| format!("10.0.0.{}:9000", i).parse().unwrap()).collect();
        let pubkeys = secrets.iter().map(|s| PublicKey::from(s).to_bytes()).collect();
        let (tunnel, instructions) = InboundTunnel::build(path, pubkeys).unwrap();

        let relays = instructions
            .iter()
            .zip(&secrets)
            .map(|((_, data), secret)| {
                let (tid, shared, inst) = open_build(secret, data).unwrap();
                let mut relay = TunnelRelay::new();
                assert!(relay.register_tunnel(tid, shared, inst.next_hop.unwrap(), inst.next_tunnel_id));
                (tid, relay)
            })
            .collect();
        (tunnel, relays)
    }

    /// gateway から終端まで流し、各ホップが受け取った長さと終端の出力を返す
    fn traverse(relays: &[([u8; 32], TunnelRelay)], msg: &[u8]) -> (Vec<usize>, Vec<u8>) {
        let mut data = msg.to_vec();
        let mut tid = relays[0].0;
        let mut seen = Vec::new();
        for (_, relay) in relays {
            let (_, next_tid, out) = relay.process_tunnel_data(&tid, &data).unwrap().unwrap();
            seen.push(out.len());
            data = out;
            tid = next_tid;
        }
        (seen, data)
    }

    #[test]
    fn tunnel_roundtrip_with_constant_length() {
        let (tunnel, relays) = setup(4); // gateway, 中継, ガード, 自分
        let msg = b"Hello Anonymously!";
        let (lens, out) = traverse(&relays, msg);
        assert!(lens.windows(2).all(|w| w[0] == w[1]), "ホップごとに長さが変わった: {:?}", lens);
        assert_eq!(tunnel.decrypt(&out).unwrap(), msg);
    }

    #[test]
    fn replies_of_different_sizes_look_alike() {
        let (_, relays) = setup(3);
        let (a, _) = traverse(&relays, &[1u8; 30]);
        let (b, _) = traverse(&relays, &[2u8; 700]);
        assert_eq!(a, b, "応答の大きさが中継から見分けられる");
    }

    #[test]
    fn only_the_gateway_id_has_the_gateway_bit() {
        let (tunnel, relays) = setup(4);
        assert!(is_gateway_id(&tunnel.endpoint.tunnel_id));
        assert!(relays[1..].iter().all(|(tid, _)| !is_gateway_id(tid)));
    }

    #[test]
    fn nonces_differ_at_every_hop() {
        // 隣り合わないホップどうしが nonce でメッセージを突き合わせられないこと
        let (_, relays) = setup(3);
        let mut data = b"x".to_vec();
        let mut tid = relays[0].0;
        let mut nonces = Vec::new();
        for (_, relay) in &relays {
            let (_, next_tid, out) = relay.process_tunnel_data(&tid, &data).unwrap().unwrap();
            nonces.push(out[..NONCE_LEN].to_vec());
            data = out;
            tid = next_tid;
        }
        assert_ne!(nonces[0], nonces[1]);
        assert_ne!(nonces[1], nonces[2]);
        assert_ne!(nonces[0], nonces[2]);
    }

    #[test]
    fn builder_terminated_tunnel_returns_over_the_builders_connection() {
        // ガード（終端の手前）の指示だけが next_hop = None になり、
        // それ以外は通常どおり次のアドレスを指す
        let secrets: Vec<x25519_dalek::StaticSecret> = (0..4)
            .map(|_| x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng))
            .collect();
        let pubkeys: Vec<[u8; 32]> = secrets
            .iter()
            .map(|s| x25519_dalek::PublicKey::from(s).to_bytes())
            .collect();
        let path: Vec<SocketAddr> = (1..=4)
            .map(|n| format!("10.0.0.{}:9000", n).parse().unwrap())
            .collect();

        let (_, instructions) = InboundTunnel::build_to_builder(path.clone(), pubkeys).unwrap();

        let next_hops: Vec<Option<SocketAddr>> = instructions
            .iter()
            .zip(&secrets)
            .map(|((_, data), secret)| {
                open_build(secret, data).unwrap().2.next_hop
            })
            .collect();

        assert_eq!(next_hops, vec![Some(path[1]), Some(path[2]), None, Some(path[3])]);
    }

    #[test]
    fn builder_terminated_tunnel_needs_a_relay() {
        let path = vec!["10.0.0.1:9000".parse().unwrap(), "10.0.0.2:9000".parse().unwrap()];
        assert!(InboundTunnel::build_to_builder(path, vec![[1; 32], [2; 32]]).is_err());
    }

    /// 同じ tunnel_id で登録し直しても、既存の登録（次ホップ）は乗っ取られないこと
    #[test]
    fn register_tunnel_does_not_overwrite_existing_id() {
        let mut relay = TunnelRelay::new();
        let mut tid = [1u8; 32];
        tid[0] |= GATEWAY_ID_BIT;
        let original_next: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let hijack_next: SocketAddr = "10.0.0.2:9000".parse().unwrap();

        assert!(relay.register_tunnel(tid, [1u8; 32], original_next, [2u8; 32]));
        assert!(
            !relay.register_tunnel(tid, [9u8; 32], hijack_next, [9u8; 32]),
            "既存 ID を上書きできてしまった"
        );

        let (next_hop, _, _) = relay.process_tunnel_data(&tid, b"hello").unwrap().unwrap();
        assert_eq!(next_hop, original_next, "後から送りつけた登録に乗っ取られた");
    }

    /// TTL を過ぎた登録は無効に扱われ、次の登録で掃除されて上書きできること
    #[test]
    fn expired_tunnel_is_rejected_and_then_cleaned_up() {
        let mut relay = TunnelRelay::new();
        let mut tid = [3u8; 32];
        tid[0] |= GATEWAY_ID_BIT;
        relay.insert_raw(
            tid,
            [1u8; 32],
            "10.0.0.1:9000".parse().unwrap(),
            [2u8; 32],
            TUNNEL_TTL + Duration::from_secs(1),
        );

        assert!(relay.process_tunnel_data(&tid, b"hello").is_err(), "期限切れなのに処理された");

        // register_tunnel は登録のたびに期限切れを掃除するので、同じ ID でも通る
        assert!(relay.register_tunnel(tid, [9u8; 32], "10.0.0.9:9000".parse().unwrap(), [9u8; 32]));
    }
}
