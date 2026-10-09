//! 保持者の受け口に届く中身の形（Part 23 の 5.2）
//!
//! 保持者の受け口のトンネルには、置く・取る・生死確認の 3 種類が流れる。
//! 受け口の gateway は中身を読まないので、種別を見分ける印は中身の先頭に置く。
//!
//! ```text
//! [種別 u8][本文]
//!   HOLDER_PUT   = 1  本文 = MailboxPut の中身 [key 32][value]
//!   HOLDER_GET   = 2  本文 = MailboxGet の中身 [key 32][bincode(TunnelEndpoint)]
//!   HOLDER_PROBE = 3  本文 = 目印 32 バイト（保持者が自分の受け口の生死を確かめる）
//! ```

use crate::error::{AetherError, Result};

/// 置く。本文は `MailboxPut` の中身と同じ
pub const HOLDER_PUT: u8 = 1;
/// 取る。本文は `MailboxGet` の中身と同じ
pub const HOLDER_GET: u8 = 2;
/// 一周の確認。本文は目印 32 バイト
pub const HOLDER_PROBE: u8 = 3;

/// 目印の長さ
pub const HOLDER_PROBE_LEN: usize = 32;

/// 受け口に入れる中身を組み立てる
pub fn build_holder_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + body.len());
    buf.push(kind);
    buf.extend_from_slice(body);
    buf
}

/// 受け口の gateway に渡す `TunnelData` の中身 `[tunnel_id 32][種別 1][本文]` を組み立てる
///
/// 置く人は、これを自分の回路の出口に `TunnelData` として gateway へ渡させる。
/// 組み立てを 1 か所にしておくのは、v2 のシャードの大きさを決める試験が実物の長さで確かめるため。
pub fn build_gateway_data(tunnel_id: &[u8; 32], kind: u8, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 1 + body.len());
    buf.extend_from_slice(tunnel_id);
    buf.push(kind);
    buf.extend_from_slice(body);
    buf
}

/// 受け口に届いた中身を種別と本文に分ける
///
/// 空の中身は拒む。種別の値の検査は呼び出し側が振り分けるときに行う
/// （将来の種別を足しても、古い保持者が黙って壊れずに捨てられるように）。
pub fn parse_holder_message(data: &[u8]) -> Result<(u8, &[u8])> {
    data.split_first()
        .map(|(kind, body)| (*kind, body))
        .ok_or_else(|| AetherError::Protocol("Empty holder message".into()))
}

/// `HOLDER_PROBE` の本文から目印を取り出す
pub fn parse_probe_marker(body: &[u8]) -> Result<[u8; HOLDER_PROBE_LEN]> {
    body.try_into()
        .map_err(|_| AetherError::Protocol("Holder probe marker must be 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_message_roundtrips_for_every_kind() {
        for kind in [HOLDER_PUT, HOLDER_GET, HOLDER_PROBE] {
            let body = vec![kind; 40];
            let built = build_holder_message(kind, &body);
            let (k, b) = parse_holder_message(&built).unwrap();
            assert_eq!(k, kind);
            assert_eq!(b, body.as_slice());
        }
    }

    #[test]
    fn gateway_data_is_tunnel_id_then_holder_message() {
        let data = build_gateway_data(&[7u8; 32], HOLDER_PUT, b"body");
        assert_eq!(&data[..32], &[7u8; 32]);
        assert_eq!(&data[32..], build_holder_message(HOLDER_PUT, b"body").as_slice());
    }

    #[test]
    fn empty_holder_message_is_rejected_and_empty_body_is_allowed() {
        assert!(parse_holder_message(&[]).is_err(), "空の中身は拒む");
        let (k, b) = parse_holder_message(&[HOLDER_GET]).unwrap();
        assert_eq!((k, b.len()), (HOLDER_GET, 0), "本文が空でも種別は読める");
    }

    #[test]
    fn probe_marker_must_be_exactly_32_bytes() {
        assert_eq!(parse_probe_marker(&[7u8; 32]).unwrap(), [7u8; 32]);
        assert!(parse_probe_marker(&[7u8; 31]).is_err());
        assert!(parse_probe_marker(&[7u8; 33]).is_err());
    }
}
