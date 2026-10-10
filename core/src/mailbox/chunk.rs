//! 大容量コンテンツのチャンク化と content-addressing (Phase 2-4)
//!
//! 単一 body の RS 分割は 1 オブジェクト ~3MB が上限（5 シャード × 1MB / 3 データ）。
//! それを超えるファイルは [`CHUNK_SIZE`] ごとに割り、各チャンクを独立した
//! **content-addressed** オブジェクトとして配置する。[`Manifest`] がチャンク参照を束ねる。
//!
//! # content-addressing と重複排除
//!
//! チャンクは**収束的暗号化**する ── nonce = `H(secret ‖ 平文チャンク)`。
//! 同じ秘密（公開なら `K_pub`）と同じ平文なら暗号文が一致するので、
//! `chunk_ref = H(暗号文)` が一致し、リング上の同じ位置（`H(chunk_ref ‖ K)`）に落ちる。
//!
//! → **同一ファイルを複数人が公開しても重複排除され、複数保持者から並列取得（swarm）できる。**
//!   Winny の「人気なファイルほど速く・落ちにくい」がそのまま出る。
//!
//! 収束暗号は「平文を推測できれば存在を確認できる」弱点を持つが、
//! **チャンク化は公開コンテンツ専用**なので無害（そもそも公開で発見可能にしている）。
//! 私信は単一 body のまま（メッセージは小さくチャンク化不要）。

use crate::error::{AetherError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// チャンク 1 つの大きさ (256KB)
///
/// 転送サイズがそのまま指紋になるため、常にこの単位へ正規化する。
/// 256KB に対する 3-Hop Onion のオーバーヘッドは +0.08% で償却される。
pub const CHUNK_SIZE: usize = 256 * 1024;

/// これ以下なら単一 body で置ける（チャンク化不要）
///
/// 単一 body は RS 3+2・各シャード <= 1MB なので理論上 ~3MB まで置けるが、
/// 判定を単純にするため 1 チャンク分を境界にする。
pub const SINGLE_BODY_LIMIT: usize = CHUNK_SIZE;

/// 1 つの [`Manifest`] が束ねられるチャンク数の上限
///
/// Manifest 自体も 1 オブジェクトとして置くので、その本体が収まる必要がある。
/// 32B × 65536 = 2MB。CHUNK_SIZE と掛けて最大 ~16GB のファイルを 1 Manifest で扱える。
/// これを超えるファイルは Manifest の木構造（将来）が要る。
pub const MAX_CHUNKS_PER_MANIFEST: usize = 65536;

/// ファイルのチャンク構成表
///
/// これ自体が 1 つの content-addressed オブジェクトとして配置され、
/// その参照（= 索引の `content_ref`）を辿ると本体を復元できる。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// 表示名（ファイル名）
    pub name: String,
    /// 復元後の全体サイズ（バイト）
    pub size: u64,
    /// 各チャンクの content-address（= そのチャンクの mailbox_key）。
    /// **並び順が本体の連結順**。
    pub chunk_refs: Vec<[u8; 32]>,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid Manifest: {}", e)))?;
        if m.chunk_refs.len() > MAX_CHUNKS_PER_MANIFEST {
            return Err(AetherError::Protocol(format!(
                "Manifest too large: {} chunks (max {})",
                m.chunk_refs.len(),
                MAX_CHUNKS_PER_MANIFEST
            )));
        }
        Ok(m)
    }
}

/// v2 のシャード 1 枚の大きさ（バイト）。データもパリティも同じ長さ
///
/// **`chunk::tests::v2_shard_bytes_fills_the_256k_onion_bucket` で決めた値。**
/// 置く向きは、置く人の回路の出口が保持者の受け口（GW_h）へ `TunnelData` を渡す形
/// （`send_onion_message_typed(TunnelData, [tunnel_id 32][HOLDER_PUT 1][put_key 32][シャード], GW_h)`）。
/// 出口に届く本文は
/// `[内側の種別 1][宛先 SocketAddr（bincode。IPv6 で 22）][PacketType 1][tunnel_id 32][HOLDER_PUT 1][put_key 32][シャード]`
/// で、onion はこれに長さ 4 バイトを前置して `padded_len` で切り上げる。
/// その結果がちょうど 262,144（256KiB のバケット）に収まる最大のシャードが
/// `262_144 − 4 − 1 − 22 − 1 − 32 − 1 − 32 = 262_051`。1 バイト増やすと 524,288 に跳ねて倍になる。
/// 宛先が IPv4（bincode で 10）なら 12 バイト短くなるが、同じバケットに切り上がるので長さは変わらない。
/// 返す向き（保持者の回路の出口 → 取る人の返信トンネルの gateway）は
/// `[内側の種別 1][宛先 22][TunnelData 1][tunnel_id 32][シャード]` で、置く向きより 33 バイト短く、
/// 同じバケットに収まる。
pub const V2_SHARD_BYTES: usize = 262_051;

/// 収束暗号のオブジェクトの付加分: nonce 12 + 認証タグ 16
pub const V2_SEAL_OVERHEAD: usize = 12 + 16;

/// v2 のチャンクの平文の大きさ（最後以外）。シャードに収まる暗号文から nonce・タグを引いた分
pub const V2_CHUNK_PLAIN: usize = V2_SHARD_BYTES - V2_SEAL_OVERHEAD;

/// [`ManifestV2`] の版番号
pub const MANIFEST_V2_VERSION: u8 = 2;

/// [`ManifestRoot`]（ストライプの表を木にした根）の版番号。[`MANIFEST_V2_VERSION`] とは別の値
///
/// 取る側は、取れたオブジェクトを `ManifestV2` → 根の順に試して見分ける。
pub const MANIFEST_ROOT_VERSION: u8 = 3;

/// 1 ファイルの大きさの上限（64GiB）
///
/// 根は 1 オブジェクト（封じて [`SINGLE_BODY_LIMIT`]）に収まる必要がある。64GiB は約 16,400 ストライプで、
/// 1 ページ約 180 ストライプなら約 92 ページ、根は 3KB ほどで十分余裕がある。
/// これより上は、ページの参照が増えて根が収まらなくなる前に、置く側・取る側が手元に持つ
/// ストライプの表（約 22MB）と、取る側の「どのシャードがどのストライプか」の索引（約 70MB）が重くなる。
/// 刻みの一番上（2^36 バイト）でもあるので、切り上げでこの上限を超えることもない。
pub const MAX_FILE_BYTES: u64 = 64 << 30;

/// [`StripeV2`] 1 つの bincode での固定部分: data 1 + parity 1 + last_object_len 4 + ハッシュ列の長さ 8
const STRIPE_V2_FIXED: usize = 1 + 1 + 4 + 8;

/// 1 つの [`ManifestV2`] が持てるストライプ数の上限
///
/// Manifest 自体も 1 オブジェクトとして置く（暗号化後に [`SINGLE_BODY_LIMIT`] 以内）ので、
/// ストライプ 1 つが最低でもハッシュ 1 個分（固定部分 + 32）かかるとして割った値。受信側の肥大対策。
pub const MAX_STRIPES_PER_MANIFEST_V2: usize = SINGLE_BODY_LIMIT / (STRIPE_V2_FIXED + 32);

/// v2 の 1 ストライプのデータシャード数（チャンク数）
pub const V2_DATA_PER_STRIPE: usize = crate::mailbox::sharding_v2::DEFAULT_DATA_SHARDS;

/// 冗長度 m を決めるときの「取りに行ったとき保持者が不在の確率」の仮定
///
/// 仮の値。段 E の抜き打ち検査で実測するまではこれで決める（Part 23 の 7 章）。
pub const V2_ASSUMED_LOSS: f64 = 0.3;

/// 冗長度 m を決めるときの「全ストライプが取れる確率」の目標
pub const V2_TARGET_AVAILABILITY: f64 = 0.999;

/// このファイルが何チャンクになるか（v2。最後以外は [`V2_CHUNK_PLAIN`]）
pub fn v2_chunk_count(size: u64) -> usize {
    size.div_ceil(V2_CHUNK_PLAIN as u64) as usize
}

/// 切り上げの最小の刻み（バイト）。小さなファイルを細かく区別させないため（約 4 チャンク分）
pub const V2_MIN_BUCKET_BYTES: u64 = 1 << 20;

/// 2 の冪の刻みをやめて、細かい刻みにする境目（1GiB）
pub const V2_FINE_BUCKET_FROM: u64 = 1 << 30;

/// 1GiB を超える刻みの、2 倍の間の 4 つの位置（4096 を 1 倍とした整数。2 の 1/4 乗刻み）
///
/// 4096 × 2^(i/4) の切り上げ。浮動小数にすると、置く側と置く前の見積もりで丸めがずれうるので、
/// 整数の表にして、1GiB × 表 ÷ 4096 を倍々にする。
const FINE_STEPS: [u64; 4] = [4096, 4871, 5793, 6889];

/// ファイルの大きさを切り上げた刻み（バイト）
///
/// - 1GiB まで: 2 の冪（最小 [`V2_MIN_BUCKET_BYTES`]）
/// - 1GiB を超えたら: 2 の 1/4 乗刻み（1, 1.19, 1.41, 1.68, 2, 2.38 … GiB）
///
/// 大きなファイルでも 2 倍刻みのままだと、1.1GiB が 2GiB に上がって上りがほぼ倍無駄になる。
/// 1/4 乗刻みなら無駄は最大約 19% で済む。代わりに、刻みの数（ガードから見た候補の数）が
/// 2 倍刻みの 4 倍に増え、同じ刻みに入る別のファイルが 4 分の 1 になる（匿名集合が小さくなる）。
/// 1GiB を超えるファイルは数が少なく、無駄な上りの方が利用者に重いと判断した。
pub fn size_bucket_bytes(size: u64) -> u64 {
    let size = size.max(1);
    if size <= V2_FINE_BUCKET_FROM {
        return size.next_power_of_two().max(V2_MIN_BUCKET_BYTES);
    }
    let mut base = V2_FINE_BUCKET_FROM;
    loop {
        for step in FINE_STEPS {
            let bucket = base / 4096 * step;
            if bucket >= size {
                return bucket;
            }
        }
        // 2^60 を超える大きさは扱わない（桁あふれ防止。上限 MAX_FILE_BYTES より遥かに上）
        if base >= 1 << 60 {
            return base;
        }
        base *= 2;
    }
}

/// 切り上げ後のチャンク数。ファイルの大きさを [`size_bucket_bytes`] の刻みに切り上げ、
/// その大きさを収めるチャンク数にして、`max` で頭打ちにする
///
/// ガードは自分のクライアントが置いた量・取った量を見ているので、大きさを丸めて
/// 候補を増やす（Part 24 の L5）。刻みをチャンク数の 2 の冪にすると、チャンクの平文が 256KiB より
/// わずかに小さいため、ちょうど 4MiB のファイルが 17 チャンクになって次の刻みへ跳ねていた。
/// バイトで決めれば 4MiB は 17、4MiB + 1 は 33 チャンクで、利用者が見る大きさと刻みが揃う。
/// `max` は通常 [`max_chunks_file`]（[`MAX_FILE_BYTES`] のチャンク数）。**上限の大きさ以下のファイルなら、
/// 刻みも上限以下**なので、頭打ちで本物のチャンク数を下回ることはない。
/// `size` が上限を超えるものは呼び出し側が先に断っている前提。
pub fn padded_chunks_for_size(size: u64, max: usize) -> usize {
    size_bucket_bytes(size).div_ceil(V2_CHUNK_PLAIN as u64).min(max as u64) as usize
}

/// 上限の大きさのファイルのチャンク数
pub fn max_chunks_file() -> usize {
    v2_chunk_count(MAX_FILE_BYTES)
}

/// 上限の大きさのファイルのストライプ数
pub fn max_stripes_file() -> usize {
    max_chunks_file().div_ceil(V2_DATA_PER_STRIPE)
}

/// 置くチャンク数（`pad` なら切り上げ込み）。上限を超えるファイルと空のファイルはエラー
///
/// 置く側・置く前の見積もり・テストが同じ数を使うよう、ここに 1 つだけ置く。
pub fn v2_layout_chunks(size: u64, pad: bool) -> Result<usize> {
    let n = v2_chunk_count(size);
    if n == 0 {
        return Err(AetherError::Config("empty file cannot use the v2 layout".into()));
    }
    if size > MAX_FILE_BYTES {
        return Err(AetherError::Config(format!(
            "File too large ({} bytes, max {})",
            size, MAX_FILE_BYTES
        )));
    }
    Ok(if pad { padded_chunks_for_size(size, max_chunks_file()) } else { n })
}

/// 埋め草のチャンク `index` の平文（長さ [`V2_CHUNK_PLAIN`]）
///
/// `[タグ 32 バイト][ゼロ]`。タグ = `HMAC-SHA256(板の秘密, "aether_v2_pad" ‖ ファイルの平文の SHA-256 ‖ index)`。
/// 全部ゼロにすると、収束暗号のため板じゅうで同じシャードになって 1 台の保持者に集まり、
/// その保持者に本当の大きさが漏れる。ファイルごとに別の中身にすれば別のシャードとして散る。
/// 同じファイルを同じ板に置き直せば同じ埋め草になる（重複排除は保たれる）。
pub fn pad_chunk_plain(secret: &[u8; 32], file_hash: &[u8; 32], index: u32) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any length");
    mac.update(b"aether_v2_pad");
    mac.update(file_hash);
    mac.update(&index.to_be_bytes());
    let mut plain = vec![0u8; V2_CHUNK_PLAIN];
    plain[..32].copy_from_slice(&mac.finalize().into_bytes());
    plain
}

/// チャンク数から、各ストライプの `(k, m)` を決める
///
/// m は**ファイルごとに 1 つ**（全ストライプが取れる確率が目標以上になる最小値）。
/// 最後の短いストライプは `ceil(m × k ÷ 16)`（最低 1）。置く側と、置く前の大きさの見積もりが
/// 同じ結果を使うよう、ここに 1 つだけ置く。
pub fn v2_stripe_shapes(chunks: usize) -> Result<Vec<(usize, usize)>> {
    if chunks == 0 {
        return Err(AetherError::Config("empty file cannot use the v2 layout".into()));
    }
    let stripes = chunks.div_ceil(V2_DATA_PER_STRIPE);
    if stripes > max_stripes_file() {
        return Err(AetherError::Config(format!("too many stripes: {}", stripes)));
    }
    let m = crate::mailbox::sharding_v2::m_for(
        V2_ASSUMED_LOSS,
        V2_DATA_PER_STRIPE,
        stripes,
        V2_TARGET_AVAILABILITY,
    )?;
    Ok((0..stripes)
        .map(|i| {
            let k = (chunks - i * V2_DATA_PER_STRIPE).min(V2_DATA_PER_STRIPE);
            let mi = if k == V2_DATA_PER_STRIPE { m } else { (m * k).div_ceil(V2_DATA_PER_STRIPE).max(1) };
            (k, mi)
        })
        .collect())
}

/// 暗号化した [`ManifestV2`] の大きさ（置く前の見積もり。nonce 12 + タグ 16 を含む）
///
/// `chunks` は切り上げた後のチャンク数（[`v2_layout_chunks`]）。
/// bincode の長さ: version 1 + 名前(8 + 名前長) + size 8 + chunk_plain 4 + ストライプ列(8 + 各 14 + 32 × (k+m))。
/// 実際に作った Manifest を封じた長さと一致する（試験で確かめている）。
pub fn manifest_v2_sealed_len(name_len: usize, chunks: usize) -> Result<usize> {
    let shapes = v2_stripe_shapes(chunks)?;
    let body: usize = shapes.iter().map(|(k, m)| STRIPE_V2_FIXED + 32 * (k + m)).sum();
    Ok(1 + 8 + name_len + 8 + 4 + 8 + body + V2_SEAL_OVERHEAD)
}

/// 暗号化後の [`ManifestV2`] 1 つが [`SINGLE_BODY_LIMIT`] に収まる最大のチャンク数
///
/// これを超えるファイルは、ストライプの表をページに分けた木（[`ManifestRoot`]）にする。名前が長いほど少し減る。
pub fn max_chunks_v2(name_len: usize) -> usize {
    let fits = |chunks: usize| {
        manifest_v2_sealed_len(name_len, chunks).is_ok_and(|n| n <= SINGLE_BODY_LIMIT)
    };
    // sealed_len はチャンク数に対して単調に増えるので二分探索
    let (mut lo, mut hi) = (0usize, MAX_STRIPES_PER_MANIFEST_V2 * V2_DATA_PER_STRIPE + 1);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if fits(mid) { lo = mid } else { hi = mid }
    }
    lo
}

/// 暗号化した [`ManifestPage`] の大きさ（置く前の見積もり。nonce 12 + タグ 16 を含む）
///
/// bincode の長さ: ストライプ列(8 + 各 14 + 32 × (k+m))。
pub fn manifest_page_sealed_len(shapes: &[(usize, usize)]) -> usize {
    8 + shapes.iter().map(|(k, m)| STRIPE_V2_FIXED + 32 * (k + m)).sum::<usize>() + V2_SEAL_OVERHEAD
}

/// 冗長度 m のとき、1 ページに入れられるストライプ数（封じて [`SINGLE_BODY_LIMIT`] に収まる最大）
///
/// ページには満杯のストライプ（k=16, m）が並ぶとして数える（最後の短いストライプは小さいので必ず収まる）。
/// m=27 で 188。取り直しの 1 往復で取れる大きさを決める既定値で、利用者は選べない。
pub fn manifest_page_stripes(m: usize) -> usize {
    let per = STRIPE_V2_FIXED + 32 * (V2_DATA_PER_STRIPE + m);
    (SINGLE_BODY_LIMIT - 8 - V2_SEAL_OVERHEAD) / per
}

/// `total` 個のストライプを 1 ページ `per_page` 個ずつに分けた範囲（最後だけ短い）
pub fn page_ranges(total: usize, per_page: usize) -> Vec<std::ops::Range<usize>> {
    let per_page = per_page.max(1);
    (0..total.div_ceil(per_page))
        .map(|i| i * per_page..((i + 1) * per_page).min(total))
        .collect()
}

/// 暗号化した [`ManifestRoot`] の大きさ（置く前の見積もり）
///
/// bincode の長さ: version 1 + 名前(8 + 名前長) + size 8 + chunk_plain 4 + stripe_count 8 + 参照列(8 + 32 × ページ数)。
pub fn manifest_root_sealed_len(name_len: usize, pages: usize) -> usize {
    1 + 8 + name_len + 8 + 4 + 8 + 8 + 32 * pages + V2_SEAL_OVERHEAD
}

/// ストライプの表の置き方
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestPlan {
    /// 1 つの [`ManifestV2`]（1 回の往復で取れる）
    Single,
    /// 根 + ページ。1 ページ `per_page` ストライプ
    Tree { per_page: usize },
}

/// ストライプの表の置き方を決める（置く側と、置く前の見積もりが同じ結果を使う）
///
/// 1 つの [`ManifestV2`] が封じて [`SINGLE_BODY_LIMIT`] に収まれば `Single`。収まらないときだけ木にする。
/// `page_cap` は試験のときだけ 1 ページのストライプ数を小さくする口（本番は `None`で、計算した既定）。
/// これが効くと、ストライプが `page_cap` を超えるファイルは小さくても木になる。
/// 根も 1 オブジェクトに収まらない大きさ（[`MAX_FILE_BYTES`] を超える）はエラー。
pub fn plan_manifest(name_len: usize, chunks: usize, page_cap: Option<usize>) -> Result<ManifestPlan> {
    let shapes = v2_stripe_shapes(chunks)?;
    let cap = page_cap.map(|c| c.max(1));
    let single_fits = manifest_v2_sealed_len(name_len, chunks).is_ok_and(|n| n <= SINGLE_BODY_LIMIT);
    if single_fits && cap.is_none_or(|c| shapes.len() <= c) {
        return Ok(ManifestPlan::Single);
    }
    // 満杯のストライプの m は最大（短いストライプは比例して小さい）
    let m = shapes[0].1;
    let per_page = manifest_page_stripes(m).min(cap.unwrap_or(usize::MAX)).max(1);
    let pages = shapes.len().div_ceil(per_page);
    if manifest_root_sealed_len(name_len, pages) > SINGLE_BODY_LIMIT {
        return Err(AetherError::Config(format!(
            "File too large for the manifest root ({} pages)",
            pages
        )));
    }
    Ok(ManifestPlan::Tree { per_page })
}

/// シャードのハッシュ。Manifest v2 の `shard_hashes` と、同時に置き場所（担当の計算）の入力になる
pub fn shard_hash(shard: &[u8]) -> [u8; 32] {
    Sha256::digest(shard).into()
}

/// v2 のストライプ 1 つ（連続するデータシャード k 個 + パリティ m 個）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeV2 {
    /// このストライプのデータシャード数 k
    pub data: u8,
    /// パリティシャード数 m
    pub parity: u8,
    /// 最後のデータシャードの、埋める前のオブジェクト長（他のデータシャードは [`V2_SHARD_BYTES`]）
    pub last_object_len: u32,
    /// データ k 個 → パリティ m 個の順の、シャードの SHA-256
    pub shard_hashes: Vec<[u8; 32]>,
}

/// ストライプの形を検べる（受信側の増幅・肥大と、後段の添字あふれを防ぐ）
fn validate_stripe(s: &StripeV2) -> Result<()> {
    let total = s.data as usize + s.parity as usize;
    if s.data == 0
        || s.parity == 0
        || total > crate::mailbox::sharding_v2::MAX_TOTAL_SHARDS
        || s.shard_hashes.len() != total
    {
        return Err(AetherError::Protocol("ManifestV2 stripe shape is invalid".into()));
    }
    let last = s.last_object_len as usize;
    if last <= V2_SEAL_OVERHEAD || last > V2_SHARD_BYTES {
        return Err(AetherError::Protocol("ManifestV2 last_object_len is out of range".into()));
    }
    Ok(())
}

impl StripeV2 {
    /// 受け取ったシャードのうち、ハッシュが合うものだけを残す（`None` のままか、偽物なら `None`）
    ///
    /// 板の読者なら誰でも偽のシャードを作れるので、使う前に必ず通す。
    /// 戻り値は [`crate::mailbox::sharding_v2::decode_stripe`] にそのまま渡せる並び。
    pub fn keep_verified(&self, got: &[Option<Vec<u8>>]) -> Vec<Option<Vec<u8>>> {
        self.shard_hashes
            .iter()
            .enumerate()
            .map(|(i, want)| {
                got.get(i)
                    .and_then(|s| s.as_ref())
                    .filter(|s| s.len() == V2_SHARD_BYTES && shard_hash(s) == *want)
                    .cloned()
            })
            .collect()
    }
}

/// v2 のファイルのチャンク構成表（Part 23 の 7 章）
///
/// v1 の [`Manifest`] とは別の形で、**互換は無い**（v1 のファイルは v2 の読み手が読まない）。
/// 置き方は v1 の Manifest と同じ（小さなものの経路）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestV2 {
    /// 常に [`MANIFEST_V2_VERSION`]
    pub version: u8,
    /// 表示名（ファイル名）
    pub name: String,
    /// ファイルの平文の大きさ
    pub size: u64,
    /// チャンクの平文の大きさ（最後のチャンク以外）
    pub chunk_plain: u32,
    pub stripes: Vec<StripeV2>,
}

impl ManifestV2 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    /// 復号して形を検べる。受信側の増幅・肥大と、後段の添字あふれを防ぐ
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid ManifestV2: {}", e)))?;
        if m.version != MANIFEST_V2_VERSION {
            return Err(AetherError::Protocol(format!(
                "ManifestV2 version {} is not supported",
                m.version
            )));
        }
        if m.stripes.len() > MAX_STRIPES_PER_MANIFEST_V2 {
            return Err(AetherError::Protocol(format!(
                "ManifestV2 too large: {} stripes (max {})",
                m.stripes.len(),
                MAX_STRIPES_PER_MANIFEST_V2
            )));
        }
        if m.chunk_plain as usize != V2_CHUNK_PLAIN {
            return Err(AetherError::Protocol("ManifestV2 chunk size mismatch".into()));
        }
        for s in &m.stripes {
            validate_stripe(s)?;
        }
        Ok(m)
    }
}

/// 木の Manifest の根
///
/// ストライプの表が 1 オブジェクトに収まらないファイルで、記述子の `content_ref` はこれを指す。
/// ストライプの表そのものは [`ManifestPage`] に分けて、小さなものの経路で置く（内容アドレスで参照）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestRoot {
    /// 常に [`MANIFEST_ROOT_VERSION`]
    pub version: u8,
    /// 表示名（ファイル名）
    pub name: String,
    /// ファイルの平文の大きさ
    pub size: u64,
    /// チャンクの平文の大きさ（最後のチャンク以外）
    pub chunk_plain: u32,
    /// 全ページを合わせたストライプの総数
    pub stripe_count: u64,
    /// ページの内容アドレス。**並び順がストライプの順**
    pub pages: Vec<[u8; 32]>,
}

impl ManifestRoot {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    /// 復号して形を検べる
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let r: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid ManifestRoot: {}", e)))?;
        if r.version != MANIFEST_ROOT_VERSION {
            return Err(AetherError::Protocol(format!(
                "ManifestRoot version {} is not supported",
                r.version
            )));
        }
        if r.chunk_plain as usize != V2_CHUNK_PLAIN {
            return Err(AetherError::Protocol("ManifestRoot chunk size mismatch".into()));
        }
        if r.size > MAX_FILE_BYTES {
            return Err(AetherError::Protocol("ManifestRoot size is over the file limit".into()));
        }
        let stripes = r.stripe_count as usize;
        if r.stripe_count > max_stripes_file() as u64 || r.pages.is_empty() || r.pages.len() > stripes {
            return Err(AetherError::Protocol("ManifestRoot page table is invalid".into()));
        }
        Ok(r)
    }
}

/// 木の Manifest のページ ── ストライプの表の一部（連続するストライプ）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestPage {
    pub stripes: Vec<StripeV2>,
}

impl ManifestPage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| AetherError::Serialization(e.to_string()))
    }

    /// 復号して形を検べる。1 ページのストライプ数は封じて [`SINGLE_BODY_LIMIT`] に収まる範囲
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let p: Self = bincode::deserialize(bytes)
            .map_err(|e| AetherError::Protocol(format!("Invalid ManifestPage: {}", e)))?;
        if p.stripes.is_empty() || p.stripes.len() > MAX_STRIPES_PER_MANIFEST_V2 {
            return Err(AetherError::Protocol("ManifestPage stripe count is out of range".into()));
        }
        for s in &p.stripes {
            validate_stripe(s)?;
        }
        Ok(p)
    }
}

/// このサイズはチャンク化が要るか
pub fn needs_chunking(size: usize) -> bool {
    size > SINGLE_BODY_LIMIT
}

/// 平文を [`CHUNK_SIZE`] ごとに切る
pub fn split(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    data.chunks(CHUNK_SIZE).collect()
}

/// 収束的 nonce ── 同じ `(secret, 平文)` から必ず同じ nonce を出す
///
/// 異なる平文からは（高確率で）異なる nonce になるので、ChaCha20 の
/// **nonce 再利用は起きない**。同一平文で一致するのが重複排除の要。
pub fn convergent_nonce(secret: &[u8; 32], plaintext: &[u8]) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(b"aether_chunk_nonce_v1");
    h.update(secret);
    h.update(plaintext);
    let digest = h.finalize();
    digest[..12].try_into().expect("12 <= 32")
}

/// 格納オブジェクト（`[nonce(12)][ciphertext]`）から content-address を出す
///
/// これがチャンク／Manifest の `mailbox_key` になる。同一内容 → 同一位置。
pub fn content_address(stored_object: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"aether_chunk_id_v1");
    h.update(stored_object);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_covers_all_bytes_in_order() {
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 123)).map(|i| i as u8).collect();
        let chunks = split(&data);
        assert_eq!(chunks.len(), 3, "2 チャンク + 端数で 3 つ");
        assert_eq!(chunks[0].len(), CHUNK_SIZE);
        assert_eq!(chunks[1].len(), CHUNK_SIZE);
        assert_eq!(chunks[2].len(), 123);

        let rejoined: Vec<u8> = chunks.concat();
        assert_eq!(rejoined, data, "連結で元に戻る");
    }

    #[test]
    fn empty_data_has_no_chunks() {
        assert!(split(&[]).is_empty());
    }

    #[test]
    fn convergent_nonce_is_deterministic() {
        let secret = [7u8; 32];
        let plain = b"the same content";
        assert_eq!(
            convergent_nonce(&secret, plain),
            convergent_nonce(&secret, plain),
            "同一 (secret, 平文) は同一 nonce"
        );
    }

    #[test]
    fn convergent_nonce_diverges_on_content_and_secret() {
        assert_ne!(
            convergent_nonce(&[1u8; 32], b"a"),
            convergent_nonce(&[1u8; 32], b"b"),
            "別の平文は別の nonce（nonce 再利用を避ける）"
        );
        assert_ne!(
            convergent_nonce(&[1u8; 32], b"a"),
            convergent_nonce(&[2u8; 32], b"a"),
            "別の秘密は別の nonce"
        );
    }

    #[test]
    fn content_address_is_stable_and_content_bound() {
        let object = b"[nonce][ciphertext]";
        assert_eq!(content_address(object), content_address(object));
        assert_ne!(content_address(object), content_address(b"different"));
    }

    #[test]
    fn manifest_survives_wire_roundtrip() {
        let m = Manifest {
            name: "cool.mkv".into(),
            size: 700 * 1024,
            chunk_refs: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        };
        let decoded = Manifest::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn oversized_manifest_is_rejected() {
        let m = Manifest {
            name: "huge".into(),
            size: u64::MAX,
            chunk_refs: vec![[0u8; 32]; MAX_CHUNKS_PER_MANIFEST + 1],
        };
        // encode は通るが decode で弾く（受信側の増幅・肥大対策）
        let bytes = bincode::serialize(&m).unwrap();
        assert!(Manifest::decode(&bytes).is_err());
    }

    fn sample_stripe(k: u8, m: u8) -> StripeV2 {
        StripeV2 {
            data: k,
            parity: m,
            last_object_len: 1000,
            shard_hashes: (0..(k + m)).map(|i| [i; 32]).collect(),
        }
    }

    fn sample_v2() -> ManifestV2 {
        ManifestV2 {
            version: MANIFEST_V2_VERSION,
            name: "big.iso".into(),
            size: 5_000_000,
            chunk_plain: V2_CHUNK_PLAIN as u32,
            stripes: vec![sample_stripe(16, 27), sample_stripe(3, 1)],
        }
    }

    #[test]
    fn manifest_v2_survives_wire_roundtrip() {
        let m = sample_v2();
        assert_eq!(ManifestV2::decode(&m.encode().unwrap()).unwrap(), m);
    }

    #[test]
    fn manifest_v2_rejects_malformed_shapes() {
        let bad = |f: &dyn Fn(&mut ManifestV2)| {
            let mut m = sample_v2();
            f(&mut m);
            assert!(ManifestV2::decode(&m.encode().unwrap()).is_err());
        };
        bad(&|m| m.version = 1);
        bad(&|m| m.chunk_plain += 1);
        bad(&|m| {
            m.stripes[0].shard_hashes.pop();
        });
        bad(&|m| m.stripes[0].data = 0);
        bad(&|m| m.stripes[0].parity = 0);
        bad(&|m| m.stripes[0].last_object_len = V2_SHARD_BYTES as u32 + 1);
        bad(&|m| m.stripes[0].last_object_len = 0);
        // v1 の Manifest のバイト列は v2 として読めない（互換を切る）
        let v1 = Manifest { name: "x".into(), size: 1, chunk_refs: vec![[0u8; 32]] };
        assert!(ManifestV2::decode(&v1.encode().unwrap()).is_err());
    }

    #[test]
    fn oversized_manifest_v2_is_rejected() {
        let mut m = sample_v2();
        m.stripes = vec![sample_stripe(1, 1); MAX_STRIPES_PER_MANIFEST_V2 + 1];
        assert!(ManifestV2::decode(&m.encode().unwrap()).is_err());
    }

    #[test]
    fn counterfeit_shards_are_dropped_and_the_stripe_still_decodes() {
        use crate::mailbox::sharding_v2::{decode_stripe, encode_stripe};
        let k = 4;
        let m = 2;
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..V2_SHARD_BYTES).map(|j| (i * 13 + j) as u8).collect())
            .collect();
        let mut all = data.clone();
        all.extend(encode_stripe(&data, m).unwrap());
        let stripe = StripeV2 {
            data: k as u8,
            parity: m as u8,
            last_object_len: V2_SHARD_BYTES as u32,
            shard_hashes: all.iter().map(|s| shard_hash(s)).collect(),
        };
        // データ 1 枚を偽物にすり替え、もう 1 枚は短い偽物にし、パリティは正しいまま
        let mut got: Vec<Option<Vec<u8>>> = all.iter().cloned().map(Some).collect();
        got[0].as_mut().unwrap()[5] ^= 1;
        got[1] = Some(vec![0u8; 10]);
        let verified = stripe.keep_verified(&got);
        assert!(verified[0].is_none() && verified[1].is_none(), "偽物は捨てる");
        assert!(verified[2..].iter().all(|s| s.is_some()));
        assert_eq!(decode_stripe(k, m, &verified).unwrap(), data);
        // 偽物を捨てた結果 k 枚に満たなければ復元しない
        got[2] = None;
        assert!(decode_stripe(k, m, &stripe.keep_verified(&got)).is_err());
    }

    /// `send_onion_message_typed(packet_type, message, dest)` と同じ組み立て（`[PacketType 1][message]` を
    /// `build_typed_forward` で包み、`OnionCircuit::wrap_packet` を通す）のパケット長から、
    /// 切り上げ後の本文の大きさを逆算する
    ///
    /// パケット = `HEADER_LEN` + 切り上げた本文 + AEAD タグ 16。
    fn onion_bucket(packet_type: crate::protocol::wire::PacketType, message: &[u8], dest: std::net::SocketAddr) -> usize {
        use crate::net::onion::{OnionCircuit, HEADER_LEN};
        use crate::protocol::wire;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut circuit = OnionCircuit::new();
        for i in 0..3u8 {
            let s = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let addr: std::net::SocketAddr = format!("10.0.0.{}:9000", i + 1).parse().unwrap();
            circuit.add_hop(addr, PublicKey::from(&s).to_bytes()).unwrap();
        }
        let mut body = vec![packet_type as u8];
        body.extend_from_slice(message);
        let inner = wire::build_typed_forward(dest, &body).unwrap();
        let packet = circuit.wrap_packet(&inner).unwrap();
        packet.len() - HEADER_LEN - 16
    }

    /// 置く向き: 置く人の回路の出口が、保持者の受け口（GW_h）へ `TunnelData` を渡す
    fn put_bucket(shard_len: usize, gateway: std::net::SocketAddr) -> usize {
        use crate::net::holder::{build_gateway_data, HOLDER_PUT};
        let mut put = vec![0x80u8; 32]; // [put_key 32][シャード]
        put.extend(vec![0xAB; shard_len]);
        let message = build_gateway_data(&[5u8; 32], HOLDER_PUT, &put);
        onion_bucket(crate::protocol::wire::PacketType::TunnelData, &message, gateway)
    }

    /// 返す向き: 保持者の回路の出口が、取る人の返信トンネルの gateway へ `TunnelData` を渡す
    ///
    /// 保持者の返事は `[reply tunnel_id 32][値]`（値 = 保存されたシャードそのもの）。
    fn reply_bucket(shard_len: usize, reply_gateway: std::net::SocketAddr) -> usize {
        let mut message = vec![6u8; 32];
        message.extend(vec![0xAB; shard_len]);
        onion_bucket(crate::protocol::wire::PacketType::TunnelData, &message, reply_gateway)
    }

    #[test]
    fn v2_shard_bytes_fills_the_256k_onion_bucket() {
        use crate::net::onion::padded_len;
        let v6: std::net::SocketAddr = "[2001:db8::1]:9443".parse().unwrap();
        let v4: std::net::SocketAddr = "192.0.2.1:9443".parse().unwrap();
        assert_eq!(bincode::serialize(&v6).unwrap().len(), 22);
        assert_eq!(bincode::serialize(&v4).unwrap().len(), 10);

        // 組み立てた本文の長さを数式でも出す: 長さ 4 + 内側の種別 1 + 宛先 + PacketType 1 + tunnel_id 32
        // + HOLDER_PUT 1 + put_key 32 + シャード
        let put_fixed = |dest: &std::net::SocketAddr| 4 + 1 + bincode::serialize(dest).unwrap().len() + 1 + 32 + 1 + 32;
        assert_eq!(put_fixed(&v6) + V2_SHARD_BYTES, 262_144, "置く向きは IPv6 で隙間が無い");
        assert_eq!(padded_len(put_fixed(&v6) + V2_SHARD_BYTES), 262_144);
        assert_eq!(padded_len(put_fixed(&v6) + V2_SHARD_BYTES + 1), 524_288, "1 バイト増やすと倍のバケットに跳ねる");

        // 実際の onion パケットの長さからも確かめる（数式の転記ミスを防ぐ）。置く向き
        assert_eq!(put_bucket(V2_SHARD_BYTES, v6), 262_144);
        assert_eq!(put_bucket(V2_SHARD_BYTES + 1, v6), 524_288, "1 バイト増やすと置く向きが 524,288 に跳ねる");
        // IPv4 宛先でも同じバケット（長さで宛先の種類は見えない）
        assert_eq!(put_bucket(V2_SHARD_BYTES, v4), 262_144);

        // 返す向き。置く向きより短いので同じバケットに収まる
        assert_eq!(reply_bucket(V2_SHARD_BYTES, v6), 262_144, "返す向きも 256KiB に収まる");
        assert_eq!(reply_bucket(V2_SHARD_BYTES, v4), 262_144);

        // 保持者の 1 件の上限（MAX_ENTRY_BYTES = 1MiB）に収まる
        const { assert!(32 + V2_SHARD_BYTES <= 1024 * 1024) };
        // 収束暗号のオブジェクト（nonce 12 + 暗号文 + タグ 16）がシャードにちょうど入る
        assert_eq!(V2_CHUNK_PLAIN + V2_SEAL_OVERHEAD, V2_SHARD_BYTES);
    }

    #[test]
    fn manifest_v2_sealed_len_matches_a_real_manifest() {
        // 切り上げ込みのチャンク数（5MB → 20 → 32 など）でも、見積もりが実物と一致する
        let sizes = [(7usize, 5_000_000u64), (100, 300_000), (3, 40_000_000), (100, 3072 * V2_CHUNK_PLAIN as u64)];
        for (name_len, size) in sizes {
            for pad in [false, true] {
                let chunks = v2_layout_chunks(size, pad).unwrap();
                let shapes = v2_stripe_shapes(chunks).unwrap();
                assert_eq!(shapes.iter().map(|s| s.0).sum::<usize>(), chunks, "データシャード数の合計がチャンク数");
                let m = ManifestV2 {
                    version: MANIFEST_V2_VERSION,
                    name: "n".repeat(name_len),
                    size,
                    chunk_plain: V2_CHUNK_PLAIN as u32,
                    stripes: shapes
                        .iter()
                        .map(|&(k, p)| StripeV2 {
                            data: k as u8,
                            parity: p as u8,
                            last_object_len: V2_SHARD_BYTES as u32,
                            shard_hashes: vec![[0u8; 32]; k + p],
                        })
                        .collect(),
                };
                let real = m.encode().unwrap().len() + V2_SEAL_OVERHEAD;
                assert_eq!(manifest_v2_sealed_len(name_len, chunks).unwrap(), real, "見積もりが実測と一致");
            }
        }
    }

    #[test]
    fn padded_chunks_round_up_by_bytes_not_by_chunk_count() {
        let mib = 1u64 << 20;
        for (size, want) in [
            (1u64, 5usize),
            (mib, 5),
            (mib + 1, 9),
            (4 * mib, 17),
            (4 * mib + 1, 33),
            (32 * mib, 129),
            (32 * mib + 1, 257),
            (100_000_000, 513), // 2^27 バイトの刻み
        ] {
            assert_eq!(padded_chunks_for_size(size, 10_000), want, "size = {}", size);
        }
        // 頭打ち: 上限を超える刻みは上限になる
        assert_eq!(padded_chunks_for_size(4 * mib + 1, 20), 20);
        assert_eq!(padded_chunks_for_size(1, 3), 3, "最小の刻みより上限が小さいときも上限");
        // 本物のチャンク数以上になる（上限に収まるファイルについて）
        for size in [1u64, V2_CHUNK_PLAIN as u64, V2_CHUNK_PLAIN as u64 + 1, mib, 4 * mib, 4 * mib + 1, 100_000_000] {
            assert!(padded_chunks_for_size(size, 10_000) >= v2_chunk_count(size), "size = {}", size);
        }
    }

    #[test]
    fn layout_pads_but_never_exceeds_the_file_limit() {
        let plain = V2_CHUNK_PLAIN as u64;
        // 1MiB 以下は 5 チャンク、1MiB を 1 バイト超えると 2MiB の刻みで 9 チャンク。pad=false なら切り上げない
        assert_eq!(v2_layout_chunks(4 * plain + 1, true).unwrap(), 5);
        assert_eq!(v2_layout_chunks(4 * plain + 1, false).unwrap(), 5);
        assert_eq!(v2_layout_chunks(V2_MIN_BUCKET_BYTES + 1, true).unwrap(), 9);
        assert_eq!(v2_layout_chunks(V2_MIN_BUCKET_BYTES + 1, false).unwrap(), 5);
        assert_eq!(v2_layout_chunks(4 << 20, true).unwrap(), 17, "ちょうど 4MiB は 17 チャンク");
        assert_eq!(v2_layout_chunks((4 << 20) + 1, true).unwrap(), 33);
        assert_eq!(v2_layout_chunks(1, true).unwrap(), 5, "小さいファイルも 1MiB の刻み");
        assert_eq!(v2_layout_chunks(1, false).unwrap(), 1);
        // 上限ちょうどは通り、切り上げでも上限を超えない
        let max = max_chunks_file();
        assert_eq!(v2_layout_chunks(MAX_FILE_BYTES, true).unwrap(), max);
        assert_eq!(v2_layout_chunks(MAX_FILE_BYTES, false).unwrap(), max);
        assert_eq!(v2_layout_chunks(MAX_FILE_BYTES - 1, true).unwrap(), max, "上限直下も刻みは上限");
        // 上限を超えれば pad の有無にかかわらず断る
        assert!(v2_layout_chunks(MAX_FILE_BYTES + 1, true).is_err());
        assert!(v2_layout_chunks(MAX_FILE_BYTES + 1, false).is_err());
        assert!(v2_layout_chunks(0, true).is_err());
    }

    #[test]
    fn buckets_are_powers_of_two_up_to_1gib_then_quarter_power_steps() {
        let gib = 1u64 << 30;
        // 1GiB まで: 2 の冪（最小 1MiB）
        assert_eq!(size_bucket_bytes(1), V2_MIN_BUCKET_BYTES);
        assert_eq!(size_bucket_bytes(gib / 2), gib / 2);
        assert_eq!(size_bucket_bytes(gib / 2 + 1), gib);
        assert_eq!(size_bucket_bytes(gib), gib, "ちょうど 1GiB は 1GiB のまま");
        // 1GiB を超えたら 1/4 乗刻み
        assert_eq!(size_bucket_bytes(gib + 1), gib * 4871 / 4096);
        let table: Vec<u64> = [gib + 1, gib * 4871 / 4096 + 1, gib * 5793 / 4096 + 1, gib * 6889 / 4096 + 1, 2 * gib + 1]
            .iter()
            .map(|&s| size_bucket_bytes(s))
            .collect();
        assert_eq!(table, vec![gib * 4871 / 4096, gib * 5793 / 4096, gib * 6889 / 4096, 2 * gib, gib * 2 * 4871 / 4096]);
        // 刻みの境目: ちょうどの値はその刻みに入り、1 バイト増えると次へ
        for b in [gib * 4871 / 4096, gib * 5793 / 4096, gib * 6889 / 4096, 2 * gib, 4 * gib, 64 * gib] {
            assert_eq!(size_bucket_bytes(b), b);
            assert!(size_bucket_bytes(b + 1) > b);
        }
        // 刻みは単調で、無駄は 19% 以内（1GiB 超）。2 の 1/4 乗の近似
        let mut prev = 0;
        let mut size = gib + 1;
        while size < MAX_FILE_BYTES {
            let b = size_bucket_bytes(size);
            assert!(b >= size && b >= prev);
            assert!((b as f64) / (size as f64) < 1.19, "size = {}, bucket = {}", size, b);
            prev = b;
            size += gib / 7;
        }
        // 1GiB 超の刻みは 2 倍ごとに 4 つ（表を倍々にする）。1〜8GiB の表
        let mut expect = Vec::new();
        for e in 0..3u32 {
            for step in [4096u64, 4871, 5793, 6889] {
                expect.push((gib << e) / 4096 * step);
            }
        }
        expect.push(8 * gib);
        let mut got = Vec::new();
        let mut size = gib;
        while size <= 8 * gib {
            let b = size_bucket_bytes(size);
            got.push(b);
            size = b + 1;
        }
        assert_eq!(got, expect);
        assert_eq!(size_bucket_bytes(MAX_FILE_BYTES), MAX_FILE_BYTES, "上限は刻みの値");
    }

    #[test]
    fn padded_chunks_never_fall_below_the_real_count_and_never_pass_the_file_limit() {
        let gib = 1u64 << 30;
        let max = max_chunks_file();
        for size in [1u64, gib - 1, gib, gib + 1, 3 * gib, 10 * gib + 12345, MAX_FILE_BYTES - 1, MAX_FILE_BYTES] {
            let padded = padded_chunks_for_size(size, max);
            assert!(padded >= v2_chunk_count(size), "size = {}", size);
            assert!(padded <= max, "size = {}", size);
        }
        // 1.1GiB は 1.19GiB の刻み（2GiB には上がらない）
        let want = (gib * 4871 / 4096).div_ceil(V2_CHUNK_PLAIN as u64) as usize;
        assert_eq!(padded_chunks_for_size(gib + gib / 10, max), want);
    }

    #[test]
    fn plan_is_single_when_the_stripes_fit_and_a_tree_otherwise() {
        // 小さなファイルは今の ManifestV2 のまま
        let small = v2_layout_chunks(5_000_000, true).unwrap();
        assert_eq!(plan_manifest(20, small, None).unwrap(), ManifestPlan::Single);
        // 800MB（旧い上限）まで 1 つの ManifestV2 に収まる
        let max_single = max_chunks_v2(20);
        assert_eq!(plan_manifest(20, max_single, None).unwrap(), ManifestPlan::Single);
        // 超えたら木
        let ManifestPlan::Tree { per_page } = plan_manifest(20, max_single + 1, None).unwrap() else {
            panic!("tree expected");
        };
        let m = v2_stripe_shapes(max_single + 1).unwrap()[0].1;
        assert_eq!(per_page, manifest_page_stripes(m));
        // 試験の口: ページの大きさを小さくすると、小さなファイルでも木になる
        let five_stripes = 5 * V2_DATA_PER_STRIPE;
        assert_eq!(plan_manifest(20, five_stripes, Some(2)).unwrap(), ManifestPlan::Tree { per_page: 2 });
        assert_eq!(plan_manifest(20, five_stripes, Some(5)).unwrap(), ManifestPlan::Single, "収まるなら 1 つ");
        // 上限の大きさでも根が収まる
        let top = v2_layout_chunks(MAX_FILE_BYTES, true).unwrap();
        let ManifestPlan::Tree { per_page } = plan_manifest(MAX_FILE_NAME_FOR_TEST, top, None).unwrap() else {
            panic!("tree expected");
        };
        let stripes = top.div_ceil(V2_DATA_PER_STRIPE);
        let pages = stripes.div_ceil(per_page);
        assert!(manifest_root_sealed_len(MAX_FILE_NAME_FOR_TEST, pages) <= SINGLE_BODY_LIMIT);
        assert!(pages < 200, "pages = {}", pages);
        // 上限を超える大きさのチャンク数は断る
        assert!(plan_manifest(20, top * 2, None).is_err());
    }

    const MAX_FILE_NAME_FOR_TEST: usize = 255;

    #[test]
    fn page_ranges_split_stripes_in_order() {
        assert_eq!(page_ranges(5, 2), vec![0..2, 2..4, 4..5]);
        assert_eq!(page_ranges(4, 2), vec![0..2, 2..4]);
        assert_eq!(page_ranges(1, 188), vec![0..1]);
        assert!(page_ranges(0, 3).is_empty());
        assert_eq!(page_ranges(3, 0), vec![0..1, 1..2, 2..3], "0 は 1 として数える");
        // どのストライプもちょうど 1 回、順番どおりに入る
        let flat: Vec<usize> = page_ranges(1000, 188).into_iter().flatten().collect();
        assert_eq!(flat, (0..1000).collect::<Vec<_>>());
    }

    fn full_stripe(m: usize) -> StripeV2 {
        StripeV2 {
            data: V2_DATA_PER_STRIPE as u8,
            parity: m as u8,
            last_object_len: V2_SHARD_BYTES as u32,
            shard_hashes: vec![[7u8; 32]; V2_DATA_PER_STRIPE + m],
        }
    }

    #[test]
    fn manifest_page_fits_the_single_body_limit_and_estimate_matches_the_real_one() {
        for m in [1usize, 5, 27, 40] {
            let per = manifest_page_stripes(m);
            let page = ManifestPage { stripes: vec![full_stripe(m); per] };
            let real = page.encode().unwrap().len() + V2_SEAL_OVERHEAD;
            assert!(real <= SINGLE_BODY_LIMIT, "m = {}: {} バイト", m, real);
            assert_eq!(real, manifest_page_sealed_len(&vec![(V2_DATA_PER_STRIPE, m); per]), "見積もりが実物と一致");
            // もう 1 つ入れると収まらない（既定は収まる最大）
            let over = ManifestPage { stripes: vec![full_stripe(m); per + 1] };
            assert!(over.encode().unwrap().len() + V2_SEAL_OVERHEAD > SINGLE_BODY_LIMIT, "m = {}", m);
        }
        assert_eq!(manifest_page_stripes(27), 188);
    }

    #[test]
    fn manifest_root_and_page_roundtrip_and_reject_bad_shapes() {
        let root = ManifestRoot {
            version: MANIFEST_ROOT_VERSION,
            name: "big.iso".into(),
            size: 5_000_000_000,
            chunk_plain: V2_CHUNK_PLAIN as u32,
            stripe_count: 1200,
            pages: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32]],
        };
        let bytes = root.encode().unwrap();
        assert_eq!(ManifestRoot::decode(&bytes).unwrap(), root);
        assert_eq!(
            bytes.len() + V2_SEAL_OVERHEAD,
            manifest_root_sealed_len("big.iso".len(), root.pages.len()),
            "見積もりが実物と一致"
        );
        // 根は ManifestV2 としては読めない（取る側が見分ける）
        assert!(ManifestV2::decode(&bytes).is_err());
        let bad = |f: &dyn Fn(&mut ManifestRoot)| {
            let mut r = root.clone();
            f(&mut r);
            assert!(ManifestRoot::decode(&r.encode().unwrap()).is_err());
        };
        bad(&|r| r.version = MANIFEST_V2_VERSION);
        bad(&|r| r.chunk_plain += 1);
        bad(&|r| r.size = MAX_FILE_BYTES + 1);
        bad(&|r| r.stripe_count = max_stripes_file() as u64 + 1);
        bad(&|r| r.pages.clear());
        bad(&|r| r.stripe_count = 3);

        let page = ManifestPage { stripes: vec![full_stripe(27); 3] };
        assert_eq!(ManifestPage::decode(&page.encode().unwrap()).unwrap(), page);
        assert!(ManifestPage::decode(&ManifestPage { stripes: Vec::new() }.encode().unwrap()).is_err());
        let mut broken = page.clone();
        broken.stripes[1].shard_hashes.pop();
        assert!(ManifestPage::decode(&broken.encode().unwrap()).is_err());
        // ページは根としても ManifestV2 としても読めない
        assert!(ManifestRoot::decode(&page.encode().unwrap()).is_err());
        // ManifestV2 は根としては読めない
        let v2 = ManifestV2 {
            version: MANIFEST_V2_VERSION,
            name: "a".into(),
            size: 10,
            chunk_plain: V2_CHUNK_PLAIN as u32,
            stripes: vec![full_stripe(3)],
        };
        assert!(ManifestRoot::decode(&v2.encode().unwrap()).is_err());
    }

    #[test]
    fn pad_chunk_is_per_file_per_board_and_deterministic() {
        let (s1, s2) = ([1u8; 32], [2u8; 32]);
        let (f1, f2) = ([10u8; 32], [11u8; 32]);
        let p = pad_chunk_plain(&s1, &f1, 0);
        assert_eq!(p.len(), V2_CHUNK_PLAIN);
        assert!(p[32..].iter().all(|&b| b == 0), "タグ以外はゼロ");
        assert_ne!(&p[..32], &[0u8; 32][..], "タグはゼロではない");
        assert_eq!(p, pad_chunk_plain(&s1, &f1, 0), "同じファイル・同じ板なら同じ");
        assert_ne!(p, pad_chunk_plain(&s1, &f2, 0), "ファイルが違えば違う");
        assert_ne!(p, pad_chunk_plain(&s2, &f1, 0), "板が違えば違う");
        assert_ne!(p, pad_chunk_plain(&s1, &f1, 1), "添字が違えば違う");
    }

    #[test]
    fn v2_stripe_shapes_give_short_last_stripe_proportional_parity() {
        // 2 本 + 3 チャンクの短い 3 本目
        let shapes = v2_stripe_shapes(2 * 16 + 3).unwrap();
        assert_eq!(shapes.len(), 3);
        let m = shapes[0].1;
        assert_eq!(shapes[1], (16, m));
        assert_eq!(shapes[2], (3, (m * 3).div_ceil(16).max(1)));
        assert!(v2_stripe_shapes(0).is_err());
    }

    #[test]
    fn v2_size_limit_boundary_with_a_100_byte_name() {
        let fit = |stripes: usize| {
            manifest_v2_sealed_len(100, stripes * V2_DATA_PER_STRIPE).unwrap() <= SINGLE_BODY_LIMIT
        };
        assert!(fit(192), "192 ストライプは Manifest が 1 オブジェクトに収まる");
        assert!(!fit(193), "193 ストライプは収まらない");
        let max = max_chunks_v2(100);
        assert!((192 * V2_DATA_PER_STRIPE..193 * V2_DATA_PER_STRIPE).contains(&max), "上限は 192〜193 ストライプの間: {}", max);
        // 上限ちょうどは通り、1 チャンク足すと超える
        assert!(manifest_v2_sealed_len(100, max).unwrap() <= SINGLE_BODY_LIMIT);
        assert!(manifest_v2_sealed_len(100, max + 1).unwrap() > SINGLE_BODY_LIMIT);
        assert!(max_chunks_v2(1000) <= max, "名前が長いほど上限は増えない");
    }

    #[test]
    fn needs_chunking_boundary() {
        assert!(!needs_chunking(SINGLE_BODY_LIMIT));
        assert!(needs_chunking(SINGLE_BODY_LIMIT + 1));
    }
}
