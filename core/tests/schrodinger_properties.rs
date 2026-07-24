//! シュレーディンガー Mailbox の性質そのものを検証する (設計書 11.6)
//!
//! e2e_schrodinger.rs が「往復が成立するか」を見るのに対して、
//! こちらは **成立してはいけないこと** を見る。
//!
//! | 11.6 の特性 | ここで検証する形 |
//! |---|---|
//! | Mailbox 匿名性 | 保存される平文バイト列に宛先も本文も現れない |
//! | Hint 匿名性 | 共有秘密を持たない者は復号もタグ照合もできない |
//! | 受信者匿名性 | 同じ宛先へ2回送っても Hint 同士が結びつかない |
//! | （18.5.4 追加分） | 保持者同士が「同じ本体の断片だ」と気づけない |
//! | （18.5.4 追加分） | 保持者1台の偽造で復元が止まらない |

use aether_core::crypto::identity::NodeId;
use aether_core::mailbox::schrodinger::SchrodingerMailbox;
use aether_core::mailbox::sharding;
use aether_core::net::gossip::GossipClient;
use aether_core::net::relay::RelayClient;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn mailbox_for(peer: NodeId, secret: [u8; 32]) -> SchrodingerMailbox {
    let mut c = HashMap::new();
    c.insert(peer, secret);
    SchrodingerMailbox::new(
        Arc::new(RelayClient::new().unwrap()),
        Arc::new(GossipClient::new(RelayClient::new().unwrap())),
        Arc::new(Mutex::new(c)),
    )
}

const BOB: NodeId = NodeId([0xB0; 32]);
const SECRET: [u8; 32] = [0x5A; 32];

/// 保持者が実際に受け取るバイト列を組み立てる
fn sealed_shards(mb: &SchrodingerMailbox, msg: &[u8]) -> ([u8; 32], Vec<Vec<u8>>) {
    let (payload, _) = mb.prepare_packet(&BOB, msg).unwrap();
    let mailbox_key: [u8; 32] = payload[0..32].try_into().unwrap();
    let mac_key = mb.shard_mac_key_for(&SECRET);

    let sealed = sharding::encode(&payload[32..])
        .unwrap()
        .iter()
        .map(|s| sharding::seal(s, &mailbox_key, &mac_key))
        .collect();

    (mailbox_key, sealed)
}

#[tokio::test]
async fn the_holder_learns_neither_content_nor_recipient() {
    // 11.6「Mailbox 匿名性」。保持者が持つのは
    // [shard_key][封をした断片] だけで、そこに宛先も本文も現れてはならない
    let mb = mailbox_for(BOB, SECRET);
    let plaintext = b"the quick brown fox jumps over the lazy dog";

    let (mailbox_key, shards) = sealed_shards(&mb, plaintext);

    for (i, shard) in shards.iter().enumerate() {
        let stored = [&sharding::shard_key(&mailbox_key, i as u8)[..], shard].concat();

        assert!(
            !contains(&stored, BOB.as_bytes()),
            "shard {} に宛先 NodeId が含まれている",
            i
        );
        assert!(
            !contains(&stored, plaintext),
            "shard {} に平文が含まれている",
            i
        );
        assert!(
            !contains(&stored, &SECRET),
            "shard {} に共有秘密が含まれている",
            i
        );
        assert!(
            !contains(&stored, &mailbox_key),
            "shard {} に mailbox_key が生で含まれている\n\
             （含まれると保持者が他の全断片のキーを計算できてしまう）",
            i
        );
    }
}

#[tokio::test]
async fn colluding_holders_cannot_tell_they_hold_the_same_body() {
    // 18.5.4 の前提。断片ごとのキーは H(mailbox_key ‖ i) なので、
    // mailbox_key を知らない保持者同士は互いのキーを計算できない。
    //
    // ここが崩れると、リング上の離れた3箇所を押さえる必要という
    // 検閲耐性の根拠が消える
    let mb = mailbox_for(BOB, SECRET);
    let (mailbox_key, _) = sealed_shards(&mb, b"censored material");

    let keys: Vec<_> = (0..sharding::TOTAL_SHARDS as u8)
        .map(|i| sharding::shard_key(&mailbox_key, i))
        .collect();

    for (i, a) in keys.iter().enumerate() {
        for (j, b) in keys.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "shard {} と {} のキーが同じ", i, j);
            }
        }
    }

    // 隣接インデックスでも相関が見えないこと（共通接頭辞ゼロ）
    assert_ne!(keys[0][0..4], keys[1][0..4]);
}

#[tokio::test]
async fn a_stranger_cannot_recognise_the_hint() {
    // 11.6「Hint 匿名性」。共有秘密を持たない者は
    // blind_tag 照合の段階で落ちる
    let alice = mailbox_for(BOB, SECRET);
    let (_, hint) = alice.prepare_packet(&BOB, b"for bob only").unwrap();

    let eavesdropper = mailbox_for(BOB, [0xEE; 32]);

    assert!(
        eavesdropper.try_decrypt_hint(&hint).is_none(),
        "別の共有秘密で Hint が開いた"
    );

    // 正規の受信者は開ける
    let bob = mailbox_for(BOB, SECRET);
    assert!(bob.try_decrypt_hint(&hint).is_some(), "本人が開けない");
}

#[tokio::test]
async fn two_sends_to_the_same_peer_are_unlinkable() {
    // 11.6「受信者匿名性」。同じ宛先へ同じ本文を2回送っても、
    // 観測者から見て同一宛先だと分かってはならない。
    //
    // mailbox_key = SHA256(毎回引き直す nonce) なので、
    // ここが一致したら nonce の生成が壊れている
    let mb = mailbox_for(BOB, SECRET);
    let msg = b"identical payload sent twice";

    let (p1, h1) = mb.prepare_packet(&BOB, msg).unwrap();
    let (p2, h2) = mb.prepare_packet(&BOB, msg).unwrap();

    assert_ne!(p1[0..32], p2[0..32], "mailbox_key が使い回されている");
    assert_ne!(h1.blind_tag, h2.blind_tag, "blind_tag が宛先の指紋になっている");
    assert_ne!(h1.nonce, h2.nonce, "Hint nonce が使い回されている");
    assert_ne!(h1.ciphertext, h2.ciphertext, "同じ本文が同じ暗号文になっている");
}

#[tokio::test]
async fn one_malicious_holder_cannot_block_retrieval() {
    // 18.5.4 が Part 11 から落とした性質の回帰テスト。
    //
    // 分割前は GET が本体まるごとを返し、AEAD がその場で偽物を弾いていた。
    // 分割後は3枚合成するまで検証できないため、断片ごとの封が要る。
    // これが無いと K レプリカ中1台の悪意で復元が永久に止まる
    let mb = mailbox_for(BOB, SECRET);
    let plaintext = b"the message everyone wants";
    let (mailbox_key, honest) = sealed_shards(&mb, plaintext);

    let mut forged = honest[0].clone();
    forged[10] ^= 0xFF; // 保持者は index も長さも見えているので形は保てる

    // 偽物が **先に** 届く。先着順で採用すると本物が捨てられる
    let mut replies = vec![forged];
    replies.extend(honest);

    let recovered = mb
        .reassemble(&replies, &mailbox_key, &SECRET)
        .expect("偽造断片で復元がエラーになった")
        .expect("3枚揃っているのに復元できていない");

    assert_eq!(recovered, plaintext);
}

#[tokio::test]
async fn shards_of_a_different_message_are_rejected() {
    // 封は mailbox_key ごと計算するので、別メッセージの断片は混ざらない。
    // 同時受信時に取り違えると、どちらも復元できなくなる
    let mb = mailbox_for(BOB, SECRET);
    let (key_a, shards_a) = sealed_shards(&mb, b"message A, the first one");
    let (_key_b, shards_b) = sealed_shards(&mb, b"message B, the second one");

    let mut mixed = shards_b;
    mixed.extend(shards_a);

    let recovered = mb
        .reassemble(&mixed, &key_a, &SECRET)
        .expect("混在でエラーになった")
        .expect("A の断片は揃っているのに復元できていない");

    assert_eq!(recovered, b"message A, the first one");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
