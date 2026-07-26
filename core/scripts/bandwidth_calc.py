#!/usr/bin/env python3
"""
AETHER Hint Broadcast 帯域シミュレーター

全ノードが全Hintを受信する前提で、ネットワーク全体のHint発生量と
各ノードが必要とするDL/UL帯域を計算する。
"""

HINT_SIZE_BYTES = 120  # blind_tag(4) + nonce(12) + ciphertext(64) + ttl(4) + pow(12) + overhead(~24)

# Gossip のファンアウト（各ノードが何ノードに転送するか）
# 典型的な Gossip protocol は log2(N) ~ 数ノードに転送する
# 重複受信があるため、実効ULはDLの fanout 倍程度になる
GOSSIP_FANOUT = 6  # 保守的な値

# 帯域の比較基準
BANDWIDTH_TIERS = [
    ("SD動画 (YouTube 480p)",   2.5),
    ("HD動画 (YouTube 720p)",   5.0),
    ("FHD動画 (YouTube 1080p)", 8.0),
    ("4K動画 (YouTube 2160p)",  25.0),
    ("一般的な光回線の1%",      10.0),
    ("一般的な光回線の5%",      50.0),
    ("一般的な光回線の10%",    100.0),
]


def calc_hints_per_sec(
    total_users: int,
    active_ratio: float,
    chat_interval_sec: float,
    shared_files_per_user: int,
    republish_interval_sec: float,
    new_file_interval_sec: float,
    group_chats: int = 0,
    group_msg_interval_sec: float = 5.0,
    group_members: int = 50,
) -> dict:
    """ネットワーク全体のHint発生率を計算"""

    active_users = total_users * active_ratio

    # 1) 1対1チャット: アクティブユーザーが chat_interval_sec ごとに1通
    chat_hps = active_users / chat_interval_sec if chat_interval_sec > 0 else 0

    # 2) グループチャット: 各グループで group_msg_interval_sec ごとに誰かが発言
    #    → 1通の発言 = 1 Hint（グループ全員が同じHintを受信するので1通）
    group_hps = group_chats / group_msg_interval_sec if group_msg_interval_sec > 0 else 0

    # 3) ファイル再放流: 各アクティブユーザーの保持ファイルが定期的にHintを再放流
    republish_hps = (active_users * shared_files_per_user / republish_interval_sec
                     if republish_interval_sec > 0 else 0)

    # 4) 新規ファイル公開: アクティブユーザーが new_file_interval_sec ごとに1件
    new_file_hps = active_users / new_file_interval_sec if new_file_interval_sec > 0 else 0

    total_hps = chat_hps + group_hps + republish_hps + new_file_hps

    return {
        "total_users": total_users,
        "active_users": int(active_users),
        "chat_hps": chat_hps,
        "group_hps": group_hps,
        "republish_hps": republish_hps,
        "new_file_hps": new_file_hps,
        "total_hps": total_hps,
    }


def calc_bandwidth(total_hps: float) -> dict:
    """Hint発生率から帯域を計算"""
    dl_bytes_sec = total_hps * HINT_SIZE_BYTES
    dl_mbps = dl_bytes_sec * 8 / 1_000_000

    # UL: Gossip転送のファンアウト分
    ul_mbps = dl_mbps * GOSSIP_FANOUT

    return {
        "dl_bytes_sec": dl_bytes_sec,
        "dl_mbps": dl_mbps,
        "ul_mbps": ul_mbps,
    }


def find_tier(mbps: float) -> str:
    """帯域がどのティアに相当するか"""
    for name, threshold in BANDWIDTH_TIERS:
        if mbps <= threshold:
            return f"< {name} ({threshold} Mbps)"
    return f"> {BANDWIDTH_TIERS[-1][0]}"


def max_users_for_bandwidth(
    target_mbps: float,
    active_ratio: float,
    chat_interval_sec: float,
    shared_files_per_user: int,
    republish_interval_sec: float,
    new_file_interval_sec: float,
) -> int:
    """指定帯域で捌ける最大ユーザー数を逆算"""
    # 1ユーザーあたりのHint発生率
    per_user = active_ratio / chat_interval_sec if chat_interval_sec > 0 else 0
    per_user += (active_ratio * shared_files_per_user / republish_interval_sec
                 if republish_interval_sec > 0 else 0)
    per_user += active_ratio / new_file_interval_sec if new_file_interval_sec > 0 else 0

    if per_user <= 0:
        return 999_999_999

    max_hps = target_mbps * 1_000_000 / 8 / HINT_SIZE_BYTES
    return int(max_hps / per_user)


# ============================================================
# シナリオ定義
# ============================================================

scenarios = [
    {
        "name": "🟢 ライト（のんびりチャット + 少量共有）",
        "desc": "1分に1通、保持50件、1時間ごと再放流、30分に1件公開",
        "total_users": 100_000,
        "active_ratio": 0.15,
        "chat_interval_sec": 60,
        "shared_files_per_user": 50,
        "republish_interval_sec": 3600,
        "new_file_interval_sec": 1800,
        "group_chats": 0,
    },
    {
        "name": "🟡 ミディアム（活発なチャット + 普通の共有）",
        "desc": "10秒に1通、保持200件、30分ごと再放流、10分に1件公開",
        "total_users": 100_000,
        "active_ratio": 0.25,
        "chat_interval_sec": 10,
        "shared_files_per_user": 200,
        "republish_interval_sec": 1800,
        "new_file_interval_sec": 600,
        "group_chats": 0,
    },
    {
        "name": "🟠 ヘビー（激しい議論 + 大量共有）",
        "desc": "5秒に1通、保持500件、15分ごと再放流、5分に1件公開",
        "total_users": 100_000,
        "active_ratio": 0.30,
        "chat_interval_sec": 5,
        "shared_files_per_user": 500,
        "republish_interval_sec": 900,
        "new_file_interval_sec": 300,
        "group_chats": 0,
    },
    {
        "name": "🔴 エクストリーム（全員常時発言 + 大量共有 + グループ）",
        "desc": "3秒に1通、保持1000件、10分ごと再放流、2分に1件公開、100グループ",
        "total_users": 100_000,
        "active_ratio": 0.50,
        "chat_interval_sec": 3,
        "shared_files_per_user": 1000,
        "republish_interval_sec": 600,
        "new_file_interval_sec": 120,
        "group_chats": 100,
        "group_msg_interval_sec": 3,
        "group_members": 50,
    },
    {
        "name": "⚫ 地獄（ストレステスト：現実ではありえない負荷）",
        "desc": "1秒に1通、保持2000件、5分ごと再放流、30秒に1件公開、500グループ",
        "total_users": 100_000,
        "active_ratio": 0.80,
        "chat_interval_sec": 1,
        "shared_files_per_user": 2000,
        "republish_interval_sec": 300,
        "new_file_interval_sec": 30,
        "group_chats": 500,
        "group_msg_interval_sec": 1,
        "group_members": 100,
    },
]


def print_separator():
    print("=" * 90)


def run():
    print()
    print("AETHER Hint Broadcast 帯域シミュレーション")
    print(f"Hint パケットサイズ: {HINT_SIZE_BYTES} bytes")
    print(f"Gossip ファンアウト: {GOSSIP_FANOUT} (UL = DL × {GOSSIP_FANOUT})")
    print_separator()

    for sc in scenarios:
        print()
        print(f"【{sc['name']}】")
        print(f"  {sc['desc']}")
        print()

        # ---- ユーザー数別の計算 ----
        user_counts = [1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000]

        print(f"  {'ユーザー数':>12}  {'アクティブ':>10}  {'Hints/sec':>12}  "
              f"{'DL帯域':>12}  {'UL帯域':>12}  相当")
        print(f"  {'-'*12}  {'-'*10}  {'-'*12}  {'-'*12}  {'-'*12}  {'-'*20}")

        for n in user_counts:
            result = calc_hints_per_sec(
                total_users=n,
                active_ratio=sc["active_ratio"],
                chat_interval_sec=sc["chat_interval_sec"],
                shared_files_per_user=sc["shared_files_per_user"],
                republish_interval_sec=sc["republish_interval_sec"],
                new_file_interval_sec=sc["new_file_interval_sec"],
                group_chats=sc.get("group_chats", 0),
                group_msg_interval_sec=sc.get("group_msg_interval_sec", 5),
                group_members=sc.get("group_members", 50),
            )
            bw = calc_bandwidth(result["total_hps"])

            tier = find_tier(bw["dl_mbps"])

            print(f"  {n:>12,}  {result['active_users']:>10,}  "
                  f"{result['total_hps']:>12,.1f}  "
                  f"{bw['dl_mbps']:>10.2f} M  "
                  f"{bw['ul_mbps']:>10.2f} M  "
                  f"{tier}")

        # ---- Hint内訳（10万人の場合） ----
        result = calc_hints_per_sec(
            total_users=100_000,
            active_ratio=sc["active_ratio"],
            chat_interval_sec=sc["chat_interval_sec"],
            shared_files_per_user=sc["shared_files_per_user"],
            republish_interval_sec=sc["republish_interval_sec"],
            new_file_interval_sec=sc["new_file_interval_sec"],
            group_chats=sc.get("group_chats", 0),
            group_msg_interval_sec=sc.get("group_msg_interval_sec", 5),
            group_members=sc.get("group_members", 50),
        )

        print()
        print(f"  📊 10万人時の内訳:")
        print(f"     チャット:     {result['chat_hps']:>10,.1f} hints/sec")
        print(f"     グループ:     {result['group_hps']:>10,.1f} hints/sec")
        print(f"     再放流:       {result['republish_hps']:>10,.1f} hints/sec")
        print(f"     新規公開:     {result['new_file_hps']:>10,.1f} hints/sec")
        print(f"     合計:         {result['total_hps']:>10,.1f} hints/sec")

        print_separator()

    # ---- 逆算: 各帯域で捌ける最大ユーザー数 ----
    print()
    print("【逆算】指定DL帯域で捌ける最大ユーザー数")
    print()

    bandwidth_targets = [1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0]

    header = f"  {'シナリオ':　<20}"
    for bw in bandwidth_targets:
        header += f"  {bw:>6.1f}M"
    print(header)
    print("  " + "-" * (22 + len(bandwidth_targets) * 8))

    for sc in scenarios:
        row = f"  {sc['name'][:20]:　<20}"
        for bw in bandwidth_targets:
            max_n = max_users_for_bandwidth(
                target_mbps=bw,
                active_ratio=sc["active_ratio"],
                chat_interval_sec=sc["chat_interval_sec"],
                shared_files_per_user=sc["shared_files_per_user"],
                republish_interval_sec=sc["republish_interval_sec"],
                new_file_interval_sec=sc["new_file_interval_sec"],
            )
            if max_n >= 1_000_000:
                row += f"  {max_n/1_000_000:>5.1f}M"
            elif max_n >= 1_000:
                row += f"  {max_n/1_000:>5.1f}K"
            else:
                row += f"  {max_n:>6}"
            
        print(row)

    print()
    print("※ M = 百万人, K = 千人")
    print("※ DL帯域のみ表示。UL帯域 = DL × Gossipファンアウト(6)")
    print("※ Winny ピーク同時接続: 約20万人")
    print()


if __name__ == "__main__":
    run()
