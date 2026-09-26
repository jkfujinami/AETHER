#!/usr/bin/env python3
"""AETHER 匿名性分析 (docs/anonymity/analysis.md) の数値を再現するスクリプト。

標準ライブラリのみ。数秒以内に終わる。重いモンテカルロは行わない
（唯一のシミュレーションは cover_overlap_probability の解析式で代替）。

実行:
    python3 docs/anonymity/compute.py
"""

import math
from itertools import product

# ---------------------------------------------------------------------------
# コード中の実際の定数（脚注はファイル:行）
# ---------------------------------------------------------------------------

# core/src/net/onion.rs:43
MAX_HOPS = 3

# core/src/net/guard.rs:35,41,44
GUARD_SAMPLE_SIZE = 3
GUARD_ROTATION_SECS = 60 * 24 * 3600  # 60日
MAX_CONSECUTIVE_FAILURES = 3

# core/src/net/dandelion.rs:33,36
FLUFF_PROBABILITY = 0.25
EXPECTED_STEM_LENGTH = 1.0 / FLUFF_PROBABILITY  # 4 ホップ
DANDELION_EPOCH_SECS = 10 * 60

# core/src/config.rs:79 (Hint PoW, SHA-256, 全ノード検証)
HINT_POW_DIFFICULTY_BITS = 10
# core/src/crypto/pow.rs:116, core/src/config.rs:80,82 (NodeId/Directory PoW, Argon2id)
NODE_ID_POW_DIFFICULTY_BITS = 16

# core/src/mailbox/schrodinger.rs:32
K_REPLICAS = 5
# core/src/mailbox/sharding.rs:25,28,31
DATA_SHARDS = 3
PARITY_SHARDS = 2
TOTAL_SHARDS = DATA_SHARDS + PARITY_SHARDS
assert TOTAL_SHARDS == K_REPLICAS

# client/src/receive.rs:37,39
FETCH_JITTER_MAX_SECS = 60.0
COVER_FETCH_MEAN_SECS = 90.0
SESSION_LIFETIME_SECS = 10 * 60  # client/src/receive.rs:24

# core/src/mailbox/hint_release.rs:40,46,52,61,69,72,78,83
NOISE_WINDOW_SECS = 8.0
ENVELOPE_FACTOR = 10.0
PATIENCE_FACTOR = 2.0
MIN_PATIENCE_SECS = 60.0
MIN_USEFUL_ANONYMITY_SET = 2.0
DEFAULT_TARGET_ANONYMITY_SET = 100.0
DEFAULT_MAX_DELAY_SECS = 6 * 3600
DEFAULT_RELAY_THROUGHPUT_BPS = 125_000.0

# core/src/net/epoch.rs:39
RING_EPOCH_SECS = 24 * 60 * 60

# ---------------------------------------------------------------------------
# 分析で使う仮定（パラメータ）── 明示的にここに置く
# ---------------------------------------------------------------------------

NETWORK_SIZES = [1_000, 10_000, 100_000]
ADVERSARY_FRACTIONS = [0.01, 0.05, 0.1, 0.2]
# 仮定: 1接続 (=1回路) あたり 1 回のガード・出口選択が発生し、
# ユーザーは1日あたり CIRCUITS_PER_DAY 回、新しい回路（＝新しい出口）を使う。
CIRCUITS_PER_DAY = 10
DAYS_PER_YEAR = 365


# ---------------------------------------------------------------------------
# 指標関数
# ---------------------------------------------------------------------------

def binom_pmf(n, k, p):
    return math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))


def binom_at_least(n, k_min, p):
    return sum(binom_pmf(n, k, p) for k in range(k_min, n + 1))


def guard_capture_prob_single_draw(f):
    """固定ガードを1本引くときに敵が当たる確率。"""
    return f


def guard_sample_capture_prob(f, sample_size=GUARD_SAMPLE_SIZE):
    """標本 sample_size 本のうち少なくとも1本が敵である確率
    (実際に使われるのは主に先頭1本だが、失敗時に標本内の次を使うため
    「標本のどれかが敵」は上限として意味がある)。
    """
    return 1 - (1 - f) ** sample_size


def guard_and_exit_both_adversarial(f):
    """1本の回路で、ガードと出口の両方を敵が握る確率 (独立選択と仮定)。
    タイミング相関によるデアノニマイズの必要条件。
    """
    return f * f


def cumulative_prob(p_per_trial, trials):
    return 1 - (1 - p_per_trial) ** trials


def k_holder_full_capture(f, k=K_REPLICAS):
    """Mailbox の K 保持者全員を敵が握る確率 (独立選択と仮定)。"""
    return f ** k


def reed_solomon_censorship_prob(f, k=K_REPLICAS, data=DATA_SHARDS, total=TOTAL_SHARDS):
    """検閲（配送阻止）が成立する確率（独立一様な敵配置を仮定）。

    シャード 1 個は K 台に複製されるので、そのシャードが取れなくなるのは
    K 台すべてが敵のとき（確率 q = f^K）。本体を復元できなくなるのは、
    total 個のうち total - data + 1 個以上のシャードが取れなくなったとき。
    """
    q = f ** k
    k_min = total - data + 1
    return binom_at_least(total, k_min, q)


def guard_periods(days, rotation_days=GUARD_ROTATION_SECS / 86400):
    """days 日のあいだに使うガードの本数（初回 + 入れ替え回数）。"""
    return 1 + int(days // rotation_days)


def guard_ever_adversarial(f, days):
    """days 日のあいだに、一度でも敵のガードを使う確率（入れ替えごとに独立に f）。"""
    return 1 - (1 - f) ** guard_periods(days)


def sender_exposure_over(f, days, circuits_per_day=CIRCUITS_PER_DAY):
    """days 日のあいだに「敵のガードの期間中に、敵の出口を 1 回以上引く」確率。

    送信者の IP（ガード）と内容（出口）が同じ攻撃者に揃う＝送信の特定。
    ガードの各期間について独立とみなす。
    """
    rotation_days = GUARD_ROTATION_SECS / 86400
    periods = guard_periods(days)
    p_not = 1.0
    remaining = days
    for _ in range(periods):
        d = min(rotation_days, remaining)
        remaining -= d
        p_exit_hit = cumulative_prob(f, int(round(d * circuits_per_day)))
        p_not *= 1 - f * p_exit_hit
    return 1 - p_not


def cover_overlap_probability(window_secs=FETCH_JITTER_MAX_SECS, mean_secs=COVER_FETCH_MEAN_SECS):
    """受信者でないノードでも、長さ window_secs の窓にダミー取得が 1 回以上入る確率。

    ダミーは平均 mean_secs のポアソン過程（指数分布の間隔）。
    """
    return 1 - math.exp(-window_secs / mean_secs)


def confirmation_messages_needed(prior_suspects, confidence=0.99,
                                 window_secs=FETCH_JITTER_MAX_SECS,
                                 mean_secs=COVER_FETCH_MEAN_SECS):
    """送信者（＝攻撃者）が、容疑者 prior_suspects 人の中から受信者を特定するのに要る通数。

    攻撃者は Hint の放流時刻 t0 を知っており、容疑者のガード側の通信（ISP 照会・
    敵ガード）から「t0 から window 以内に取得が出たか」を観測する。
    受信者なら必ず出る（確率 1）。受信者でなければダミーが入る確率 p0 でしか出ない。
    1 通ごとの尤度比は 1/p0。事前オッズ 1/(S-1) から事後確率 confidence に達する通数。
    """
    p0 = cover_overlap_probability(window_secs, mean_secs)
    lr = 1 / p0
    target_odds = confidence / (1 - confidence)
    prior_odds = 1 / max(prior_suspects - 1, 1e-9) if prior_suspects > 1 else float("inf")
    if prior_odds >= target_odds:
        return 0
    return math.ceil(math.log(target_odds / prior_odds) / math.log(lr))


def grinding_cost_fixed_seed(n_relays, k=K_REPLICAS, pow_secs=18.0):
    """位置が公開されている対象（公式板の索引・プレキー束）の K 保持者を全部取るコスト。

    ノードの位置は H(NodeId ‖ seed) で、PoW は位置に関与しない。攻撃者は鍵ペアを作って
    位置だけを安く計算し、狙いの位置に最も近い正直なノードより内側に着地したものだけ
    PoW を解けばよい。内側に着地する確率はおよそ 1/N（両側で平均幅 1/N）。
    返り値: (位置計算の回数, PoW を解く回数, PoW の CPU 秒)
    """
    hashes = k * n_relays
    return hashes, k, k * pow_secs


def normalized_entropy_uniform(anonymity_set_size):
    """一様分布を仮定した正規化エントロピー（Díaz ら 2002 の degree of anonymity）。"""
    if anonymity_set_size <= 1:
        return 0.0
    return 1.0


# ---------------------------------------------------------------------------
# 出力
# ---------------------------------------------------------------------------

def fmt(x):
    if x == 0:
        return "0"
    if x < 1e-6:
        return f"{x:.3e}"
    return f"{x:.6f}"


def main():
    print("=== 定数確認 ===")
    print(f"MAX_HOPS = {MAX_HOPS}")
    print(f"GUARD_SAMPLE_SIZE = {GUARD_SAMPLE_SIZE}, GUARD_ROTATION_SECS = {GUARD_ROTATION_SECS} ({GUARD_ROTATION_SECS/86400:.0f} 日)")
    print(f"DANDELION fluff_probability = {FLUFF_PROBABILITY}, 期待ステム長 = {EXPECTED_STEM_LENGTH:.1f} ホップ, epoch = {DANDELION_EPOCH_SECS}秒")
    print(f"Hint PoW difficulty = {HINT_POW_DIFFICULTY_BITS} bits (SHA-256)")
    print(f"NodeId/Directory PoW difficulty = {NODE_ID_POW_DIFFICULTY_BITS} bits (Argon2id)")
    print(f"K_REPLICAS = {K_REPLICAS}, DATA_SHARDS = {DATA_SHARDS}, PARITY_SHARDS = {PARITY_SHARDS}, TOTAL_SHARDS = {TOTAL_SHARDS}")
    print(f"FETCH_JITTER_MAX = {FETCH_JITTER_MAX_SECS}秒, COVER_FETCH_MEAN = {COVER_FETCH_MEAN_SECS}秒")
    print()

    print("=== 表1: 1 本の回路でガード・出口とも敵 (f^2) ===")
    for f in ADVERSARY_FRACTIONS:
        print(f"  f={f:>4}: {fmt(guard_and_exit_both_adversarial(f))}")
    print()

    print("=== 表2: 期間中に一度でも敵のガードを使う確率（60 日ごとに入れ替え）===")
    for f in ADVERSARY_FRACTIONS:
        row = "  ".join(f"{d}日={fmt(guard_ever_adversarial(f, d))}" for d in (30, 365, 3 * 365))
        print(f"  f={f:>4}: {row}")
    print()

    print("=== 表3: 期間中に送信が特定される確率（敵ガード期間中に敵出口を引く）===")
    print(f"  仮定: 1 日 {CIRCUITS_PER_DAY} 回路")
    for f in ADVERSARY_FRACTIONS:
        row = "  ".join(f"{d}日={fmt(sender_exposure_over(f, d))}" for d in (30, 365, 3 * 365))
        print(f"  f={f:>4}: {row}")
    print()

    print("=== 表4: 保持者の占有（独立一様な配置。私信の本体に当てはまる）===")
    for f in ADVERSARY_FRACTIONS:
        print(f"  f={f:>4}: シャード 1 個の K={K_REPLICAS} 台全部={fmt(k_holder_full_capture(f))}"
              f"  検閲成立(3/5 シャード以上)={fmt(reed_solomon_censorship_prob(f))}")
    print()

    print("=== 表5: 位置が公開されている対象（公式板の索引・プレキー束）の狙い撃ち ===")
    print("  シード固定（現在の既定）では 1 回で済む。日次シードでも、新規ノードが即座に")
    print("  保持者になれるなら毎日この費用を払うだけで再現できる。")
    for n in NETWORK_SIZES:
        h, pows, secs = grinding_cost_fixed_seed(n)
        print(f"  N={n:>7}: 位置計算 {h:,} 回 + PoW {pows} 回（CPU 約 {secs:.0f} 秒）")
    print()

    p0 = cover_overlap_probability()
    print("=== 表6: 受信者の確認攻撃（送信者＝攻撃者、容疑者の通信タイミングを観測）===")
    print(f"  受信者でない人の窓内にダミーが入る確率 p0 = 1 - exp(-60/90) = {p0:.4f}")
    print(f"  1 通あたりの尤度比 1/p0 = {1/p0:.3f}（約 {math.log2(1/p0):.2f} ビット）")
    for s_ in (2, 10, 1_000, 10_000):
        print(f"  容疑者 {s_:>6} 人 → 99% で特定するのに要る通数: {confirmation_messages_needed(s_)}")
    print("  一定間隔の取得枠（本物がダミーの枠を置き換える）にすれば尤度比は 1 になり、何通送っても絞れない")
    print()

    print("=== 表7: 受信者の匿名集合（Hint を受け取るリレー全体）の正規化エントロピー（理想値）===")
    for n in NETWORK_SIZES:
        print(f"  N={n}: log2(N) = {math.log2(n):.2f} bits, 正規化エントロピー = {normalized_entropy_uniform(n):.1f}")
    print()


if __name__ == "__main__":
    main()
