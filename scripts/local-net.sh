#!/bin/sh
# 手元で試すためのテスト網を立てる（127.0.0.1 に到達可能なリレーを N 台）
#
#   scripts/local-net.sh [台数=5] [先頭ポート=19001]
#
# 種ノードは 127.0.0.1:<先頭ポート>。GUI / CLI の「種ノード」にこれを入れる。
# PoW は本番と同じ難易度 16（リリースビルドで 1 台十数秒〜）。Ctrl+C で全部止まる。
set -eu

N=${1:-5}
BASE=${2:-19001}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DATA=${AETHER_LOCALNET_DIR:-"$ROOT/target/local-net"}
BIN="$ROOT/target/release/aether-cli"

cargo build --release -p aether-cli --manifest-path "$ROOT/Cargo.toml"
mkdir -p "$DATA"

PIDS=""
trap 'kill $PIDS 2>/dev/null; exit 0' INT TERM

i=0
while [ "$i" -lt "$N" ]; do
  port=$((BASE + i))
  dir="$DATA/relay$i"
  [ -f "$dir/identity.key" ] || "$BIN" --data-dir "$dir" init >/dev/null 2>&1
  if [ "$i" -eq 0 ]; then
    "$BIN" --data-dir "$dir" start --port "$port" --advertise "127.0.0.1:$port" >"$dir.log" 2>&1 &
  else
    "$BIN" --data-dir "$dir" start --port "$port" --advertise "127.0.0.1:$port" \
      --connect "127.0.0.1:$BASE" >"$dir.log" 2>&1 &
  fi
  PIDS="$PIDS $!"
  # 種が待ち受けを始めてから他を参加させる（先に要求すると取りこぼす）
  if [ "$i" -eq 0 ]; then
    until grep -q "待ち受け開始" "$dir.log" 2>/dev/null; do sleep 1; done
  fi
  i=$((i + 1))
done

echo "リレー $N 台を起動中（PoW 計算に少しかかります）。ログ: $DATA/relay*.log"
echo "種ノード: 127.0.0.1:$BASE"
wait
