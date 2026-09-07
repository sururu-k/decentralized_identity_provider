#!/usr/bin/env bash
#
# デモの並列表示 (docs/container-split.md 第 12 節)。
#
# node1 / node2 / node3 / gateway / rp の 5 列を tmux のペインに並べ、6 つ目の
# ペインに「ブラウザ役」CLI スタンドインの実行例を **入力済み・未実行** で置く。
# 各列が第 10 節の圧縮形式 (1〜2 行、英語、← / →) で出すので、横に並べると
# 「ブラウザ以外は id_token を組み立てる材料を揃えられない」ことが見える。
#
#   scripts/demo-tmux.sh          # スタックが起動済みであることを前提にする
#   scripts/demo-tmux.sh --up     # 起動していなければ docker compose up -d --build --wait
#   TAIL=0 scripts/demo-tmux.sh   # 過去ログを出さず、これから起きることだけを見る
#
# 既定の TAIL=5 は、各サービスの `● up` イベント (holds: / never: の 1 行) が
# 画面に残るようにするため。まっさらな画面から始めたいときは TAIL=0。
#
# 終了: 各ペインで Ctrl-C → exit、またはセッションごと `tmux kill-session -t pasta-demo`。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SESSION="pasta-demo"
WINDOW="demo"
SERVICES="node1 node2 node3 gateway rp"
EXPECTED_COUNT=5
TAIL="${TAIL:-5}"

# 6 つ目のペインに入れておく実行例 (Enter は送らない)。
CLI_EXAMPLE='cd projects/demo && npm run -s sign-on -- --gateway http://localhost:3000 --user alice --password password123 --client-id demo_client --nonce demo-1'

AUTO_UP=0
for arg in "$@"; do
  case "$arg" in
    --up) AUTO_UP=1 ;;
    -h|--help)
      sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "不明な引数: $arg (使えるのは --up と --help)" >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# 1. tmux
if ! command -v tmux >/dev/null 2>&1; then
  cat >&2 <<'EOF'
tmux が見つかりません。5 列を並べて表示するのに必要です。

  macOS:         brew install tmux
  Debian/Ubuntu: sudo apt install tmux

tmux を入れずに 1 列ずつ見る場合は、ターミナルを 5 枚開いて次を実行してください。

  docker compose logs -f --no-log-prefix node1
  docker compose logs -f --no-log-prefix node2
  docker compose logs -f --no-log-prefix node3
  docker compose logs -f --no-log-prefix gateway
  docker compose logs -f --no-log-prefix rp
EOF
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. compose スタック
running_count() {
  docker compose ps --status running --services 2>/dev/null | grep -c . || true
}

RUNNING="$(running_count)"
if [ "$RUNNING" -lt "$EXPECTED_COUNT" ]; then
  if [ "$AUTO_UP" -eq 1 ]; then
    echo "起動しているサービスが ${RUNNING}/${EXPECTED_COUNT} なので docker compose up します…"
    mkdir -p secrets
    docker compose up -d --build --wait
    RUNNING="$(running_count)"
  else
    cat >&2 <<EOF
起動しているサービスが ${RUNNING}/${EXPECTED_COUNT} しかありません。先にスタックを起動してください。

  mkdir -p secrets
  docker compose up -d --build --wait

このスクリプトに起動まで任せる場合は --up を付けてください。

  scripts/demo-tmux.sh --up
EOF
    exit 1
  fi
fi

if [ "$RUNNING" -lt "$EXPECTED_COUNT" ]; then
  echo "起動後もサービスが ${RUNNING}/${EXPECTED_COUNT} です。docker compose ps を確認してください。" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. tmux セッション
attach() {
  if [ -n "${TMUX:-}" ]; then
    tmux switch-client -t "$SESSION"
  else
    tmux attach-session -t "$SESSION"
  fi
}

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "セッション '$SESSION' は既にあります。attach します (作り直すなら tmux kill-session -t $SESSION)。"
  attach
  exit 0
fi

logs_cmd() {
  echo "docker compose logs -f --no-log-prefix --tail=$TAIL $1"
}

set -- $SERVICES
first="$1"
shift

tmux new-session -d -s "$SESSION" -n "$WINDOW" -c "$ROOT" "$(logs_cmd "$first")"
tmux select-pane -t "$SESSION:$WINDOW.0" -T "$first"

for svc in "$@"; do
  tmux split-window -t "$SESSION:$WINDOW" -c "$ROOT" "$(logs_cmd "$svc")"
  tmux select-pane -t "$SESSION:$WINDOW" -T "$svc"
  tmux select-layout -t "$SESSION:$WINDOW" tiled
done

# 6 つ目: ブラウザ役の shell。実行例を入力しておくが Enter は送らない。
tmux split-window -t "$SESSION:$WINDOW" -c "$ROOT"
tmux select-pane -t "$SESSION:$WINDOW" -T "browser (ブラウザ役 CLI — Enter で実行)"
tmux select-layout -t "$SESSION:$WINDOW" tiled
tmux send-keys -t "$SESSION:$WINDOW" -l "$CLI_EXAMPLE"

# ペイン境界にサービス名を出す (pane-border-status はウィンドウオプション)。
tmux set-option -w -t "$SESSION:$WINDOW" pane-border-status top
tmux set-option -w -t "$SESSION:$WINDOW" pane-border-format ' #{pane_title} '

# ブラウザ役のペインを選択した状態で開く。
tmux select-pane -t "$SESSION:$WINDOW.5"

attach
