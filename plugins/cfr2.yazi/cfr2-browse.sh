#!/usr/bin/env bash
# cfr2-browse : fzf picker over an R2 bucket, started by the cfr2 yazi plugin.
#   cfr2-browse.sh BUCKET DEST_DIR
# Keys (shown in the header):
#   enter   pull + decrypt into DEST_DIR      ctrl-s  share link (copied, 1 h)
#   ctrl-e  edit (decrypt into RAM)           ctrl-d  restore drill
#   ctrl-v  verify checksum                   ctrl-x  move to trash
#   ctrl-b  other bucket                      esc     back to yazi
set -uo pipefail
bucket=${1:-}
dest=${2:-.}
CFR2=${CFR2_BIN:-cfr2}

copy() {
	if command -v pbcopy >/dev/null; then pbcopy
	elif [ -n "${WAYLAND_DISPLAY:-}" ] && command -v wl-copy >/dev/null; then wl-copy
	elif command -v xclip >/dev/null; then xclip -selection clipboard
	else cat >/dev/null; return 1; fi
}

pause() { printf '\n[press enter]'; read -r _; }

"$CFR2" agent start >/dev/null 2>&1 || true
echo "cfr2: touch the Token2 if it blinks (once per bucket, then the agent remembers)" >&2

while :; do
	[ -n "$bucket" ] || bucket=$("$CFR2" bucket list 2>/dev/null | awk '{print $1}' | fzf --prompt='bucket> ' --height=40% --reverse) || exit 0
	list=$("$CFR2" ls -r "$bucket:" 2>&1) || { echo "$list"; pause; exit 1; }
	if [ -z "$list" ]; then echo "$bucket is empty (nothing to pull)"; pause; bucket=""; continue; fi
	out=$(printf '%s\n' "$list" | fzf --prompt="$bucket> " --reverse --no-sort \
		--header=$'enter pull | ^S share | ^E edit | ^D drill | ^V verify | ^X trash | ^B bucket | esc quit' \
		--expect=enter,ctrl-s,ctrl-e,ctrl-d,ctrl-v,ctrl-x,ctrl-b \
		--nth=4..) || exit 0
	key=$(printf '%s\n' "$out" | sed -n 1p)
	line=$(printf '%s\n' "$out" | sed -n 2p)
	obj=$(printf '%s' "$line" | awk '{ $1=$2=$3=""; sub(/^ +/, ""); print }')
	[ -n "$obj" ] || continue
	case "$key" in
		enter) "$CFR2" pull "$bucket:$obj" "$dest"; pause; exit 0 ;;
		ctrl-s)
			url=$("$CFR2" share --ttl 1h "$bucket:$obj") && { printf '%s' "$url" | copy && echo "link copied (valid 1 h)" || echo "$url"; }
			pause ;;
		ctrl-e) "$CFR2" edit "$bucket:$obj"; pause ;;
		ctrl-d) "$CFR2" drill "$bucket:$obj"; pause ;;
		ctrl-v) "$CFR2" verify "$bucket:$obj"; pause ;;
		ctrl-x) read -r -p "move $obj to trash? [y/N] " a; [ "$a" = y ] && "$CFR2" rm "$bucket:$obj"; pause ;;
		ctrl-b) bucket="" ;;
	esac
done
