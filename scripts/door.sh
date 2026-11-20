#!/usr/bin/env bash
# A Compute Substrate door in one command, on a Debian or Ubuntu server (x86-64 or ARM):
#
#   curl -fsSL https://github.com/compute-substrate/compute-substrate/releases/download/<tag>/door.sh | sudo bash
#
# (docs/public-node.md links the current one)
#
# A door is a node anyone's browser can reach, which also keeps the sites .csd names point to, so
# they stay up with no one's own server. This installs:
#   - the node (csd), syncing the network and checking every block itself;
#   - the site store (csd-sites), keeping the sites names point to;
#   - Caddy, serving both over HTTPS: on your domain, or with none, on <your-ip>.sslip.io;
#   - an announcement: a record on the network saying "a door, at this address", so the Compute
#     Substrate Node app finds it. It's written once this door's key holds 0.26 CSD.
#
# Options (after `bash -s --` when piped):
#   --domain example.org   a domain of yours, already pointing to this server (default: <ip>.sslip.io)
#   --invite <link>        an invite link, to pay for the announcement
#   --node URL             use a node already running here, at this RPC address, not a new one
#   --announce-only        only announce a door already set up by hand (with --domain, its domain)
#
# Running it again updates the programs and keeps everything else. Nothing here is consensus.
set -euo pipefail

TAG="__TAG__"   # filled in when a release is made
REPO="compute-substrate/compute-substrate"
DOMAIN="" INVITE="" NODE="" ONLY="" OWN_NODE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --invite) INVITE="$2"; shift 2 ;;
    --node) NODE="$2"; shift 2 ;;
    --announce-only) ONLY=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "Run it as root (sudo bash)." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "This needs systemd (Debian or Ubuntu)." >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "Only x86-64 and ARM servers are supported (this is $(uname -m))." >&2; exit 1 ;;
esac
case "$TAG" in __*) echo "This copy of door.sh has no release tag; use the one attached to a release." >&2; exit 1 ;; esac

say "Installing what it needs"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates gnupg python3 >/dev/null
if ! command -v caddy >/dev/null; then
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy >/dev/null
fi

say "Getting the programs ($TAG, $ARCH), checked"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/$REPO/releases/download/$TAG"
curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS-linux.txt"
for p in csd csd-sites; do
  curl -fsSL -o "$TMP/$p-linux-$ARCH" "$BASE/$p-linux-$ARCH"
  (cd "$TMP" && grep " $p-linux-$ARCH\$" SHA256SUMS | sha256sum -c - >/dev/null) || { echo "$p didn't match its checksum; stopping." >&2; exit 1; }
  install -m 755 "$TMP/$p-linux-$ARCH" "/usr/local/bin/$p"
done

if [ -n "$ONLY" ]; then
  [ -n "$DOMAIN" ] || { echo "--announce-only needs --domain, the door's domain." >&2; exit 1; }
  NODE="$(systemctl show csd-sites -p ExecStart --value 2>/dev/null | grep -o -- '--node [^ ]*' | cut -d' ' -f2 || true)"
  [ -n "$NODE" ] || { echo "No site store (csd-sites service) here to announce." >&2; exit 1; }
fi

id csd >/dev/null 2>&1 || useradd --system --home /var/lib/csd --create-home --shell /usr/sbin/nologin csd
install -d -o csd -g csd /var/lib/csd /var/lib/csd/sites
install -d /etc/csd
[ -f /etc/csd/deny.txt ] || printf '# Sites this door won'"'"'t keep or serve: CIDs and .csd names, one per line.\n' > /etc/csd/deny.txt

if [ -z "$NODE" ] && [ -z "$ONLY" ]; then
  say "The node"
  OWN_NODE=1
  NODE="http://127.0.0.1:8789"
  [ -f /var/lib/csd/genesis.bin ] || sudo -u csd /usr/local/bin/csd genesis --out /var/lib/csd/genesis.bin >/dev/null
  BOOT=$(curl -fsSL "https://raw.githubusercontent.com/$REPO/main/app/bootnodes.txt" | grep -v '^\s*#' | grep '/p2p/' | paste -sd, -)
  cat > /etc/systemd/system/csd.service <<EOF
[Unit]
Description=Compute Substrate node
After=network-online.target
Wants=network-online.target
[Service]
User=csd
ExecStart=/usr/local/bin/csd node --datadir /var/lib/csd/db --rpc 127.0.0.1:8789 --genesis /var/lib/csd/genesis.bin --p2p-listen /ip4/0.0.0.0/tcp/17999 --bootnodes $BOOT
Restart=always
RestartSec=5
TimeoutStopSec=600
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
fi

if [ -z "$DOMAIN" ]; then
  IP=$(curl -fsS -4 https://api.ipify.org)
  DOMAIN="${IP//./-}.sslip.io"
fi
URL="https://$DOMAIN"
NODE_HOSTPORT="${NODE#http://}"

if [ -z "$ONLY" ]; then
say "The site store"
cat > /etc/systemd/system/csd-sites.service <<EOF
[Unit]
Description=Compute Substrate site store
After=network-online.target csd.service
[Service]
User=csd
ExecStart=/usr/local/bin/csd-sites --node $NODE --dir /var/lib/csd/sites --listen 127.0.0.1:8795 --deny /etc/csd/deny.txt --url $URL
Restart=always
[Install]
WantedBy=multi-user.target
EOF

say "HTTPS, at $URL"
cat > /etc/caddy/csd-door.caddy <<EOF
# A Compute Substrate door (scripts/door.sh). Pages on any site may read the node and its sites:
# everything here is public, and a transaction is only accepted if its owner signed it.
$DOMAIN {
	header {
		Access-Control-Allow-Origin "*"
		Access-Control-Allow-Methods "GET, POST, OPTIONS"
		Access-Control-Allow-Headers "content-type"
		Access-Control-Max-Age "600"
	}
	@preflight method OPTIONS
	handle @preflight {
		respond 204
	}
	handle /sites* {
		request_body {
			max_size 70MB
		}
		reverse_proxy 127.0.0.1:8795
	}
	@read {
		method GET
		path /health /tip /domains /oracle /headers/* /proof/tx/* /tx/* /block/* /utxos/* /address/* /recent/* /proposals/* /proposal/* /attestations/* /window/* /top/* /topk/* /events/*
		not path /tx/template/*
	}
	handle @read {
		reverse_proxy $NODE_HOSTPORT
	}
	@submit {
		method POST
		path /tx/submit
	}
	handle @submit {
		request_body {
			max_size 1MB
		}
		reverse_proxy $NODE_HOSTPORT
	}
	handle {
		respond 404
	}
}
EOF
# a fresh Caddy's sample page goes; an existing Caddyfile keeps everything and imports this
if grep -q '/usr/share/caddy' /etc/caddy/Caddyfile 2>/dev/null || [ ! -s /etc/caddy/Caddyfile ]; then
  echo "import /etc/caddy/csd-door.caddy" > /etc/caddy/Caddyfile
elif ! grep -q 'csd-door.caddy' /etc/caddy/Caddyfile; then
  printf '\nimport /etc/caddy/csd-door.caddy\n' >> /etc/caddy/Caddyfile
fi
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null

if command -v ufw >/dev/null && ufw status | grep -q active; then
  ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw allow 17999/tcp >/dev/null
fi
fi # not --announce-only

say "The announcement"
KEY=/var/lib/csd/door.key
if [ -n "$INVITE" ]; then
  # an invite link carries a private key (base64url): the announcement is paid from it
  CODE="${INVITE##*/invite/}"; CODE="${CODE%/}"
  python3 -c 'import base64,sys; c=sys.argv[1]; b=base64.urlsafe_b64decode(c+"="*(-len(c)%4)); assert len(b)==32; print(b.hex())' "$CODE" > "$KEY" \
    || { echo "That isn't an invite link." >&2; exit 1; }
elif [ ! -f "$KEY" ]; then
  /usr/local/bin/csd wallet new | awk '/^privkey:/ {print $2}' | sed 's/^0x//' > "$KEY"
fi
chown csd: "$KEY"; chmod 600 "$KEY"
echo "$URL" > /etc/csd/door-url

cat > /usr/local/bin/csd-door-announce <<'EOF'
#!/usr/bin/env bash
# Writes this door's announcement (a record under csd.doors, its text the door's address) once, as
# soon as the node answers and the door's key holds enough CSD. Run every 10 minutes until then.
set -euo pipefail
NODE="$(systemctl show csd-sites -p ExecStart --value | grep -o -- '--node [^ ]*' | cut -d' ' -f2)"
URL="$(cat /etc/csd/door-url)"; KEY="$(cat /var/lib/csd/door.key)"
FEE=25000000
J="$(curl -fsS "$NODE/proposals/csd.doors/500" 2>/dev/null)" || { echo "The node isn't answering yet."; exit 0; }
if printf '%s' "$J" | python3 -c 'import json,sys; u=sys.argv[1]; sys.exit(0 if any(p.get("uri","").rstrip("/")==u for p in json.load(sys.stdin).get("proposals",[])) else 1)' "$URL"; then
  echo "Announced already: $URL"; exit 0
fi
ADDR="$(/usr/local/bin/csd wallet recover --privkey "$KEY" | awk '/^addr20:/ {print $2}')"
IN="$(curl -fsS "$NODE/utxos/${ADDR#0x}?available=true" | python3 -c 'import json,sys; f=int(sys.argv[1]); u=[x for x in json.load(sys.stdin).get("utxos",[]) if int(x["value"])>=f+1000000]; u.sort(key=lambda x:-int(x["value"])); print("%s:%s:%s" % (u[0]["txid"], u[0]["vout"], u[0]["value"]) if u else "")' "$FEE")"
if [ -z "$IN" ]; then
  echo "Waiting for CSD: send 0.3 CSD to $ADDR, and the door announces itself within 10 minutes."; exit 0
fi
TIP="$(curl -fsS "$NODE/tip" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')"
HASH="$(printf %s "$URL" | sha256sum | cut -d' ' -f1)"
/usr/local/bin/csd wallet propose --privkey "$KEY" --input "$IN" --fee "$FEE" --domain csd.doors \
  --payload-hash "$HASH" --uri "$URL" --expires-epoch $(( TIP / 30 + 10000000 )) --rpc-url "$NODE" > /var/lib/csd/door-announce.json
echo "Announced $URL. The Node app finds it once the record is in a block."
EOF
chmod 755 /usr/local/bin/csd-door-announce
cat > /etc/systemd/system/csd-door-announce.service <<'EOF'
[Unit]
Description=Announce this Compute Substrate door on the network
After=csd.service csd-sites.service
[Service]
Type=oneshot
User=csd
ExecStart=/usr/local/bin/csd-door-announce
EOF
cat > /etc/systemd/system/csd-door-announce.timer <<'EOF'
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
[Install]
WantedBy=timers.target
EOF
chown csd: /etc/csd/door-url

systemctl daemon-reload
if [ -z "$ONLY" ]; then
  # only a node this script set up; one given with --node is left running as it is
  if [ -n "$OWN_NODE" ]; then systemctl enable csd >/dev/null 2>&1; systemctl restart csd; fi
  systemctl enable --now csd-sites >/dev/null 2>&1 && systemctl restart csd-sites
  systemctl reload caddy 2>/dev/null || systemctl restart caddy
else
  systemctl restart csd-sites 2>/dev/null || true
fi
systemctl enable --now csd-door-announce.timer >/dev/null 2>&1
systemctl start csd-door-announce.service >/dev/null 2>&1 || true

ADDR="$(/usr/local/bin/csd wallet recover --privkey "$(cat "$KEY")" | awk '/^addr20:/ {print $2}')"
say "Done. This door is $URL"
cat <<EOF
- The node is syncing. Check it with:   curl -s $URL/tip
- Its sites:                             curl -s $URL/sites
$(if [ -f /var/lib/csd/door-announce.json ]; then echo "- It has announced itself on the network."; else printf '%s\n' "- It announces itself once its key holds 0.3 CSD: send it to $ADDR" "  (or run this again with --invite <link>). See how it's going with:" "  journalctl -u csd-door-announce -n 5"; fi)
- Sites you won't keep or serve go in /etc/csd/deny.txt (CIDs or .csd names, one per line). A door
  is a host: what it serves is yours to answer for.
- Open TCP ports 80, 443 and 17999 in your provider's firewall too, if it has one.
EOF
