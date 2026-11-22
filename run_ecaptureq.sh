#!/usr/bin/env bash
# run_ecaptureq.sh — stream on-device HTTPS plaintext (eCapture) to eCaptureQ client on this host.
# Usage: ./run_ecaptureq.sh [iface]     (iface optional, autodetected on the phone)
set -u

HARSHARE=/home/kali/Desktop/ecap-har
DEV_EC=/data/local/tmp/ec2
DEV_LIB_SRC=${LIB_PATCH:-/data/local/tmp/l6.so}
HOST_LIB_SRC=${LIB_PATCH_HOST:-/tmp/lhe_p6.so}
APEX_LIB=/apex/com.android.tethering/lib64/libhttpengine.so
PKG=sa.gov.nic.twkhayat
ACT=$PKG/com.tawakkalna.twkapp.ui.MainActivity
WS_PORT=28257
CLIENT=$HARSHARE/examples/ecaptureq_client/ecaptureq_client

need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
need adb
[ "$(adb get-state 2>/dev/null)" = device ] || { echo "no adb device"; exit 1; }
adb shell 'su 0 true' 2>/dev/null || { echo "no root via su"; exit 1; }

# --- host client build -------------------------------------------------------
if [ ! -x "$CLIENT" ]; then
  echo "[*] building eCaptureQ client (first run)"
  ( cd "$HARSHARE/examples/ecaptureq_client" && go build -o ecaptureq_client . ) || exit 1
fi

# --- device prerequisites ----------------------------------------------------
adb push "$HARSHARE/bin/ecapture" "$DEV_EC" >/dev/null || exit 1
adb shell "su 0 chmod 755 $DEV_EC"
if [ -f "$HOST_LIB_SRC" ]; then
  adb push "$HOST_LIB_SRC" "$DEV_LIB_SRC" >/dev/null || exit 1
fi
adb shell "su 0 chmod 644 $DEV_LIB_SRC; su 0 chcon u:object_r:system_lib_file:s0 $DEV_LIB_SRC"
adb shell "su 0 sh -c 'umount $APEX_LIB 2>/dev/null; mount --bind $DEV_LIB_SRC $APEX_LIB'" || { echo "bind mount failed"; exit 1; }

# --- interface autodetect ----------------------------------------------------
IFACE=${1:-}
if [ -z "$IFACE" ]; then
  IFACE=$(adb shell 'for i in $(ip -o link show up | awk -F": " "{print \$2}" | cut -d@ -f1); do [ -f /sys/class/net/$i/statistics/tx_bytes ] && echo "$(cat /sys/class/net/$i/statistics/tx_bytes) $i"; done' 2>/dev/null \
          | awk '$2 ~ /^(rmnet|wlan|eth)/' | sort -rn | awk 'NR==1{print $2}')
fi
echo "[*] capture interface: ${IFACE:-<none>}"
[ -n "$IFACE" ] || { echo "no up rmnet/wlan interface"; exit 1; }

# --- app + tunnel ------------------------------------------------------------
adb shell "su 0 am force-stop $PKG"
adb shell 'input keyevent 224' >/dev/null 2>&1
adb reverse --remove-all >/dev/null 2>&1
adb shell "am start -n $ACT" >/dev/null 2>&1
for _ in $(seq 1 25); do sleep 0.4; PID=$(adb shell pidof -s "$PKG" | tr -d '\r'); [ -n "$PID" ] && break; done
[ -n "${PID:-}" ] || { echo "app did not start"; exit 1; }
echo "[*] target pid $PID"

adb forward tcp:$WS_PORT tcp:$WS_PORT >/dev/null

cleanup() {
  echo; echo "[*] cleanup"
  adb shell 'su 0 pkill -f "/data/local/tmp/ec2"' >/dev/null 2>&1
  adb forward --remove tcp:$WS_PORT >/dev/null 2>&1
  adb shell "su 0 umount $APEX_LIB" >/dev/null 2>&1
  exit 0
}
trap cleanup INT TERM

# --- device-side capture server ---------------------------------------------
echo "[*] starting ecapture on device (WS :$WS_PORT)"
adb shell "su 0 sh -c 'cd /data/local/tmp && exec $DEV_EC tls -m text --libssl=$APEX_LIB ${IFACE:+-i $IFACE} --pid $PID --ecaptureq ws://0.0.0.0:$WS_PORT --harfile /data/local/tmp/live.har --xmlfile /data/local/tmp/live.xml'" &
CAP_PID=$!
sleep 2

# --- host-side viewer ---------------------------------------------------------
echo "[*] waiting for device WS :$WS_PORT"
for _ in $(seq 1 30); do adb shell "ss -tln 2>/dev/null | grep -q :$WS_PORT" && break; sleep 0.5; done
echo "[*] connecting client to ws://127.0.0.1:$WS_PORT/  (Ctrl-C to stop)"
while :; do
  "$CLIENT" -server "ws://127.0.0.1:$WS_PORT/" -verbose && break
  sleep 1
done
