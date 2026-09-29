#!/usr/bin/env bash
# Verify that adding perf_event_open to security.syscalls.deny actually makes
# the syscall return EPERM (seccomp) inside an Incus container.
#
# Run this ON YOUR REAL INCUS HOST (not a nested sandbox). Needs the `incus`
# CLI with daemon access (add sudo if your user isn't in the incus-admin group).
set -euo pipefail

INCUS="${INCUS:-incus}"                 # set INCUS="sudo incus" if needed
# Default to Coi's local image (present on any Coi host, no network needed).
# Override with IMAGE=images:alpine/edge or IMAGE=ubuntu:24.04 if you prefer.
IMAGE="${IMAGE:-coi-default}"
C="coi-perf-verify-$$"

echo "== host kernel.perf_event_paranoid =="
paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "?")
echo "  perf_event_paranoid = $paranoid"
if [ "$paranoid" != "?" ] && [ "$paranoid" -ge 3 ] 2>/dev/null; then
  echo "  WARNING: paranoid >= 3 blocks perf_event_open at the KERNEL (EACCES) and"
  echo "           will MASK the seccomp signal. Result may be inconclusive (see below)."
fi

cleanup() { $INCUS delete -f "$C" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# This mirrors exactly what Coi writes: a \n-separated list, each entry with an
# explicit "errno 1" action. Both matter — a space-separated value is one
# malformed LXC rule (container won't start), and a bare syscall name inherits
# LXC's default action, which on current Incus is SIGSYS-KILL (init dies)
# instead of the intended EPERM. $'...' makes these real newlines.
DENY=$'io_uring_setup errno 1\nio_uring_enter errno 1\nio_uring_register errno 1\nbpf errno 1\nuserfaultfd errno 1\nkeyctl errno 1\nadd_key errno 1\nrequest_key errno 1\nperf_event_open errno 1'

echo "== launching $C from image '$IMAGE' with the strict deny list =="
if ! $INCUS launch "$IMAGE" "$C" -c security.syscalls.deny="$DENY" >/dev/null 2>launch.err; then
  echo "  launch FAILED:"; sed 's/^/    /' launch.err; rm -f launch.err
  echo "  --- instance start log (if any) ---"
  $INCUS info --show-log "$C" 2>/dev/null | sed 's/^/    /' | tail -25 || true
  echo
  echo "  Common causes:"
  echo "   * image not found  -> list local images:   $INCUS image list"
  echo "                         then re-run with IMAGE=<alias>"
  echo "   * remote unreachable (images:*) -> use a local image instead"
  exit 1
fi
rm -f launch.err
sleep 3

echo "== deny list actually set on the instance =="
$INCUS config get "$C" security.syscalls.deny

state=$($INCUS list "$C" -c s -f csv 2>/dev/null || echo "?")
echo "== instance state after launch: $state =="
if [ "$state" != "RUNNING" ]; then
  echo "  Instance is not running. Startup log:"
  $INCUS info --show-log "$C" 2>/dev/null | sed -n '/Log/,$p' | sed 's/^/    /' | head -30
  echo
  echo "  To tell WHY, compare against a no-deny launch of the same image:"
  echo "     $INCUS launch $IMAGE ${C}-nodeny; sleep 3; $INCUS list ${C}-nodeny; $INCUS delete -f ${C}-nodeny"
  echo "   * no-deny also stops -> image isn't launchable bare; set IMAGE=ubuntu:24.04 (or a stock image)"
  echo "   * no-deny stays up   -> a denied syscall is killing init (real compat finding)"
  exit 1
fi

echo "== building + running the perf_event_open probe inside the container =="
$INCUS exec "$C" -- sh -c '
  apk add --no-cache build-base linux-headers >/dev/null 2>&1 || {
    command -v apt-get >/dev/null && apt-get update -qq && apt-get install -y -qq gcc libc6-dev linux-libc-dev >/dev/null 2>&1;
  }
  cat > /tmp/probe.c <<"EOF"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
int main(void){
  struct perf_event_attr a; memset(&a,0,sizeof(a));
  a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a);
  a.config=PERF_COUNT_HW_CPU_CYCLES; a.disabled=1;
  a.exclude_kernel=1; a.exclude_hv=1;
  long fd = syscall(SYS_perf_event_open,&a,0,-1,-1,0);
  if(fd<0){ printf("perf_event_open -> errno %d (%s)\n", errno, strerror(errno)); return errno; }
  printf("perf_event_open -> SUCCESS fd=%ld (NOT denied)\n", fd); return 0;
}
EOF
  cc /tmp/probe.c -o /tmp/probe && /tmp/probe
'
rc=$?

echo
echo "== VERDICT =="
case "$rc" in
  1)  echo "  errno 1 (EPERM) -> seccomp is enforcing the deny. SHIP IT. ✅" ;;
  13) echo "  errno 13 (EACCES) -> the KERNEL (perf_event_paranoid) blocked it, so the" ;
      echo "     seccomp deny is UNCONFIRMED (masked). Re-run on a host with" ;
      echo "     perf_event_paranoid <= 2, or lower it temporarily:" ;
      echo "         sudo sysctl kernel.perf_event_paranoid=1" ;
      echo "     then re-run — expect EPERM (1). ⚠️" ;;
  0)  echo "  SUCCESS -> the deny is NOT taking effect at all. DO NOT SHIP; investigate. ❌" ;;
  *)  echo "  errno $rc -> unexpected; inspect manually." ;;
esac
