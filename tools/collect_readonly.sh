#!/system/bin/sh
# Prints diagnostics to stdout. Does not flash, mount, unlock, or reboot.
# Use: sh collect_readonly.sh > sm8750-device-info.txt
# Review the output before sharing it. No serial number or hardware ID is queried.

printf '%s\n' 'SM8750 read-only diagnostics v1'
for prop in ro.product.device ro.board.platform ro.build.version.incremental \
  ro.build.version.release ro.boot.slot_suffix ro.boot.verifiedbootstate \
  ro.boot.flash.locked ro.boot.vbmeta.device_state; do
  printf '%s=' "$prop"
  getprop "$prop"
done

printf '\n%s\n' 'Partition names and links:'
if [ -d /dev/block/by-name ]; then
  ls -l /dev/block/by-name
else
  printf '%s\n' '/dev/block/by-name unavailable in this context'
fi

printf '\n%s\n' 'UEFI runtime visibility:'
if [ -d /sys/firmware/efi ]; then
  ls /sys/firmware/efi
else
  printf '%s\n' '/sys/firmware/efi unavailable; this does not prove UEFI was absent during boot'
fi

for root in /sys/firmware/efi/efivars /sys/firmware/efi/vars; do
  [ -d "$root" ] || continue
  for var in "$root"/BootOrder-* "$root"/BootNext-* "$root"/AttemptUSBFirst-*; do
    [ -e "$var" ] || continue
    printf '\n%s\n' "$var"
    if [ -f "$var" ] && [ -r "$var" ]; then
      od -An -tx1 -N 128 "$var"
    else
      printf '%s\n' 'not a readable efivarfs file'
    fi
  done
done
