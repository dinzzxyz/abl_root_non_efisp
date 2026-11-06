#!/system/bin/sh
# SM8750 phase 2. Reads block devices; writes only temporary/output files.
# No flashing, reboot, mounts, lock changes, or variable writes.
# No GPT unique partition GUIDs, disk GUIDs, serials, or variable contents.

printf '%s\n' 'SM8750 boot metadata diagnostics v2'
printf 'uid='
id -u
if [ "$(id -u)" != 0 ]; then
  printf '%s\n' 'ERROR: run this script through su so firmware can be read'
  exit 1
fi

for prop in ro.product.device ro.board.platform ro.build.version.incremental \
  ro.build.version.release ro.boot.slot_suffix ro.boot.verifiedbootstate \
  ro.boot.flash.locked ro.boot.vbmeta.device_state; do
  printf '%s=' "$prop"
  getprop "$prop"
done

for tool in head sha256sum dd od tr wc cut mktemp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'ERROR: required command unavailable: %s\n' "$tool"
    exit 1
  fi
done
SM8750_META_DIR=$(mktemp -d /data/local/tmp/sm8750-meta.XXXXXX) || exit 1
sm8750_cleanup() {
  rm -f "$SM8750_META_DIR/header.bin" "$SM8750_META_DIR/entries.bin" "$SM8750_META_DIR/prefix.bin"
  rmdir "$SM8750_META_DIR" 2>/dev/null
}
trap sm8750_cleanup 0
trap 'exit 1' 1 2 15

printf '\n%s\n' 'Firmware fingerprints: exact prefix lengths of supplied ROM files'
while read -r part length; do
  path="/dev/block/by-name/$part"
  if [ ! -b "$path" ]; then
    printf 'FIRMWARE name=%s status=unavailable\n' "$part"
    continue
  fi
  if ! head -c "$length" "$path" > "$SM8750_META_DIR/prefix.bin" 2>/dev/null; then
    printf 'FIRMWARE name=%s status=read_error\n' "$part"
    continue
  fi
  actual=$(wc -c < "$SM8750_META_DIR/prefix.bin" | tr -d ' \n')
  digest=$(sha256sum "$SM8750_META_DIR/prefix.bin")
  digest=$(printf '%s\n' "$digest" | cut -d ' ' -f 1)
  magic=$(od -An -v -tx1 -N 16 "$SM8750_META_DIR/prefix.bin" | tr -d ' \n')
  status=ok
  [ "$actual" = "$length" ] || status=truncated
  printf 'FIRMWARE name=%s prefix_bytes=%s bytes_read=%s sha256=%s magic16=%s status=%s\n' \
    "$part" "$length" "$actual" "$digest" "$magic" "$status"
done <<'SM8750_FIRMWARE_LENGTHS'
abl_a 335672
abl_b 335672
uefi_a 2839004
uefi_b 2839004
xbl_config_a 345376
xbl_config_b 345376
SM8750_FIRMWARE_LENGTHS

printf '\n%s\n' 'Selected partition sizes'
for part in abl_a abl_b uefi_a uefi_b xbl_config_a xbl_config_b \
  uefivarstore toolsfv logfs persist blackbox xbl_sc_logs; do
  path="/dev/block/by-name/$part"
  [ -b "$path" ] || continue
  bytes=unknown
  if command -v blockdev >/dev/null 2>&1; then
    bytes=$(blockdev --getsize64 "$path" 2>/dev/null) || bytes=unknown
  fi
  printf 'PARTITION name=%s size_bytes=%s\n' "$part" "$bytes"
done

SM8750_META_AWK=
if command -v awk >/dev/null 2>&1; then
  SM8750_META_AWK=$(command -v awk)
elif [ -x /data/data/com.termux/files/usr/bin/awk ]; then
  SM8750_META_AWK=/data/data/com.termux/files/usr/bin/awk
elif [ -x /data/data/com.termux/files/usr/bin/gawk ]; then
  SM8750_META_AWK=/data/data/com.termux/files/usr/bin/gawk
fi

printf '\n%s\n' 'GPT type GUIDs (unique GUID fields intentionally omitted)'
printf '%s\n' 'GPT_CRC_CHECK=not_performed'
for disk in sda sdb sdc sdd sde sdf; do
  device="/dev/block/$disk"
  [ -b "$device" ] || continue
  if [ -z "$SM8750_META_AWK" ]; then
    printf 'GPT_SKIP disk=%s reason=awk_unavailable\n' "$disk"
    continue
  fi
  sector=$(cat "/sys/class/block/$disk/queue/logical_block_size" 2>/dev/null)
  case "$sector" in 512|1024|2048|4096) ;; *)
    printf 'GPT_SKIP disk=%s reason=sector_size_unavailable\n' "$disk"
    continue ;;
  esac
  if ! dd if="$device" of="$SM8750_META_DIR/header.bin" bs="$sector" skip=1 count=1 2>/dev/null; then
    printf 'GPT_SKIP disk=%s reason=header_read_error\n' "$disk"
    continue
  fi
  signature=$(od -An -v -tx1 -N 8 "$SM8750_META_DIR/header.bin" | tr -d ' \n')
  if [ "$signature" != 4546492050415254 ]; then
    printf 'GPT_SKIP disk=%s reason=no_primary_gpt_signature\n' "$disk"
    continue
  fi
  entries_lba=$(od -An -tu8 -j 72 -N 8 "$SM8750_META_DIR/header.bin" | tr -d ' \n')
  entries=$(od -An -tu4 -j 80 -N 4 "$SM8750_META_DIR/header.bin" | tr -d ' \n')
  entry_size=$(od -An -tu4 -j 84 -N 4 "$SM8750_META_DIR/header.bin" | tr -d ' \n')
  invalid=0
  for value in "$entries_lba" "$entries" "$entry_size"; do
    case "$value" in ''|*[!0-9]*) invalid=1 ;; esac
  done
  if [ "$invalid" -ne 0 ]; then
    printf 'GPT_SKIP disk=%s reason=invalid_header_fields\n' "$disk"
    continue
  fi
  if [ "$entries" -lt 1 ] || [ "$entries" -gt 1024 ] || \
     [ "$entry_size" -lt 128 ] || [ "$entry_size" -gt 4096 ] || \
     [ $((entry_size % 8)) -ne 0 ] || [ "$entries_lba" -lt 2 ] || [ "$entries_lba" -gt 16777216 ]; then
    printf 'GPT_SKIP disk=%s reason=header_out_of_bounds\n' "$disk"
    continue
  fi
  total=$((entries * entry_size))
  blocks=$(((total + sector - 1) / sector))
  if ! dd if="$device" of="$SM8750_META_DIR/entries.bin" bs="$sector" \
      skip="$entries_lba" count="$blocks" 2>/dev/null; then
    printf 'GPT_SKIP disk=%s reason=entries_read_error\n' "$disk"
    continue
  fi
  actual=$(wc -c < "$SM8750_META_DIR/entries.bin" | tr -d ' \n')
  if [ "$actual" -lt "$total" ]; then
    printf 'GPT_SKIP disk=%s reason=truncated_entries\n' "$disk"
    continue
  fi
  printf 'GPT_TABLE disk=%s sector_bytes=%s entry_count=%s entry_size=%s\n' \
    "$disk" "$sector" "$entries" "$entry_size"
  od -An -v -tu1 "$SM8750_META_DIR/entries.bin" |
    "$SM8750_META_AWK" -v step="$entry_size" -v limit="$entries" -v disk="$disk" -v sector="$sector" '
# SM8750_GPT_AWK_BEGIN
function le(off, count, result, power, j) {
  result=0; power=1
  for(j=0;j<count;j++) { result+=b[off+j]*power; power*=256 }
  return result
}
function emit(used, j, guid, name, code, first, last, esp) {
  used=0
  for(j=0;j<16;j++) used+=b[j]
  if(!used) return
  guid=sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    b[3],b[2],b[1],b[0],b[5],b[4],b[7],b[6],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15])
  name=""
  for(j=56;j<128;j+=2) {
    code=b[j]+256*b[j+1]
    if(!code) break
    name=name ((code>=32 && code<127) ? sprintf("%c",code) : "?")
  }
  first=le(32,8); last=le(40,8)
  esp=(guid=="c12a7328-f81f-11d2-ba4b-00a0c93ec93b") ? 1 : 0
  printf "GPT_ENTRY\tdisk=%s\tindex=%d\tname=%s\ttype_guid=%s\tfirst_lba=%.0f\tlast_lba=%.0f\tsize_bytes=%.0f\tesp_type=%d\n",
    disk,record+1,name,guid,first,last,(last>=first ? (last-first+1)*sector : 0),esp
}
BEGIN { position=0; record=0 }
{
  for(i=1;i<=NF;i++) {
    b[position]=$i
    position++
    if(position==step) {
      emit()
      position=0
      record++
      if(record>=limit) exit
    }
  }
}
# SM8750_GPT_AWK_END
'
done

printf '\n%s\n' 'Kernel EFI options'
if [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
  zcat /proc/config.gz 2>/dev/null |
    grep -E '^(CONFIG_EFI=|CONFIG_EFI_STUB=|CONFIG_EFIVAR_FS=|CONFIG_EFI_RUNTIME_WRAPPERS=|# CONFIG_EFI is not set|# CONFIG_EFIVAR_FS is not set)'
else
  printf '%s\n' 'KERNEL_CONFIG=unavailable'
fi
printf '\n%s\n' 'UEFI runtime directory'
if [ -d /sys/firmware/efi ]; then
  ls /sys/firmware/efi
else
  printf '%s\n' 'EFI_RUNTIME_DIRECTORY=unavailable'
fi
