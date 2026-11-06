# Diagnostik perangkat — 6 November 2026

Sumber: `sm8750-device-info.txt` yang dikirim pengguna setelah menjalankan
collector v1. SHA-256 sumber:
`cf596e316652ed92c96fbe3c8526d2f1d00f422e161be74e43024b76edb1ae3d`.
Ringkasan terpilih tersimpan di
`evidence/device_2026_11_06/summary.json`; berkas mentah tetap menjadi input
pengguna di luar Git.

## Hasil yang sekarang diketahui

| Item | Hasil laporan |
|---|---|
| Device | `annibale` |
| Board/platform | `sun` |
| Android | `16` |
| Build incremental | `OS3.0.307.0.WPKCNXM` |
| Slot aktif yang dilaporkan | `_a` |
| `ro.boot.verifiedbootstate` | `green` |
| `ro.boot.flash.locked` | `1` |
| `ro.boot.vbmeta.device_state` | `locked` |
| Nama `efisp` / `efisp_a` / `efisp_b` | Tidak muncul di daftar by-name |
| `/sys/firmware/efi` | Tidak tersedia pada laporan ini |

Identitas build cocok dengan metadata ROM CN dalam masukan awal. Itu belum
membuktikan ABL, UEFI, dan XBL config yang terpasang identik byte demi byte.
Hash komponen boot belum dikumpulkan oleh collector v1.

Nilai `locked`/`green` di atas berasal dari properti Android. Laporan ini tidak
memuat pemeriksaan independen status lock, UID collector, atau log autentikasi
boot. Karena itu hasilnya belum membuktikan fake lock berhasil, bootloader
benar-benar terkunci, atau payload lama pernah dijalankan.

## Pemetaan partisi yang berguna

| Nama | Target block device |
|---|---|
| `abl_a` | `/dev/block/sde10` |
| `abl_b` | `/dev/block/sde45` |
| `uefi_a` | `/dev/block/sde1` |
| `uefi_b` | `/dev/block/sde36` |
| `xbl_config_a` | `/dev/block/sdb2` |
| `xbl_config_b` | `/dev/block/sdc2` |
| `uefivarstore` | `/dev/block/sde73` |
| `toolsfv` | `/dev/block/sde70` |
| `logfs` | `/dev/block/sda14` |
| `persist` | `/dev/block/sdf7` |
| `blackbox` | `/dev/block/sda23` |
| `xbl_sc_logs` | `/dev/block/sde80` |

Terdapat 141 tautan by-name dalam laporan, termasuk enam tautan disk utuh.
Daftar ini belum memberikan GPT type GUID, LBA, ukuran, atau validitas CRC.
Tidak adanya nama `efisp` tidak membuktikan tidak ada partisi bertipe ESP
dengan nama lain. `uefivarstore` juga bukan pengganti otomatis loader GBL.

## Hubungan dengan firmware yang telah ditelusuri

PE `VariableDxe` pada UEFI CN memiliki SHA-256
`c56fb5b2a5c3359b1be699229bc17be5b16e0fd87980fe1ef011fa3aa35ea0ee`.
Penanda relevan di dalam PE itu:

| Offset file PE | Penanda |
|---|---|
| `0xA384` | `Varstore partition %g` dalam pesan diagnostik |
| `0xA45C` | `unsupported varstore` |
| `0xA47B` | `invalid varstore partition configuration` |
| `0xA4AD` | `VarStoreQseeStorId` |
| `0xB98D` | Pesan kegagalan pencarian QseeCom protocol |
| `0xB9DD` | Path build menuju `VariablesHelperLib/LA/DefaultVarStore.c` |

Penanda itu mendukung perlunya menelusuri provider variable storage dan
konfigurasinya. Ia belum membuktikan format `uefivarstore` di HP, kemampuan
menulis variabel dari Android, ataupun keterjangkauan BootNext sebelum
LinuxLoader. Urutan dispatch QcomBds yang sebelumnya dipetakan tetap berlaku
untuk hash firmware acuan.

## Pemeriksaan berikutnya: metadata saja

`tools/collect_boot_metadata.sh` mencakup:

1. UID collector dan properti build yang sama.
2. Header dan SHA-256 prefix ABL/UEFI/XBL config pada kedua slot, menggunakan
   panjang persis berkas ROM acuan. Ini dapat membedakan basis CN, engineering,
   PE mentah, atau komponen lain tanpa mengunggah seluruh firmware.
3. Ukuran partisi terpilih.
4. Nama, GPT type GUID, LBA dan ukuran entry GPT. Disk GUID dan unique
   partition GUID tidak dicetak. CRC GPT belum diverifikasi oleh collector.
5. Opsi EFI kernel bila `/proc/config.gz` dapat dibaca.

Collector membaca block device dan menggunakan file sementara berukuran
terbatas di `/data/local/tmp`, lalu menghapus file sementaranya. Ia tidak
menulis ke block device. Fitur GPT membutuhkan awk; script mencoba awk di PATH
atau instalasi Termux dan melaporkan `awk_unavailable` bila tidak tersedia.

Simpan script di `/sdcard/Download/`, kemudian jalankan:

```sh
su -c 'sh /sdcard/Download/collect_boot_metadata.sh' > /sdcard/Download/sm8750-boot-metadata.txt
```

Hasil berikutnya yang diperlukan adalah `sm8750-boot-metadata.txt`. Belum ada
image baru untuk uji flash. Keberadaan partisi varstore atau filesystem yang
cocok tetap belum menyelesaikan entry EFI dan autentikasi image.
