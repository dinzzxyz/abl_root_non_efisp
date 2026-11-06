# Hasil metadata boot dari perangkat — 6 November 2026

Sumber: `sm8750-boot-metadata.txt` dari collector v2, SHA-256:
`71a2df187f1ccc689f4ea318cfd5a793814059c690022ba05bf4d57f186861ed`.
Analisis terstruktur ada di
`evidence/device_2026_11_06/boot-metadata-analysis.json`.

## 1. Klarifikasi properti boot

Pengguna mengonfirmasi bahwa modul spoofing memodifikasi properti status boot.
Karena itu `locked`/`green` dalam laporan tidak dipakai sebagai bukti status
lock fisik, hasil fake lock pada ABL, atau keberhasilan eksekusi payload.
Modul tidak perlu dicopot untuk tahap pembacaan metadata ini.

Collector v2 melaporkan `uid=0`. Metadata tetap merupakan hasil pembacaan
dari Android; bukan hasil attestation hardware atau log autentikasi firmware.

## 2. Enam prefix image cocok dengan ROM CN acuan

| Komponen | Byte yang dibaca per slot | Ukuran partisi per slot | Hasil slot A dan B |
|---|---:|---:|---|
| ABL | 335.672 | 8 MiB | SHA-256 sama dengan `cn/abl.elf` |
| UEFI | 2.839.004 | 5 MiB | SHA-256 sama dengan `cn/uefi.elf` |
| XBL config | 345.376 | 512 KiB | SHA-256 sama dengan `cn/xbl_config.elf` |

Prefix mencakup seluruh panjang file image OEM yang diberikan pada ZIP awal.
Byte sisa setiap partisi belum di-hash. Pada bagian image yang dibandingkan,
kedua slot cocok dengan CN dan tidak cocok dengan engineering.

Implikasinya:

- Peta QcomBds pada hash UEFI CN sekarang cocok dengan image prefix yang
  dibaca dari perangkat, bukan hanya label build Android.
- Awal ABL yang dibaca adalah ELF CN, bukan file PE mentah `result/boot.efi`.
- Resep patch lama pada basis engineering tetap berguna untuk reproduksi
  hasil lama, tetapi offsetnya tidak otomatis berlaku untuk ABL CN saat ini.
- Hash yang cocok tidak membuktikan image yang dimodifikasi kelak akan
  diterima autentikasi boot.

## 3. GPT: tidak ditemukan efisp atau ESP standar dalam data internal ini

Collector melaporkan enam tabel GPT dengan sektor logis 4.096 byte dan 135
entry berisi partisi: sda 34, sdb 5, sdc 5, sdd 3, sde 81, sdf 7.

Tidak ditemukan nama `efisp` maupun GPT type GUID ESP standar
`c12a7328-f81f-11d2-ba4b-00a0c93ec93b` pada entry tersebut. Parser menghitung
kembali ukuran dari LBA, membandingkan ukuran partisi terpilih, dan memeriksa
entry tidak bertumpang tindih pada disk yang sama. CRC GPT belum diverifikasi
oleh collector; hal itu tidak boleh diubah menjadi klaim validasi CRC.

| Partisi | Ukuran | GPT type GUID |
|---|---:|---|
| `uefivarstore` | 512 KiB | `165bd6bc-9250-4ac8-95a7-a93f4a440066` |
| `toolsfv` | 1 MiB | `97745aba-135a-44c3-9adc-05616173c24c` |
| `logfs` | 8 MiB | `bc0330eb-3410-4951-a617-03898dbe3372` |
| `persist` | 32 MiB | `6c95e238-e343-4ba8-b489-8681ed22ad0b` |
| `blackbox` | 154 MiB | `048e9437-3c11-4ed5-a9c1-2c3f42e1383a` |
| `xbl_sc_logs` | 128 KiB | `f7eecb66-781a-439a-8955-70e12ed4a7a0` |

Dalam data keenam LUN internal itu, tidak ada kandidat yang memenuhi pemilihan
ESP upstream berdasarkan nama `efisp` atau type GUID ESP. Ini memperjelas
masalah backend default-menu BDS yang sebelumnya dicatat. Media eksternal atau
volume virtual yang mungkin ditambahkan BDS tidak termasuk data GPT ini.

Partisi yang ada mempunyai fungsi masing-masing. Keberadaan `toolsfv` atau
`uefivarstore` tidak otomatis menyediakan entry GBL; kapasitas partisi juga
tidak membuktikan ruangnya aman dipakai untuk payload atau record baru.

## 4. Hubungan uefivarstore dengan VariableDxe makin konkret

Byte little-endian GPT type GUID `165bd6bc-9250-4ac8-95a7-a93f4a440066`
ditemukan pada PE VariableDxe CN di offset `0xD088`, `0xD098`, `0xD0A8`, dan
`0xD0C8`. Image VariableDxe ini berada di UEFI CN yang hash prefix-nya cocok
dengan laporan perangkat.

Di modul yang sama, referensi konfigurasi `VarStoreQseeStorId` berada pada
RVA `0x2518–0x2528`; diagnostik konfigurasi varstore berada pada
`0x21E8–0x2208` dan `0x24E8–0x2504`. Byte dan disassembly terpilih disimpan
di `evidence/device_2026_11_06/variabledxe_variables_trace.txt`.

Ini menghubungkan identitas tipe partisi dengan driver yang perlu ditelusuri.
Format storage sebenarnya, kebijakan autentikasi variabel, dan akses menulis
variabel dari Android masih belum dibuktikan. Mengedit raw varstore bukan
langkah yang disiapkan atau diuji dalam penelitian ini.

## 5. Interface variabel EFI tidak tersedia melalui efivarfs pada kernel ini

Laporan konfigurasi:

```text
CONFIG_EFI_STUB=y
CONFIG_EFI=y
CONFIG_EFI_RUNTIME_WRAPPERS=y
# CONFIG_EFIVAR_FS is not set
```

Direktori `/sys/firmware/efi` juga tidak tersedia pada laporan. Dukungan EFI
yang dikompilasi tidak membuktikan kernel menerima konteks boot/runtime EFI.
Pada Linux upstream, pembuatan direktori EFI dalam `efisubsys_init` bergantung
pada flag `EFI_BOOT`. Source upstream itu merupakan rujukan perilaku umum,
bukan bukti bahwa seluruh source kernel Android pengguna identik.

Menyalakan EFIVAR_FS saja belum terbukti cukup untuk menyediakan akses runtime
pada alur boot perangkat ini. Tidak ada langkah mount atau perubahan kernel
yang diperlukan untuk melanjutkan analisis metadata yang sudah ada.

Rujukan primer:

- [Linux efivarfs](https://docs.kernel.org/filesystems/efivarfs.html).
- [Linux EFI boot stub](https://docs.kernel.org/admin-guide/efi-stub.html).
- [Linux EFI core](https://github.com/torvalds/linux/blob/master/drivers/firmware/efi/efi.c),
  blob yang diperiksa: `9bc22de0d67ee0bc8482cd673f48ffe00843d2dc`.

## 6. Uji patcher upstream pada basis yang tepat

Patcher C dari commit upstream
`4ef438cfde42943694fde5753bbf5d8c0b4ec02e` dikompilasi untuk host Linux dengan
GCC `-O2 -Iinclude`, lalu dijalankan offline terhadap PE hasil ekstraksi CN dan
engineering. Input asli tetap utuh. Kedua percobaan berhenti dengan exit 1:

```text
Warning: Failed to patch ABL GBL
Error: Failed to find/patch ABL Boot State
Patching failed
```

Patcher menemukan satu pasangan string-state pada masing-masing basis:

| Basis PE | Offset ADRP/ADD | Target sebelum | Target yang dicoba |
|---|---|---|---|
| CN | `0x45674` | `unlocked` di `0xA28EC` | `locked` di `0x91E49` |
| Engineering | `0x46BE8` | `unlocked` di `0xA3AA3` | `locked` di `0x93386` |

Perubahan ini hanya sempat diterapkan pada buffer proses sebelum tahap boot
state gagal. Program tidak menyimpan output karena gagal. Itu bukan patch
lengkap yang dapat digunakan, dan bukan bukti fake lock bekerja. Log dan
provenance percobaan ada di folder evidence yang sama.

Kesimpulan praktis: selain entry BDS dan autentikasi, pola patch boot-state
SM8750 perlu dipetakan secara struktural. Patcher upstream saat ini tidak
dapat langsung dipakai untuk dua basis yang diberikan.

## 7. Langkah lanjut tanpa tes tambahan sekarang

Data fase 2 sudah cukup untuk melanjutkan analisis offline pada basis CN.
Prioritas selanjutnya adalah jalur entry sebelum LinuxLoader, provider
variabel/boot options, dan pola boot-state CN. Bukti runtime dan log PIL/UEFI
tetap diperlukan sebelum sebuah image eksperimental dinyatakan layak diuji.

Pengguna tidak perlu mencopot modul spoofing untuk tahap ini. Remote yang
tersedia pada sesi berikutnya dapat dipakai untuk pembacaan log terarah;
tidak ada jadwal, reboot, perubahan GPT, atau uji flash yang dibuat otomatis.

## Mengulang analisis laporan

```bash
python3 src/analyze_boot_metadata.py /path/to/sm8750-boot-metadata.txt --boot-properties-spoofed --output generated/boot-metadata-analysis.json
python3 -m unittest discover -s tests -v
```

Parser menerima pemisah tab maupun teks literal `\t` pada laporan Android.
