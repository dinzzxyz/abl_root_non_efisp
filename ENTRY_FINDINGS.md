# Ebl native sebagai kandidat entry tanpa efisp

Tanggal: 7 November 2026, Asia/Jakarta. **Hasil statis dan probe DT hanya baca;
belum ada aplikasi EFI kustom yang berjalan pada HP.**

Temuan baru memisahkan tiga persoalan: masuk ke lingkungan EFI sebelum
LinuxLoader, memuat aplikasi dari media yang bisa dibaca UEFI, lalu menyimpan
pilihan BDS. `efisp` bukan syarat yang terlihat pada jalur file/RAM milik Ebl
native. Namun entry awal dan penerimaan autentikasinya belum terbukti.

## 1. Basis dan ruang alamat

Semua alamat di bawah adalah **offset file PE sekaligus RVA pada PE yang
diidentifikasi ini**. Alamat tersebut bukan offset `uefi.elf`, bukan alamat
fisik RAM, dan bukan offset ABL. Analyzer tetap memakai konversi RVA/file;
pengujiannya sengaja memakai pemetaan yang berbeda.

| Komponen | SHA-256 seluruh PE |
|---|---|
| QcomBds, identik CN/engineering | `c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78` |
| Ebl dalam UEFI utama CN | `306bed8aaca6c2a31b6bee8360d1e9c727440ed50664bf3e107420ec103c5761` |
| Ebl dalam Tools FV live, **bukan basis alamat di sini** | `187dbb53b7b692c4965991cf97dfba006bd967ef4044f4dfe0396d953ede3c9b` |

Ebl utama adalah file FFS type 9, PE subsystem 10: aplikasi UEFI. Ia tidak
otomatis dijalankan sebagai driver DXE hanya karena ada di firmware volume.
Lihat [LIVE_BOOT_FINDINGS.md](LIVE_BOOT_FINDINGS.md) untuk asal FFS dan Tools FV.

## 2. Ada callback hotkey sebelum LinuxLoader, tetapi belum ada entry Ebl

Penelusuran indirect call memperjelas urutan yang sebelumnya hanya dipetakan
dari direct call. QcomBds sendiri memasang interface platform dengan GUID
`d874d61a-4b87-7608-a00f-58add7052530`. GUID berada pada `0x1D278`, tabel pada
`0x1D460`, revision `0x10003`. Installer menyiapkan GUID/interface pada
`0x2474`/`0x2478`, lalu memanggil Boot Services `+0x148` pada `0x2488`.

| Offset interface | Pointer dalam PE | Target setelah branch thunk |
|---|---|---|
| `+0x08` | `0x1628` | `0x62AC` |
| `+0x10` | `0x162C` | wrapper yang memanggil `0x65F0` pada `0x1634` |
| `+0x18` | `0x1644` | `0x69A8` |
| `+0x20` | `0x1648` | `0x6A38` |
| `+0x28` | `0x164C` | `0x59DC`, pemeriksaan perhatian/hotkey |
| `+0x30` | `0x1650` | `0x6BA4` |
| `+0x38` | `0x1654` | `0x69C8` |

| Urutan dalam init `0x1D44` | Instruksi atau target |
|---|---|
| Inisialisasi platform | `0x1D8C: BLR` interface `+0x08` |
| Penyiapan konsol | `0x1DAC: BLR` interface `+0x10` |
| Pemeriksaan hotkey | `0x1DC0: BLR` interface `+0x28` → `0x59DC` |
| Hook berikutnya | `0x1DCC: BL 0x6CDC` |
| Default apps | `0x1DEC: BL 0x4FF4` |
| LinuxLoader dalam default apps | `0x5254: BL 0x7D2C`, namespace ABL |
| Setup-app handler, bila alur kembali sejauh ini | `0x1E70: BL 0x56E4` |

Koreksi batas klaim: **pemeriksaan hotkey memang lebih awal**, sedangkan
handler yang meluncurkan `OEMSetupApp` tetap dipanggil sesudah default apps.
Keberadaan callback awal tidak membuktikan tombol tertentu dapat menahan
LinuxLoader atau membuka Ebl pada mode retail.

Dalam callback `0x59DC` ditemukan pembacaan EFI variable `BDSHotKeyState`,
input key melalui `0xA184`, dan pemeriksaan bit 0 `OsIndications` melalui
`0x4A50`. Beberapa cabang menambah counter di `0x1D880`. Pemanggilan pada
`0x5B14` menuju `0x6F38` adalah operasi **SerialPort Lib**, bukan launcher Ebl.
Pembacaan config `OEMSetupApp` pada `0x5B50` tidak diikuti launch dalam fungsi
ini; fungsi menetapkan state 3 lalu mengembalikan sukses. Hook `0x6CDC` juga
tidak menunjukkan launch Ebl pada kode yang diperiksa.

`OEMSetupApp` tidak ada pada konfigurasi FDT yang sudah diperiksa. Konfigurasi
`EnableShell=1` dan hadirnya nama Ebl tidak cukup untuk menggantikan bukti
caller. Source analyzer sekarang melacak ADRP yang diselingi instruksi lain;
pencarian pasangan ADRP/ADD yang harus bersebelahan dapat melewatkan referensi.
Pelacakan ini lokal dan konservatif, bukan pembuktian CFG seluruh firmware.

## 3. Ebl mempunyai jalur file/RAM yang nyata

Tabel registrasi menunjuk langsung ke handler, bukan sekadar string bantuan:

| Entry tabel PE | Nama | Handler |
|---|---|---|
| `0x14040` | `loadfv` | `0x3534` |
| `0x14060` | `start` | `0x3374` |
| `0x176D8` | `mountfv partitionlabel;` | `0xDC94` |

### loadfv: buffer RAM ke ProcessFirmwareVolume

Constructor `0x4118` memakai GUID DXE Services Table
`05ad34ba-6f02-4214-952e-4da0398e2bb9` pada `0x19028` dan menyimpan hasil
pencarian configuration table ke slot `0x1AE30`. Argumen itu disiapkan oleh
ADRP yang saling diselingi pada `0x4120`–`0x412C`, kemudian helper `0x86C0`
dipanggil pada `0x4130`. Helper memindai `EFI_SYSTEM_TABLE.ConfigurationTable`.
Constructor lain menyimpan tabel yang sama ke `0x1AE68` untuk Dispatch.

`loadfv` menerima buffer device langsung atau membaca file melalui helper
`0xD2C8` pada `0x35A4`. Kedua cabang memanggil slot **DXE Services `+0x98`**:

| Offset PE | Byte | Instruksi |
|---|---|---|
| `0x3584` | `081947f9` | `LDR X8, [X8, #0xE30]` |
| `0x3588` | `084d40f9` | `LDR X8, [X8, #0x98]` |
| `0x358C` | `00013fd6` | `BLR X8` |
| `0x35C8` | `081947f9` | `LDR X8, [X8, #0xE30]` |
| `0x35CC` | `084d40f9` | `LDR X8, [X8, #0x98]` |
| `0x35D0` | `00013fd6` | `BLR X8` |

Argumen mengikuti bentuk `(buffer, size, &handle)`. Layout DXE Services dari
source EDK2 yang dipin menempatkan Dispatch pada `+0x80` dan
ProcessFirmwareVolume pada `+0x98`: header 24 byte, lalu 13 pointer layanan GCD,
kemudian Dispatch/Schedule/Trust/ProcessFirmwareVolume.

[Spesifikasi PI](https://uefi.org/specs/PI/1.9/V2_Services_DXE_Services.html)
menjelaskan ProcessFirmwareVolume sebagai pemasangan FV dari memori. Ini
**bukan** bukti bahwa aplikasi di dalam FV otomatis berjalan atau diterima
autentikasinya.

### mountfv: label partisi, GUID, atau file FV bersarang

Bantuan native menyebut `MountFv toolsfv`, opsi `-g` untuk GUID, serta `-f`
untuk file. Handler memeriksa literal `-g` pada `0x16044` dan `-f` pada
`0x16047`. Bantuan path `-f` mengandung byte form-feed `0x0C` di tempat yang
tampaknya dimaksudkan sebagai `\f`; ini dicatat persis pada JSON, bukan
dijadikan bukti sintaks path yang telah diuji.

Cabang file: `0xDD74 → 0xD2C8` membaca file, `0xDD84 → 0x1305C` memproses
buffer. Helper `0xB830` menelusuri FV/file bersarang. Installer `0xB56C`
memasang FVB GUID `8f644fa9-e850-4db1-9ce2-0b44698e8da4` bersama Device Path
melalui Boot Services `+0x148`, tail-call pada `0xB80C`.

Ini jalur berbeda dari pemanggilan ProcessFirmwareVolume oleh `loadfv`.
Cabang label/GUID melewati `0x13124`, yang membaca volume lalu memakai helper
buffer yang sama. Tail `0xDE20 → 0x10E64` mencoba reconnect controller dan
DXE Dispatch (`+0x80`), tetap mengikuti status yang dikembalikan firmware.

### start: file EFI ke LoadImage dan StartImage

Handler `0x3374` membuka target. Bila device path tersedia, ia menggunakan
device path; jika tidak, ia membaca file ke buffer. Cabang buffer memanggil
Boot Services **LoadImage `+0xC8`** pada `0x3430`; cabang device path pada
`0x33F0`. Setelah status sukses, **StartImage `+0xD0`** dipanggil pada
`0x34EC`. Ini bukan lompat mentah ke entry address.

Karena itu, aplikasi EFI diagnostik kecil dapat menjadi kandidat uji awal yang
lebih sederhana daripada langsung memuat seluruh BDS. Tetap dibutuhkan entry
Ebl, filesystem yang terlihat dalam UEFI, kecocokan ABI dan penerimaan image.
Filesystem Android yang terpasang tidak otomatis terlihat dalam UEFI.

## 4. Jalur reboot khusus belum didukung bukti

Probe langsung pada HP membaca 5.615 direktori device tree, tanpa error,
pemotongan kedalaman atau batas jumlah. Lima node terkait reboot/restart
tercatat, tetapi tidak ada properti bernama `mode-*` pada tree yang dibaca.
Hasil ini tidak membuktikan tidak adanya command hardcoded dalam driver.

Source publik MiCode cabang `annibale-w-oss` dipin ke
`f66f8c8bcbe38044fab61d44ea7f7c224f82b3ea`. Dalam
`drivers/power/reset/qcom-reboot-reason.c`, tabel mengenali recovery,
bootloader, rtc, dua alasan dm-verity, keys clear dan panic. Tidak ada entry
`uefi`; command yang tidak cocok memakai fallback `0x20` pada source itu.
Kernel KSU yang sedang berjalan belum dicocokkan byte-for-byte dengan source
publik ini. Jadi **belum ada dasar untuk menyuruh mencoba reboot uefi**.
Tidak ada reboot atau penulisan reboot reason yang dilakukan.

Hash file, Git blob SHA, tautan source primer, layout DXE dan provenance
collector ada di `evidence/entry_2026_11_07/source_references.json`.
Source GPL pembanding tidak disalin ke repo ini.

## 5. Ide yang diteruskan dan urutan pembuktiannya

Hipotesis kerja: **entry native Ebl → file EFI diagnostik di RAM → baru BDS**.
Opsi FV tersedia bila port nanti memang memerlukan driver atau namespace FV
tersendiri. Jalur penyimpanan payload tidak perlu didesain sebagai partisi
`efisp` sebelum kemampuan file/RAM ini diuji.

1. Temukan caller Ebl yang benar-benar terjangkau pada PROD/Retail sebelum
   LinuxLoader. Periksa provider protokol yang dipanggil pada fase default,
   kebijakan setup/console, dan apakah ada jalur aplikasi native yang valid.
   Jangan menyamakan string Ebl atau flag EnableShell dengan caller.
2. Setelah entry tersedia, uji aplikasi diagnostik minimal yang mencetak marker,
   inventaris protokol yang dibutuhkan port, lalu kembali ke pemanggilnya.
   Catat status LoadImage/StartImage dan log, bukan hanya perubahan layar.
3. Buktikan sumber file/volume yang benar-benar terlihat dalam UEFI. Keberadaan
   FAT12 logfs tidak membuatnya ESP atau tempat payload yang bebas efek tulis.
4. Baru uji ABI/protokol BDS dan rancang pengganti SuperFbStore untuk menyimpan
   pilihan. Upstream masih memakai raw efisp/ESP untuk dua record 1 KiB;
   eksekusi dari RAM tidak otomatis menghilangkan dependensi penyimpanan itu.

Tahap pertama masih menjadi penghalang. Belum ada image flashable, resep
flashing, akses EFI variable dari Android, atau hasil eksekusi kustom yang
diverifikasi. Modul spoofing tidak perlu dicopot untuk analisis ini.

## 6. Reproduksi dari workspace kosong

Pulihkan repo, dependensi dan `gpt.zip` sesuai [RECOVERY.md](RECOVERY.md), lalu:

```bash
.venv/bin/python src/trace_ebl_entry.py /path/to/gpt.zip --out generated/entry
.venv/bin/python -m unittest discover -s tests -v
```

Analyzer menolak hash berbeda dan hanya menulis JSON serta disassembly
terpilih. `src/verify_research.py` juga menjalankan analisis ini. Bukti tersimpan
di `evidence/entry_2026_11_07`; seluruh byte instruksi dan call edges yang
dipakai tersedia pada dua file disassembly, tanpa mengekspor firmware PE.
