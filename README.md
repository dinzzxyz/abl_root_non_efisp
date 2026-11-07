# Penelusuran SuperFastboot SM8750 / annibale

Updated: 7 November 2026. Status: **analisis statis, rekonstruksi patch dan log stock**.
Paket ini berisi source alat analisis, bukti, dan catatan pengembangan.
Belum merupakan port SuperFastboot yang dapat di-flash.

Repo: https://github.com/dinzzxyz/abl_root_non_efisp

Untuk memulai dari workspace kosong, baca [RECOVERY.md](RECOVERY.md).
Untuk melanjutkan penelitian, mulai dari [HANDOFF.md](HANDOFF.md) dan
[RESEARCH_CONTINUED.md](RESEARCH_CONTINUED.md). Riwayat temuan ada di
[HISTORY.md](HISTORY.md), sedangkan riwayat perubahan lengkap tersedia di Git.
Hasil diagnostik HP dan pemeriksaan berikutnya ada di
[DEVICE_FINDINGS.md](DEVICE_FINDINGS.md).
Analisis hash firmware/GPT dari collector fase 2 ada di
[BOOT_METADATA_FINDINGS.md](BOOT_METADATA_FINDINGS.md).
Pemetaan kandidat Boot State CN dan handler diagnostik OEM ada di
[BOOTSTATE_FINDINGS.md](BOOTSTATE_FINDINGS.md).
Log UEFI yang diambil langsung serta isi Tools FV/FAT12 ada di
[LIVE_BOOT_FINDINGS.md](LIVE_BOOT_FINDINGS.md).
Peta callback awal QcomBds dan jalur file/RAM Ebl native ada di
[ENTRY_FINDINGS.md](ENTRY_FINDINGS.md).

## Hasil utama

1. `result/boot.efi` dapat direproduksi **identik byte demi byte** dari
   `eng rom/abl.elf`: 9 byte berubah pada 4 rentang instruksi.
2. Hasil itu adalah aplikasi ARM64 PE/EFI, bukan image partisi ABL berformat
   ELF/FV seperti file ABL asli. Pemakaian langsung sebagai image `abl_ab`
   tidak mengikuti format yang digunakan jalur PIL ABL pada firmware ini.
3. Pada dua LinuxLoader SM8750 yang diberikan, pencarian penanda tidak
   menemukan loader GBL/`efisp` milik referensi. Penanda itu ditemukan pada
   ABL `myron`, `myron_global`, dan `nezha_global` dari modul pembanding.
4. Jalur boot yang teridentifikasi berada pada **QcomBds** di `uefi.elf` dan
   konfigurasi DT `/sw/uefi/str_param/DefaultBDSBootApp` di `xbl_config.elf`.
   Nilainya `LinuxLoader` pada kedua ROM.
5. `BootNext`, `BootOrder`, dan fallback `\EFI\BOOT\BOOTAA64.EFI` memang ada
   dalam QcomBds. Namun pemanggilan aplikasi bawaan terjadi lebih dulu.
   Kode itu tidak membuktikan ada jalur boot alternatif yang sudah bisa dipakai.
6. Pemindaian bentuk instruksi menemukan satu blok Boot State pada setiap ABL
   meski mask patcher upstream menghasilkan nol hit. Metode itu merekonstruksi
   seluruh byte hasil engineering lama dan menghasilkan resep kandidat CN:
   10 byte / empat rentang, belum diuji runtime dan tidak diekspor sebagai image.
7. Pembacaan perangkat menemukan lima log UEFI pada volume FAT12 di `logfs`,
   19 aplikasi native pada `toolsfv` termasuk Shell/Ebl/Menu, dan rekaman
   boot stock yang menunjukkan NV volatile. Entry kustom belum teruji.
8. Ebl utama mempunyai `start` (LoadImage/StartImage), `loadfv`
   (ProcessFirmwareVolume dari buffer) dan `mountfv` (FV bersarang).
   Callback hotkey QcomBds memang berjalan sebelum default apps, tetapi
   entry Ebl sebelum LinuxLoader dan penerimaan image kustom belum terbukti.

Baca [LAPORAN.md](LAPORAN.md) untuk offset, call graph, batas bukti,
dan tahap pengembangan berikutnya.

## Isi source

| Berkas | Fungsi |
|---|---|
| `src/fwlib.py` | Ekstraksi PE dari LZMA, pembacaan FDT dan nama FFS |
| `src/analyze.py` | Mengulang penelusuran secara offline dari `gpt.zip` |
| `src/recover_patch.py` | Rekonstruksi persis hasil patch lama dengan validasi hash |
| `src/trace_paths.py` | Namespace ABL FV, digest ELF, dan inventaris protokol |
| `src/verify_research.py` | Pemeriksaan regresi offline yang dapat dijalankan ulang |
| `src/analyze_boot_metadata.py` | Perbandingan laporan prefix hash, ukuran dan GPT |
| `src/map_bootstate.py` | Anchor struktural CN/engineering, byte kandidat dan kalibrasi |
| `src/trace_diagnostics.py` | Tabel OEM CN dan cabang argumen handler log |
| `src/analyze_live_boot.py` | FAT12 bounded, cuplikan log terpilih dan inventaris Tools FV |
| `src/trace_ebl_entry.py` | Callback protokol QcomBds dan jalur file/RAM Ebl native |
| `tools/collect_reboot_dt.js` | Inventaris DT reboot/mode terbatas, hanya membaca |
| `tools/collect_live_boot.js` | Probe root dan capture block terbatas, hanya membaca |
| `tools/collect_readonly.sh` | Informasi build, partisi, dan visibilitas EFI di Android |
| `tools/collect_boot_metadata.sh` | Hash firmware terpasang, ukuran dan GPT type GUID |
| `evidence/` | Hasil analisis, hash, konfigurasi terpilih, dan disassembly |
| `VALIDATION.txt` | Hasil verifikasi terhadap berkas masukan yang diberikan |
| `UPSTREAM.json` | Repo dan commit acuan yang diperiksa |
| `INPUTS.json` | Hash ZIP masukan dan setiap anggotanya |
| `context/` | Prompt dan laporan uji asli dari pengguna |

Tidak ada skrip dari ZIP masukan yang dieksekusi. Alat analisis tidak
menjalankan `fastboot`, `adb`, `su`, atau membuka perangkat blok.

## Menjalankan ulang

Gunakan Python 3.10+ pada komputer Linux. Tempatkan ZIP masukan asli di luar
repo ini; firmware dan loader OEM tidak disertakan dalam source yang dibagikan.
Git dan ripgrep juga diperlukan untuk analisis lanjutan. Semua contoh
restorasi dan checkout source acuan ada di RECOVERY.md.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python src/analyze.py /path/to/gpt.zip --out generated
.venv/bin/python src/recover_patch.py /path/to/gpt.zip
```

Perintah terakhir memeriksa rekonstruksi tanpa menghasilkan file EFI.
Untuk menyimpan salinan payload yang identik dengan hasil lama:

```bash
.venv/bin/python src/recover_patch.py /path/to/gpt.zip --output generated/recovered_payload.efi
```

Salinan itu tetap **payload PE/EFI**, bukan image ABL yang sudah dikemas dan
diautentikasi. Alat menolak firmware dengan hash berbeda.

Setelah source acuan dipulihkan sesuai RECOVERY.md, jalankan seluruh pemeriksaan:

```bash
.venv/bin/python src/verify_research.py /path/to/gpt.zip --upstream ../gbl_root_canoe --log generated/verification.txt
```

## Catatan untuk pengembangan lintas perangkat

Pisahkan empat lapis: format image OEM, titik masuk EFI yang benar-benar
terjangkau, media penyimpanan payload, lalu kompatibilitas protokol BDS.
Folder `persist/efisp` dan partisi raw `efisp` merupakan dua hal berbeda.
Menyediakan lokasi penyimpanan tidak otomatis menyediakan pemanggilnya.

Offset dalam laporan khusus untuk hash yang tercatat. Untuk perangkat/ROM
lain, ulangi ekstraksi dan penelusuran; jangan menyalin offset langsung.

## Backup dan GitHub

Paket source ini dapat dimasukkan ke repo GitHub. Repo publik sebaiknya berisi
source, hash, dan hasil penelitian, tanpa firmware OEM, loader EDL, kredensial,
atau data identitas perangkat. ZIP masukan asli diperlukan untuk reproduksi.

Snapshot awal sudah dipush sebagai commit
`fffb031ef92a1c1549aefec5337aa1a959a5a062`. Kelanjutan penelitian dicatat dalam
commit berikutnya. Aset rilis memuat ZIP source dan bundle riwayat Git untuk
pemulihan. Untuk memulihkan bundle ke folder baru:

```bash
git clone SM8750-research-history-2026-11-07.bundle recovered-research
```

Keberhasilan push ini menggunakan login GitHub CLI yang diselesaikan pengguna;
koneksi plugin semula dapat membaca tetapi menolak write dengan HTTP 403.

## Sumber dan lisensi

Source Python baru dalam `src/` menggunakan lisensi MIT, lihat `LICENSE`.
Proyek acuan memiliki lisensi GPL-3.0; source upstream dan firmware OEM
tidak direlisensi oleh paket ini. Catatan analisis merujuk hasil pemeriksaan
terhadap berkas yang diberikan pengguna dan repo upstream.
