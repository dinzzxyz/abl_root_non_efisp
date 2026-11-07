# Memulihkan dan melanjutkan penelitian

## 1. Ambil repo beserta riwayat

Pada komputer Linux dengan Git, Python 3.10+, dan ripgrep:

```bash
git clone https://github.com/dinzzxyz/abl_root_non_efisp.git
cd abl_root_non_efisp
git log --oneline --decorate --all
```

Jika GitHub tidak dapat dijangkau, ekstrak ZIP backup yang diunduh. Untuk
memulihkan riwayat dari bundle pada aset rilis:

```bash
git clone SM8750-research-history-2026-11-07.bundle recovered-research
cd recovered-research
git remote set-url origin https://github.com/dinzzxyz/abl_root_non_efisp.git
```

Bundle merupakan snapshot saat dibuat. Commit setelah snapshot tetap harus
diambil dari remote atau bundle yang lebih baru.

## 2. Ambil masukan asli

Gunakan `gpt.zip` asli dari berkas percakapan/backup pribadi. Periksa SHA-256
terhadap `INPUTS.json`. Jangan menganggap file dengan nama sama pasti identik.
Atas permintaan pengguna, hanya CN ABL default dan hasil repack yang dipin
disertakan dalam annibale; firmware komponen lain dan loader EDL tidak disalin.

```bash
sha256sum /path/to/gpt.zip
```

Jika ZIP asli hilang, manifest tetap menyimpan hash tiap anggota. Untuk
reproduksi penuh tetap dibutuhkan byte firmware yang sama; hasil analisis saja
tidak dapat menggantikan masukan asli.

## 3. Siapkan dependensi dan source acuan

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
git clone https://github.com/SuperTurtleDev/gbl_root_canoe.git ../gbl_root_canoe
git -C ../gbl_root_canoe checkout 4ef438cfde42943694fde5753bbf5d8c0b4ec02e
```

Source upstream cukup di-checkout pada commit yang dipin untuk mengulang
analisis. Tidak perlu membangun atau menjalankan firmware untuk langkah ini.

## 4. Ulangi hasil dan verifikasi

```bash
.venv/bin/python src/analyze.py /path/to/gpt.zip --out generated
.venv/bin/python src/trace_paths.py /path/to/gpt.zip --upstream ../gbl_root_canoe --out generated/continued
.venv/bin/python src/recover_patch.py /path/to/gpt.zip
.venv/bin/python src/map_bootstate.py /path/to/gpt.zip --out generated/bootstate
.venv/bin/python src/trace_diagnostics.py /path/to/gpt.zip --out generated/bootstate
.venv/bin/python src/trace_ebl_entry.py /path/to/gpt.zip --out generated/entry
.venv/bin/python src/verify_research.py /path/to/gpt.zip --upstream ../gbl_root_canoe --log generated/verification.txt
```

Verifikasi membandingkan seluruh byte hasil patch, menolak basis salah,
memeriksa GUID volume, digest SHA-384, call edges, dan deklarasi protokol.
Semua berlangsung offline terhadap berkas. Lulus verifikasi bukan hasil uji HP.
BOOTSTATE_FINDINGS.md menjelaskan hasil pemetaan struktural dan batasnya.
ENTRY_FINDINGS.md menjelaskan callback indirect QcomBds dan jalur file/RAM Ebl.
Analyzer entry memakai CN UEFI dari ZIP asli, tanpa membutuhkan HP atau source
kernel online. Tautan/hash source pembanding ada di bukti entry. Menjalankan
ulang probe DT bersifat opsional: tools/collect_reboot_dt.js hanya membaca tree
Android dan mencetak JSON; hasil lama sudah tersimpan tanpa identifier perangkat.
Dua alat baru hanya mengeluarkan JSON/disassembly; kandidat CN dihitung dalam
memori dan tidak dibuat menjadi file firmware. Source pembanding DeviceInfo
dipin dalam summary bukti; tidak dibutuhkan koneksi online untuk mengulang
pemindaian terhadap ZIP asli.

Untuk mengulang analisis laporan collector v2 yang sudah diterima:

```bash
python3 src/analyze_boot_metadata.py /path/to/sm8750-boot-metadata.txt --boot-properties-spoofed --output generated/boot-metadata-analysis.json
```

Flag spoofing di atas sesuai klarifikasi pengguna pada kasus ini; jangan
menandai laporan perangkat lain dengan flag itu tanpa informasi yang sesuai.
Temuan fase 2 ada di BOOT_METADATA_FINDINGS.md.

Paket annibale dapat direproduksi tanpa ZIP masukan karena default disertakan:

```bash
python3 annibale/src/patch.py --check
python3 -m pip install -r annibale/src/requirements.txt
python3 annibale/src/verify_signature.py --check
```

Hasil audit yang benar adalah stock VALID dan kandidat INVALID. Repack
memperbaiki format/checksum/digest, bukan signature OEM. File ELF dan catatan
fastboot yang diminta ada dalam annibale; baca ANNIBALE_BUILD.md dan
annibale/notes.txt sebelum menafsirkan kandidat sebagai file untuk uji HP.

Untuk hasil live tanggal 7 November, sediakan kembali ZIP privat
`SM8750-live-boot-inputs-2026-11-07.zip`. Ini berisi Tools FV, volume logfs,
xbl_sc_logs dan probe, bukan source untuk dipublikasikan. Hash tiap anggota
ada di LIVE_INPUTS.json. Kemudian jalankan:

```bash
.venv/bin/python src/analyze_live_boot.py /path/to/SM8750-live-boot-inputs-2026-11-07.zip --firmware /path/to/gpt.zip --out generated/live
.venv/bin/python src/verify_research.py /path/to/gpt.zip --upstream ../gbl_root_canoe --live-archive /path/to/SM8750-live-boot-inputs-2026-11-07.zip --log generated/full-validation.txt
```

Raw log mengandung identifier; analyzer hanya mengekspor baris yang cocok
dengan pola lengkap yang diizinkan. Baca LIVE_BOOT_FINDINGS.md sebelum menarik
kesimpulan entry dari keberadaan Shell atau filesystem FAT.

Prototype Ebl-first dan perbandingan logo membutuhkan dependency Unicorn dari
requirements.txt. Source penuh repo diperlukan untuk menjalankan generator
hook; file 72 byte di paket annibale merupakan program studi, bukan image EFI.

```bash
.venv/bin/python src/plan_ebl_first.py /path/to/gpt.zip --out generated/ebl-first --emulate
.venv/bin/python src/analyze_logo_donor.py /path/to/logo.zip --firmware /path/to/gpt.zip --out generated/logo-comparison --cert-out generated/abl-certs
.venv/bin/python src/verify_research.py /path/to/gpt.zip --upstream ../gbl_root_canoe --live-archive /path/to/SM8750-live-boot-inputs-2026-11-07.zip --logo-archive /path/to/logo.zip --log generated/all-validation.txt
```

LOGO_INPUTS.json memuat hash input logo.zip yang dikirim pengguna. Tanpa ZIP
tersebut, bagian perbandingan logo dapat dilewati; generator hook dan analisis
firmware lainnya tetap dapat dijalankan. Rincian ada di EBL_FIRST_FINDINGS.md.

## 5. Baca bukti dengan ruang alamat yang tepat

| Bentuk alamat | Contoh | Cara membaca |
|---|---|---|
| Offset file ELF | `abl.elf:0x1078` | Posisi dalam file ABL yang dikompresi |
| Offset buffer dekompresi | `LZMA output:0x8` | Posisi setelah stream dibuka |
| Offset PE payload | `boot.efi:0x3A72C` | Lokasi instruksi patch pada PE engineering |
| RVA modul | `QcomBds RVA 0x5254` | Alamat relatif image PE QcomBds |
| Nilai FDT | CN `xbl_config.elf:0x242D8` | Awal string LinuxLoader di property DT |

Jangan menerapkan offset PE langsung ke file ELF, atau memakai alamat
engineering pada CN tanpa pemetaan ulang.

## 6. Mengumpulkan informasi Android

Salin `tools/collect_readonly.sh` ke `/sdcard/Download/` pada HP yang sedang
berfungsi. Dari shell Android/Termux:

```bash
su -c 'sh /sdcard/Download/collect_readonly.sh' > sm8750-device-info.txt
```

Collector hanya mencetak properti build, daftar link partisi, visibilitas EFI,
dan BootOrder/BootNext/AttemptUSBFirst bila dapat dibaca. Ia tidak mengubah
status lock, menulis partisi, memasang filesystem, atau me-reboot HP.
Tidak terlihatnya `/sys/firmware/efi` tidak membuktikan UEFI tidak digunakan
pada tahap boot sebelumnya.

Log PIL/UEFI masih perlu diperoleh melalui fasilitas logging yang benar-benar
tersedia pada perangkat. Jangan menganggap `dmesg` Android sudah mencakup
seluruh log sebelum kernel.

Sesudah laporan v1 tersedia, gunakan `tools/collect_boot_metadata.sh` untuk
mencocokkan hash boot firmware, ukuran, dan GPT type GUID. Detail hasil v1 dan
perintah fase 2 ada di DEVICE_FINDINGS.md. Collector fase 2 membutuhkan root
serta awk untuk bagian GPT; hasil akan menyebutkan bagian yang tidak tersedia.

Pengujian parser GPT pada komputer Linux dapat diulang tanpa perangkat:

```bash
python3 -m unittest discover -s tests -v
sh -n tools/collect_boot_metadata.sh
```

## 7. Menyimpan perkembangan berikutnya

Kerjakan perubahan baru pada branch penelitian:

```bash
git switch -c research/next-step
git add src tools evidence README.md LAPORAN.md RESEARCH_CONTINUED.md HANDOFF.md HISTORY.md
git diff --cached --stat
git commit -m "Describe the concrete research result"
git push -u origin research/next-step
```

Tambahkan bukti baru dan batas pengujiannya ke HISTORY.md/HANDOFF.md. Jangan
menandai port sebagai bekerja sebelum ada log dan hasil runtime yang sesuai.

Untuk membuat snapshot riwayat di luar repo:

```bash
git bundle create ../SM8750-research-history-2026-11-07.bundle --all
git bundle verify ../SM8750-research-history-2026-11-07.bundle
```

## 8. Status koneksi GitHub pada sesi penelitian ini

Koneksi plugin berhasil membaca akun `dinzzxyz` dan menemukan repo tujuan.
Percobaan create README melalui koneksi itu mendapat HTTP 403 `Resource not
accessible by integration`. Setelah pengguna menyelesaikan login browser
GitHub CLI, push Git langsung berhasil untuk commit awal.

Kredensial tidak disertakan dalam source, bundle, atau ZIP. Pada sesi baru,
gunakan koneksi yang memang mempunyai izin menulis; tidak perlu menempelkan
password atau token ke percakapan.
