# Riwayat penelitian

## 2026-11-06 — snapshot awal

Commit `fffb031ef92a1c1549aefec5337aa1a959a5a062`:

- Membaca prompt dan catatan kegagalan dari ZIP pengguna.
- Mengekstrak PE ABL dan 104 PE unik pada masing-masing UEFI CN/engineering.
- Memulihkan patch lama secara byte-identik, 9 byte pada 4 rentang.
- Mengidentifikasi perbedaan format PE payload dan ELF/FV ABL.
- Memetakan urutan QcomBds/default app sebelum BootNext.
- Mengurai DT xbl_config dan menyimpan bukti serta source analisis.

## 2026-11-06 — kelanjutan dan pemulihan workspace

Commit penelitian lanjutan: `8d56aad3d05959929257908fce62528bbbb0e005`.

Commit dokumentasi pemulihan dapat ditemukan melalui:

```bash
git log --oneline --all
```

- Mencocokkan GUID argumen launch QcomBds dengan FV aktual dalam ABL.
- Mengidentifikasi FFS LinuxLoader dan callsite LoadImage/StartImage.
- Menemukan digest SHA-384 PT_LOAD pada offset `0x51150` di hash segment.
- Menginventarisasi 33 deklarasi protokol LinuxLoader/FastbootLib.
- Menelusuri penyimpanan default menu di ujung ESP dan fallback type GUID.
- Menambahkan verifikasi yang bisa dijalankan ulang serta collector Android.
- Menambahkan manifest input, catatan prompt/test asli, panduan recovery,
  dan handoff untuk sesi berikutnya.
- Login GitHub diverifikasi sebagai dinzzxyz; snapshot awal dipush ke repo
  `dinzzxyz/abl_root_non_efisp` melalui Git setelah koneksi plugin menolak write.

Status pengujian: statis/offline. Belum ada flashing atau keberhasilan BDS
kustom/fake lock pada perangkat yang diverifikasi oleh penelitian ini.

## 2026-11-06 — diagnostik pertama dari perangkat

- Membaca sm8750-device-info.txt: annibale/sun, Android 16,
  OS3.0.307.0.WPKCNXM, slot A.
- Memetakan 141 tautan by-name; nama efisp tidak muncul. uefivarstore,
  toolsfv, logfs, persist, blackbox dan xbl_sc_logs tersedia pada daftar.
- Mencatat properti green/locked sebagai laporan Android, tanpa menganggapnya
  bukti status lock independen atau keberhasilan patch.
- Mencocokkan penanda VariableDxe pada firmware acuan dengan kebutuhan
  penelitian variable storage; belum ada akses variabel runtime yang terbukti.
- Menambahkan collector fase 2 yang hanya membaca block device dan pengujian
  parser GPT sintetis. Hash komponen boot terpasang dan GPT type GUID masih
  menunggu hasil dari perangkat.

## 2026-11-06 — hash komponen boot dan metadata GPT

- Menerima hasil collector v2 dengan uid=0; keenam prefix image ABL/UEFI/XBL
  config cocok dengan CN acuan, bukan engineering.
- Memeriksa 135 entry pada enam GPT, ukuran/LBA dan overlap; tidak ditemukan
  nama efisp maupun type GUID ESP standar. CRC GPT belum diperiksa.
- Pengguna mengonfirmasi properti boot dimodifikasi modul spoofing; nilainya
  tidak dipakai untuk membuktikan status lock.
- Mencatat EFIVAR_FS tidak aktif dan runtime directory EFI tidak tersedia.
- Mencocokkan GPT type GUID uefivarstore dengan empat konstanta VariableDxe.
- Probe patcher C upstream pada CN dan engineering berakhir exit 1 karena
  anchor Boot State tidak ditemukan; tidak ada output patch lengkap.
- Menambahkan parser laporan yang dapat diulang, pengujian, bukti dan
  BOOT_METADATA_FINDINGS.md. Tidak meminta tes flash atau pencopotan modul.

## 2026-11-06 — pemetaan struktural Boot State CN dan handler log

- Menemukan satu blok TST/B.EQ/MOV/LDRB/CMP/CSET/LSL pada setiap ABL;
  mendokumentasikan alasan mask CBZ upstream menghasilkan nol hit.
- Memetakan getter dengan byte ke-13 struktur DeviceInfo dan magic yang sama;
  membandingkan definisi IsUnlocked pada source publik yang dipin.
- Menurunkan empat rentang kandidat CN yang mengubah 10 byte. Hasil hanya
  dihitung dalam memori, tanpa menulis PE/ELF atau mengakses perangkat.
- Mengalibrasi metode yang sama terhadap engineering: semua byte identik
  dengan result/boot.efi lama (9 byte berbeda dari aslinya).
- Menambahkan pengujian penolakan branch salah, register sink yang ditimpa,
  pemisahan file offset/RVA, dan encoder ADRP melintasi batas page.
- Memetakan loop registrasi 34 command CN dan handler lkmsg/lpmsg/uefilog.
  Menemukan cabang save di uefilog; tidak menandainya sebagai hanya membaca.
- Menambahkan BOOTSTATE_FINDINGS.md, dua alat analisis, JSON, disassembly,
  dan pemeriksaan regresi. Entry EFI/autentikasi serta runtime tetap belum
  terbukti; tidak ada image flashable atau command OEM yang diuji.

## 2026-11-07 — capture live logfs, Tools FV dan XBL

- Membaca partisi melalui Desktop Commander pada Android dengan uid=0,
  tanpa flash, mount, reboot atau perubahan konfigurasi boot.
- Mengambil volume FAT12 5 MiB dalam partisi logfs 8 MiB; kedua FAT identik,
  lima UEFILOG*.TXT masing-masing 64 KiB dapat dibaca lengkap.
- Memperoleh bukti boot stock: secure boot On, PROD/Retail TRUE, NV volatile,
  VB2 orange, lalu ExitBootServices. Bootconfig kernel juga orange/unlocked;
  properti Android yang di-spoof tetap tidak dipakai sebagai bukti lock.
- Mengurai Tools FV asli: 19 aplikasi PE, termasuk Shell/Ebl/Menu. Inner FV
  berbeda GUID dari ABL FV. Ebl main UEFI merujuk GUID Tools FV dan memiliki
  bantuan MountFv, tetapi PE-nya berbeda dari Ebl yang ada di Tools FV.
- Memeriksa tujuh kelompok log XBL dengan marker 463–469. Tidak ada match
  pencarian kegagalan PIL/ELF yang ditargetkan; tidak menyimpulkan penyebab brick.
- Menyimpan masukan mentah secara privat dan hanya metadata/cuplik log yang
  diseleksi ke repo. Menambahkan analyzer FAT12 bounded, collector Node,
  pengujian korupsi filesystem dan batas privasi, serta panduan pemulihan.
- Jalur yang layak diteruskan adalah caller Ebl/Shell sebelum LinuxLoader;
  belum ada entry kustom atau image modifikasi yang diuji pada perangkat.

## 2026-11-07 — callback awal dan jembatan file/RAM Ebl native

- Menemukan provider protokol platform di QcomBds sendiri dan mengurai tujuh
  callback. Callback hotkey +0x28 dipanggil sebelum default apps; SetupApp
  launch tetap sesudahnya. Ini memperjelas batas analisis direct call terdahulu.
- Mengikuti callback awal: BDSHotKeyState, input key, OsIndications, counter
  perhatian dan pembacaan OEMSetupApp. Pemanggilan SerialPort Lib tidak
  disalahartikan sebagai launcher Ebl. Entry Ebl sebelum LinuxLoader belum ada.
- Membuktikan hubungan tabel command Ebl utama dengan handler start, loadfv,
  mountfv. Memetakan LoadImage/StartImage, DXE ProcessFirmwareVolume +0x98,
  installer FVB untuk FV bersarang dan Dispatch +0x80, beserta constructor
  DXE Services GUID dan byte instruksinya.
- Memeriksa DT live secara hanya baca: 5.615 direktori, tanpa error/batas,
  tanpa properti mode-*. Memeriksa tabel reboot-reason source publik MiCode
  yang dipin; tidak ada entry uefi. Tidak menyamakan source dengan kernel KSU
  yang belum dicocokkan, serta tidak menjalankan reboot percobaan.
- Menambahkan analyzer offline, lima pengujian negatif dan collector DT.
  Seluruh 18 pengujian unit dan pipeline firmware/live lulus. Metadata source,
  disassembly, hash, cara reproduksi dan batas runtime disimpan ke Git.
- Hipotesis lanjutan: entry Ebl native → probe EFI file/RAM → port BDS;
  entry, autentikasi, visibilitas filesystem dan pengganti SuperFbStore masih
  harus dibuktikan. Tidak ada flash atau eksekusi image kustom pada HP.

## 2026-11-07 — paket annibale, repack ELF dan audit ECDSA

- Mengikuti permintaan eksplisit pengguna: membuat annibale dengan kandidat
  OS3.0.307.0.WPKCNXM_abl.elf, default dalam src, script patch, audit signature,
  checksum dan notes.txt berisi reproduksi serta referensi fastboot/pemulihan.
  Pengecualian dua file firmware ini dicatat di AGENTS.md dan .gitignore.
- Mengemas empat rentang/10 byte kandidat PE CN ke ELF asli dengan panjang
  tetap. LZMA baru 310149 byte muat dalam PT_LOAD, dibanding 311404 byte asli.
  Ukuran section/FFS, checksum header dan digest payload SHA-384 diperbarui.
  Re-ekstraksi dan hash keluaran dipin, bukan sekadar perubahan ekstensi.
- Menemukan dan memvalidasi signature asli ECDSA P-384/SHA-384 atas signed
  range ELF [0x51000,0x511B0). DER signature 103 byte dalam blok 104 byte.
  Signature yang dipertahankan pada hasil patch INVALID, walau digest segmen
  dan hubungan signature tiga sertifikat valid. Tidak membuat signature OEM
  baru dan tidak menguji penerimaan firmware pada HP.
- Mengikat consumer QcomBds 0x4F4C dengan argumen ABL ke interface PILDxe
  0x171B8, method +8 → 0x1790 → helper 0x1FC0. Belum menemukan entry Ebl baru.
- Menambahkan enam pengujian paket/DER/overwrite/signature; seluruh 24 unit
  test lulus. Pipeline utama memeriksa pasangan ELF, reproduksi byte identik,
  ekstraksi PE independen dan batas signature. Bukti di annibale serta
  evidence/annibale_2026_11_07; panduan lanjutan pada ANNIBALE_BUILD.md.
- Tidak menjalankan command flash, reboot, relock atau menulis partisi HP.

## 2026-11-07 — contoh logo Fenrir dan program Ebl-first

- Membaca logo.zip, script, teks dan screenshot build tanpa mengeksekusi
  script kiriman atau mempublikasikan raw logo/screenshot.
- File repack sudah memuat cert1/cert2 donor. Repair mempertahankannya,
  menambah context-[0] 90 byte untuk hash baru dan memperbaiki alignment.
  Hash image memakai padding nol 16 byte. Tidak menyamakan observasi file
  dengan pengujian native verifier atau boot MediaTek baru.
- Memin source primer Fenrir/liblk dan merujuk lisensinya tanpa menyalin
  source upstream ke source MIT penelitian.
- Memverifikasi signature stock UEFI dan ABL; ketiga cert identik. Kandidat
  ABL v6 sudah mempertahankan signature/cert asli. Mengekspor data publik
  cert serta signature donor sesuai permintaan pengguna.
- Membuat hook QcomBds 0x5254 → 0x1C900: Ebl Main FV lalu LinuxLoader ABL FV
  jika Ebl kembali. Program baru 72 byte tidak mengubah charger/PIL yang
  lebih dulu berjalan dan tidak diterbitkan sebagai image OEM.
- Delapan kasus emulasi ARM64/ABI dengan helper mock dan uji negatif baru
  membuat seluruh 32 tes lulus. Belum ada uji EFI/USB/display/boot HP.
- Menyimpan source generator, program/listing, cert, metadata dan panduan.
  Jalur autentikasi perubahan UEFI atau tulis RAM awal masih belum ditemukan;
  belum ada port SuperFastboot tanpa efisp yang berjalan di perangkat.

## 2026-11-07 — image UEFI Ebl-first aktual untuk annibale (v8)

- Melanjutkan permintaan upload sesudah sesi terputus. Checkpoint v7 hanya
  menerbitkan stub/listing/rencana; kini hook dikemas ke ELF UEFI lengkap.
  Pemanggil berada di QcomBds dalam UEFI, bukan ABL. ABL v6 tidak berubah.
- Menyertakan UEFI default CN, hasil OS3.0.307.0.WPKCNXM_uefi_EBL_FIRST_RESEARCH.elf,
  builder stdlib, laporan, audit signature dan panduan. Hash stock 1488a82e...
  dan hasil 4d27c330... dipin lengkap. Ukuran keduanya 2839004 byte.
- Mengubah call PE/RVA 0x5254 dan memasang stub 72 byte di 0x1C900. Hash PE
  sama dengan rencana v7 6a2ae633...; ada 63 byte berbeda dalam dua rentang.
  Stub mendahulukan Ebl Main FV dan melanjutkan LinuxLoader ABL FV bila kembali.
- Repack Main FV: LZMA 668275 → 662182 byte. PAD FFS 6096 byte di ELF 0xEFD10
  mempertahankan file berikutnya pada 0xF14E0. ELF/program headers, file lain,
  ukuran image, signature/cert dan trailing 676 FF tetap dipertahankan.
  Header/file-chain/checksum dan SHA-384 diperiksa setelah ekstraksi ulang.
- Ekstraktor PE independen menemukan 104 modul: hanya QcomBds berubah,
  103 modul lain identik. Parser FV independen tetap menjangkau FFS berikutnya.
  Enam tes baru mencakup container aktual, PAD/celah, digest, hash guard,
  input-overwrite, signature dan byte hasil yang kembali diemulasi.
- Seluruh 38 tes dan pipeline firmware/live/logo lulus. Signature UEFI stock
  VALID, modifikasi INVALID dengan cert OEM asli. Ini belum image diterima
  autentikasi, boot Ebl, atau port SuperFastboot yang berjalan di HP.
- Panduan membedakan target UEFI/ABL dan memberi referensi fastboot yang
  sesuai, tanpa menjalankan flash, reboot, relock atau penulisan partisi.
