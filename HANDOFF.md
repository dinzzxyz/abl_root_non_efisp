# Titik lanjut untuk sesi atau kontributor berikutnya

Updated: 7 November 2026, Asia/Jakarta.

## Tujuan pengguna

Meneliti port SuperFastboot/fake-lock dari acuan SM8850 ke firmware SM8750
annibale tanpa partisi raw `efisp` yang digunakan acuan. Pengguna membutuhkan
source, commit, byte patch, alamat, jalur boot, dan cara memulihkan pekerjaan
ketika workspace atau konteks percakapan hilang.

## Repo dan checkpoint

- Repo: https://github.com/dinzzxyz/abl_root_non_efisp
- Commit awal: `fffb031ef92a1c1549aefec5337aa1a959a5a062`.
- Branch remote utama: `main`.
- Basis source upstream: `4ef438cfde42943694fde5753bbf5d8c0b4ec02e` pada
  https://github.com/SuperTurtleDev/gbl_root_canoe.
- Input asli: `gpt.zip`; hash dan seluruh nama file ada di `INPUTS.json`.
  Byte firmware tidak dimasukkan ke source repo.

Login GitHub dan ketersediaan kredensial bergantung pada sesi. Jangan
menganggap plugin yang dapat membaca repo otomatis dapat melakukan push.
Periksa koneksi yang berlaku saat melanjutkan; jangan menyimpan token dalam Git.

## Yang sudah selesai

1. Memulihkan resep patch lama dari ABL engineering: 9 byte / 4 lokasi,
   hasil sama persis dengan `result/boot.efi`.
2. Mengidentifikasi perbedaan PE mentah versus container ELF/FV ABL, beserta
   pemeriksaan ELF di PILDxe.
3. Memetakan QcomBds yang identik pada CN dan engineering. Default apps
   dipanggil sebelum pembacaan BootNext.
4. Menghubungkan argumen GUID dispatch dengan FV aktual dalam ABL.
5. Menemukan SHA-384 payload PT_LOAD di hash segment ELF pada `0x51150`.
6. Mengurai konfigurasi UEFI dari FDT xbl_config, bukan placeholder cfg.
7. Mendata deklarasi protokol LinuxLoader dan FastbootLib serta penanda
   GUID pada modul firmware SM8750.
8. Mencatat dependensi penyimpanan default BDS terhadap ESP dan menyiapkan
   collector Android yang hanya membaca.
9. Membaca diagnostik pengguna: annibale/sun, Android 16, build CN yang sama,
   slot A, 141 tautan by-name tanpa nama efisp. Menemukan uefivarstore,
   toolsfv dan sumber log sebagai target penelusuran berikutnya.
10. Menyiapkan collector fase 2 untuk hash komponen boot, ukuran dan GPT type
    GUID. Lihat DEVICE_FINDINGS.md untuk data dan batas kesimpulannya.
11. Menerima hasil fase 2: uid=0; keenam prefix ABL/UEFI/XBL config pada slot
    A/B cocok dengan file image CN. Tercatat 135 partisi dari enam tabel GPT,
    tanpa nama efisp maupun type GUID ESP standar pada data tersebut.
12. Pengguna mengonfirmasi spoofing properti status boot. Properti locked/
    green tidak dijadikan bukti keadaan lock atau keberhasilan patch ABL.
13. Kernel melaporkan EFIVAR_FS tidak aktif dan runtime directory EFI tidak
    tersedia. Type GUID uefivarstore cocok dengan konstanta VariableDxe CN.
14. Probe patcher upstream pada CN dan engineering berhenti karena pola Boot
    State tidak ditemukan. Tidak ada output patch lengkap dari percobaan ini.
15. Memetakan satu blok Boot State secara struktural pada setiap ABL. Mask
    upstream gagal karena bentuk CBZ/stack load berbeda dari TST/B.EQ/direct
    LDRB yang digunakan dua input ini.
16. Menemukan analog empat lokasi patch pada CN: 0x3A398, 0x3B774, 0x3B7B8,
    0x45674 dalam PE hasil ekstraksi. Kandidatnya mengubah 10 byte, dihitung
    dalam memori saja. Metode yang sama menghasilkan engineering lama persis.
17. Menghubungkan getter dengan byte ke-13 sesudah basis DeviceInfo/magic;
    source DeviceInfo pembanding mendukung inferensi IsUnlocked. Detail dan
    batas dataflow tercatat di BOOTSTATE_FINDINGS.md.
18. Memetakan tabel 34 command CN dan handler lkmsg/lpmsg/uefilog. Handler
    uefilog mempunyai cabang argumen save, sehingga belum dianggap hanya
    membaca. Tidak ada command OEM dieksekusi.
19. Mengambil snapshot read-only langsung dari HP: toolsfv 1 MiB, volume
    logfs 5 MiB, xbl_sc_logs 128 KiB, serta probe header/bootconfig. Input
    firmware dan log mentah disimpan privat, bukan pada repo publik.
20. Memeriksa FAT12 pada logfs: sektor 4096, 1273 cluster, dua FAT identik,
    dan lima file UEFILOG0.TXT–UEFILOG4.TXT masing-masing 64 KiB.
21. Menginventarisasi 19 aplikasi Tools FV, termasuk Shell, Ebl dan Menu.
    Namespace inner Tools FV c4be3b58-1c19-4881-b101-8d02fce6708b berbeda
    dari namespace ABL yang dipakai dispatch default.
22. Membaca log stock: Secure Boot On, PROD/Retail TRUE, NV tables VOLATILE,
    VB2 orange, OS Loader dan penghentian Boot Services. Ini bukan uji port.
23. Menemukan tujuh kelompok XBL marker 463–469 tanpa match pola kegagalan
    PIL/ELF yang dicari; penyebab brick lama masih belum terbukti.

## Status yang belum boleh dianggap selesai

- Belum ada bukti runtime BDS kustom berjalan di SM8750.
- Belum ada image ABL baru yang dikemas, diautentikasi, dan diuji di HP.
- Belum ada log yang membuktikan penyebab brick atau keberhasilan fake lock.
- Ukuran/LBA/GPT type GUID sudah tersedia dari collector v2; CRC GPT dan
  daftar variabel EFI belum diperiksa. Tidak ditemukan ESP pada data enam LUN.
- Properti boot dikonfirmasi dimodifikasi modul. Status lock independen belum
  diperiksa; hash prefix firmware sudah cocok dengan CN.
- Empat lokasi kandidat CN sudah dipetakan, tetapi dataflow lintas seluruh
  CFG/alias dan efek runtime belum dibuktikan. Patcher upstream asli tetap
  gagal pada dua basis. Resep 9 byte lama khusus engineering yang dipin;
  kandidat CN 10 byte tidak menyediakan container ABL atau entry SuperFastboot.
- File `8750_noauth_Xiaomi.zip` adalah bahan pemulihan dari pengguna;
  kompatibilitas dan keberhasilan unbrick tidak diuji dalam pekerjaan ini.

## Data penting

| Item | Nilai |
|---|---|
| UI aplikasi ABL | `LinuxLoader` |
| FFS GUID | `f536d559-459f-48fa-8bbc-43b554ecae8d` |
| ABL FV name GUID | `046fae99-cf2e-49ed-a6a8-a1488b7e80d3` |
| QcomBds FFS GUID | `5a50aa81-c3ae-4608-a0e3-41a2e69baf94` |
| Callsite dispatch di QcomBds | RVA `0x5254` |
| Helper launch | RVA `0x7D2C` |
| Konfigurasi aplikasi | `/sw/uefi/str_param/DefaultBDSBootApp` |
| Basis patch | `eng rom/abl.elf` |

Alamat itu bukan offset universal. Cocokkan hash sebelum menggunakan alamat.
Penjelasan lengkap ada di LAPORAN.md dan RESEARCH_CONTINUED.md.

## Langkah berikut yang paling bernilai

Mulai dari identitas firmware terpasang, GPT/partisi dan log PIL/UEFI. Prioritas
adalah membuktikan entry yang dapat dijalankan dan kebijakan autentikasi.
Sesudah itu baru pilih media payload dan uji ABI/protokol BDS.

Identitas build, hash prefix komponen boot, dan metadata GPT sekarang tersedia.
Baca BOOT_METADATA_FINDINGS.md serta evidence/device_2026_11_06 terlebih dahulu.
Baca BOOTSTATE_FINDINGS.md serta evidence/bootstate_2026_11_06 untuk hasil baru.
Baca LIVE_BOOT_FINDINGS.md dan evidence/live_2026_11_07: sekarang log stock
serta Tools FV asli tersedia. Jalankan analyzer dengan dua ZIP privat menurut
RECOVERY.md; jangan meminta ulang collector metadata fase 1/2 tanpa alasan baru.
Lanjutkan caller Ebl, pemasangan Tools FV, gate retail/menu dan autentikasi
aplikasi sebelum LinuxLoader. Jangan menganggap Shell yang tersedia sudah
dapat dijalankan, atau logfs FAT12 sebagai ESP. NV volatile perlu diperhitungkan
dalam usulan BootNext/BootOrder; itu tidak membuktikan semua storage TEE volatile.
Jangan menyamakan handler log OEM dengan perintah yang bebas efek tulis:
uefilog mempunyai cabang save. Belum ada resep transfer log USB yang diuji.
Tidak ada tes tambahan yang diminta kepada pengguna pada akhir checkpoint ini.

Jangan mengulang flashing PE mentah ke ABL berdasarkan hilangnya padlock.
Gejala tersebut tidak membuktikan payload pernah dieksekusi.

## Membuka sesi baru

Minta kontributor membaca AGENTS.md, README.md, HANDOFF.md, LAPORAN.md,
RESEARCH_CONTINUED.md dan RECOVERY.md. Jalankan verifikasi offline sebelum
mengubah resep patch atau memperluas klaim ke ROM lain.
