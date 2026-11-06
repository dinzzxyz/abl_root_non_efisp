# Titik lanjut untuk sesi atau kontributor berikutnya

Updated: 6 November 2026, Asia/Jakarta.

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

## Status yang belum boleh dianggap selesai

- Belum ada bukti runtime BDS kustom berjalan di SM8750.
- Belum ada image ABL baru yang dikemas, diautentikasi, dan diuji di HP.
- Belum ada log yang membuktikan penyebab brick atau keberhasilan fake lock.
- Ukuran/LBA/GPT type GUID sudah tersedia dari collector v2; CRC GPT dan
  daftar variabel EFI belum diperiksa. Tidak ditemukan ESP pada data enam LUN.
- Properti boot dikonfirmasi dimodifikasi modul. Status lock independen belum
  diperiksa; hash prefix firmware sudah cocok dengan CN.
- Pola boot-state CN belum dipetakan lengkap; patcher upstream gagal pada
  tahap tersebut. Resep 9 byte lama hanya untuk basis engineering yang dipin.
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
Lanjutkan analisis entry EFI, provider variable storage dan pola boot-state CN.
Tidak ada tes tambahan yang diminta kepada pengguna pada akhir checkpoint ini.

Jangan mengulang flashing PE mentah ke ABL berdasarkan hilangnya padlock.
Gejala tersebut tidak membuktikan payload pernah dieksekusi.

## Membuka sesi baru

Minta kontributor membaca AGENTS.md, README.md, HANDOFF.md, LAPORAN.md,
RESEARCH_CONTINUED.md dan RECOVERY.md. Jalankan verifikasi offline sebelum
mengubah resep patch atau memperluas klaim ke ROM lain.
