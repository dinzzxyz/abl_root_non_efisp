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

## Status yang belum boleh dianggap selesai

- Belum ada bukti runtime BDS kustom berjalan di SM8750.
- Belum ada image ABL baru yang dikemas, diautentikasi, dan diuji di HP.
- Belum ada log yang membuktikan penyebab brick atau keberhasilan fake lock.
- Belum ada GPT lengkap dan daftar variabel EFI dari HP.
- Tidak adanya raw `efisp` adalah laporan pengguna; ZIP tidak berisi GPT
  lengkap yang memverifikasi seluruh layout perangkat.
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

Jangan mengulang flashing PE mentah ke ABL berdasarkan hilangnya padlock.
Gejala tersebut tidak membuktikan payload pernah dieksekusi.

## Membuka sesi baru

Minta kontributor membaca AGENTS.md, README.md, HANDOFF.md, LAPORAN.md,
RESEARCH_CONTINUED.md dan RECOVERY.md. Jalankan verifikasi offline sebelum
mengubah resep patch atau memperluas klaim ke ROM lain.
