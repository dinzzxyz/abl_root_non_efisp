# Perbandingan Fenrir dan prototype Ebl sebelum LinuxLoader

7 November 2026, Asia/Jakarta. **Temuan baru berupa analisis file, ekspor
sertifikat publik dan program hook yang diuji pada emulator CPU. Belum ada
UEFI yang dipatch atau dijalankan pada HP.**

## 1. Apa yang ditunjukkan logo.zip

Masukan baru pengguna berukuran 15.367.950 byte, SHA-256
`549ddd66d6719553e2cfa035f0cecb68bef376a60c7eda0b4c988085066d0267`.
`LOGO_INPUTS.json` memuat hash semua anggotanya. `sign_logo.py` dibaca sebagai
source dan tidak dieksekusi. Screenshot memperlihatkan output proses build
Fenrir; itu tidak menambahkan bukti flash/boot independen ke penelitian ini.
Keberhasilan logo di perangkat MediaTek mengikuti pengalaman yang dilaporkan
pengguna, sedangkan observasi byte berikut dapat diulang offline.

Ada enam header MTK pada setiap contoh: logo1/cert1/cert2/logo2/cert1/cert2.
File repack yang diberikan **sudah mempunyai payload cert1/cert2 donor**.
Namun header logo1 dan payloadnya berubah sehingga hash lama tidak lagi cocok.

Hasil yang diberi nama mod-signed melakukan dua perubahan teramati:

1. Cert1 logo1 tetap identik. Cert2 lama 982 byte dipertahankan sebagai suffix,
   dengan tambahan blok ASN.1 context-[0] sepanjang **90 byte** di depannya.
2. Header berikutnya kembali memenuhi alignment 16 byte. Pada file repack,
   lima header berada pada offset yang tidak sesuai alignment terdeklarasi:
   `0x300F3`, `0x309C3`, `0x30FA3`, `0x53E0F3`, `0x53E9C3`.

Prefix baru mengiklankan SHA-256 header baru dan SHA-256 payload baru setelah
padding nol sampai kelipatan 16. Hash payload tanpa padding berbeda; analyzer
memeriksa bentuk padding yang benar. Logo2 serta payload dua sertifikatnya
tidak berubah. Bukti JSON ada di `evidence/ebl_first_2026_11_07/comparison.json`.

Observasi ini memisahkan penyalinan sertifikat dari override hash dan perbaikan
container. File saja belum menentukan kontribusi masing-masing perubahan
terhadap gejala preloader; tidak ada native parser MTK yang dieksekusi di sini.

## 2. Hubungan dengan source primer Fenrir

Repo Fenrir dipin ke `ed86ee4459d8fb2ce5031149d64d2dc7c90848ab`;
liblk dipin ke `75c8f14f16457b6c53d950d18d1ed7d2a665bed6`.

- [Fenrir](https://github.com/R0rt1z2/fenrir/tree/ed86ee4459d8fb2ce5031149d64d2dc7c90848ab)
  mendeskripsikan dependensi pada kebijakan boot chain MediaTek tertentu.
- [certificate.py](https://github.com/R0rt1z2/liblk/blob/75c8f14f16457b6c53d950d18d1ed7d2a665bed6/liblk/structures/certificate.py)
  mendefinisikan pembentukan context-[0] override hash.
- [partition.py](https://github.com/R0rt1z2/liblk/blob/75c8f14f16457b6c53d950d18d1ed7d2a665bed6/liblk/structures/partition.py)
  menghitung hash image dengan padding nol 16 byte.

Versi/blob sumber dan lisensinya dicatat di `source-references.json` pada
folder bukti. Source GPL/AGPL tersebut tidak disalin ke source MIT proyek ini.
Menyalin sertifikat saja tidak mereplikasi asumsi parser/policy MediaTek
yang dipakai contoh ini pada platform lain.

## 3. Sertifikat Qualcomm sudah sama persis

Audit diperluas ke ABL dan UEFI asli CN. Keduanya memakai tiga sertifikat
DER yang **identik byte demi byte**. Leaf certificate SHA-256:
`2c2a1a828954062434bc11cd496fea487427fbdb6f79874ba204c33a0f9d71c3`.

| Data | ABL ELF asli | UEFI ELF asli |
|---|---|---|
| SHA-256 container | `d6e9b411…` | `1488a82e…` |
| Software ID di signed metadata | `0x1C` | `0x09` |
| Signed range, offset file ELF | `[0x51000,0x511B0)` | `[0x2B4000,0x2B41B0)` |
| Signature image dengan leaf public key | Valid | Valid |
| Setelah satu byte digest pada signed data diubah | Invalid | Invalid |

Percobaan satu byte itu hanya pemeriksaan signature, bukan image UEFI baru.
Kandidat ABL v6 yang sudah diterbitkan juga mempertahankan seluruh blok
signature/sertifikat asli secara identik. Hash payload berubah; signature
image tidak diperbarui oleh penyalinan sertifikat tersebut.

Sesuai permintaan pengguna, `annibale/research/certs/` kini memuat:
`abl_leaf.der`, `abl_intermediate.der`, `abl_root.der`,
`abl_chain_with_padding.bin` (3.360 byte) dan
`abl_original_image_signature.bin` (104 byte). Ini seluruhnya data publik
yang diekstrak dari ABL default, tanpa private key atau signature baru.

Audit tidak membuktikan kebijakan runtime/fused root perangkat. Belum
ditemukan mekanisme override hash ala contoh MTK pada jalur Qualcomm yang
diperiksa. Itu batas hasil saat ini, bukan pembuktian bahwa seluruh firmware
Qualcomm bebas dari kelemahan parser.

## 4. Titik program yang konkret untuk Ebl lebih dulu

Basis QcomBds masih SHA-256
`c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78`.
Semua alamat pada tabel ini adalah **RVA/offset PE QcomBds**, bukan offset
`abl.elf`, `uefi.elf` atau alamat fisik RAM.

| Peran | Alamat / byte |
|---|---|
| Call peluncur LinuxLoader | RVA `0x5254`, asli `b6 0a 00 94` → helper `0x7D2C` |
| Usulan call ke stub | `ab 5d 00 94` → RVA `0x1C900` |
| Area kandidat stub | RVA `0x1C900`, 72 byte nol dalam section executable |
| Literal UTF-16 Ebl | RVA `0x1C940`, 8 byte |
| Pointer GUID Main FV | RVA `0x1D0F8` |
| Pointer GUID ABL FV asli | RVA `0x1D0E8` |
| Kembali ke caller | RVA `0x5258` |

Main FV bernama `631008b0-b2d1-410a-8b49-2c5c4d8ecc7e` memang memuat Ebl dan
QcomChargerApp. Ini dikonfirmasi dari FV pada buffer hasil dekompresi UEFI,
bukan hanya kemunculan GUID. LinuxLoader berada dalam namespace ABL FV
`046fae99-cf2e-49ed-a6a8-a1488b7e80d3`. Mengubah nama aplikasi tanpa mengubah
namespace tidak cukup untuk menemukan Ebl.

Program 16 instruksi menyimpan X19/X20 dan FP/LR pada frame 32 byte,
menyimpan argumen LinuxLoader asli, menyiapkan Main FV dan string Ebl, lalu
memanggil helper native. Bila call kembali, argumen asli dipulihkan untuk
call LinuxLoader. Register/stack dipulihkan dan status LinuxLoader diteruskan
ke continuation asli. Nama Ebl berada dalam literal baru; tidak menimpa
string LinuxLoader pada stack caller.

Hook hanya berlaku pada alur yang sudah mencapai call `0x5254`. Jalur charger
dan persiapan PIL ABL sebelumnya tetap berjalan. ABL asli tidak perlu diubah
oleh rancangan hook ini. SHA-256 program baru 72 byte:
`c23fd7d7575070f8b87de2d7990ad95d856d407c7353aae25017c5c807d0f234`.

`DefaultChargerApp` juga menunjukkan jalur Main FV yang lebih awal: property
`/sw/uefi/str_param/DefaultChargerApp` bernilai QcomChargerApp pada offset
file CN xbl_config `0x242BC`, dengan call QcomBds `0x5074`. Mengubah property
itu dapat mengubah perilaku charging; prototype tidak mengubahnya. Property
DefaultBDSBootApp berada di `0x242D8` dan tetap LinuxLoader.

## 5. Apa yang lulus emulasi dan yang belum

Unicorn 2.1.4 menjalankan byte ARM64 stub, dengan helper `0x7D2C` dimock.
Delapan kasus mencakup dua base alamat image, status Ebl sukses/error dan
status LinuxLoader sukses/error. Helper mock sengaja menimpa register
caller-saved X0–X18 dan flag NZCV.

Pemeriksaan lulus untuk urutan/nama/namespace, argumen ketiga NULL, stack
16-byte-aligned pada call, pemulihan SP serta X19–X29, continuation `0x5258`,
dan status LinuxLoader. Uji negatif mendeteksi namespace salah dan instruksi
penyimpanan register yang dihilangkan. Ini pemeriksaan ABI/control flow,
**bukan menjalankan Ebl atau LinuxLoader yang sebenarnya**.

Area stub nol dan executable, tanpa direct branch atau pointer qword aligned
yang ditemukan menuju rentang itu. Itu belum membuktikan padding bebas dari
seluruh referensi runtime. MMU/cache, kebijakan LoadImage, console, perangkat
input dan protokol native belum diuji. Jika Ebl tidak kembali, LinuxLoader
tidak dilanjutkan oleh rancangan ini.

Penerapan memerlukan modifikasi UEFI yang diterima autentikasi atau jalur
tulis RAM sebelum dispatch. Keduanya belum ditemukan. Generator hanya
menerbitkan program baru, listing dan JSON; tidak menulis PE/ELF OEM baru.
Kandidat ABL v6 tidak berubah dan tidak menyertakan hook ini. Checkpoint v8
berikutnya kini menambahkan builder terpisah dan image **UEFI** lengkap;
lihat UEFI_EBL_FIRST_BUILD.md. Batas generator di atas tetap berlaku untuk
src/plan_ebl_first.py, bukan pernyataan bahwa image v8 belum tersedia.

## 6. Reproduksi

Untuk image UEFI eksperimen v8, bukan hanya program studi di bawah, jalankan
`python3 annibale/src/patch_uefi_ebl_first.py --check` dan
`python3 annibale/src/verify_uefi_signature.py --check`. Lihat
UEFI_EBL_FIRST_BUILD.md untuk hash, repack dan bukti signature-invalid.

```bash
.venv/bin/python src/plan_ebl_first.py /path/to/gpt.zip --out generated/ebl-first --emulate
.venv/bin/python src/analyze_logo_donor.py /path/to/logo.zip --firmware /path/to/gpt.zip --out generated/logo-comparison --cert-out generated/abl-certs
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python src/verify_research.py /path/to/gpt.zip --upstream ../gbl_root_canoe --live-archive /path/to/SM8750-live-boot-inputs-2026-11-07.zip --logo-archive /path/to/logo.zip --log generated/verification.txt
```

`logo.zip` diperlukan hanya untuk perbandingan MTK. Input mentahnya tetap
privat. Hasil program/cert publik ada di annibale/research dan metadata/bukti
di evidence/ebl_first_2026_11_07. Tidak ada flashing, reboot, relock atau
penulisan partisi yang dilakukan dalam checkpoint ini.
