# Image UEFI Ebl-first annibale — checkpoint v8

7 November 2026, Asia/Jakarta. Atas permintaan pengguna, hook v7 sekarang
dikemas dalam **image UEFI ELF lengkap**, dengan default dan script reproduksi.
Pemanggilnya adalah QcomBds dalam UEFI. **Tidak ada ABL Ebl-first baru** dalam
desain ini; ABL kandidat lama hanya memuat empat rentang patch Boot State.

**Signature OEM image UEFI hasil patch INVALID.** Container/digest yang benar
dan delapan kasus emulasi tidak membuktikan firmware akan diterima atau Ebl
berjalan di HP. Ini artefak eksperimen yang dapat diperiksa, bukan rilis port
SuperFastboot siap flash. Tidak ada flashing atau reboot perangkat dilakukan.

## File dan hash lengkap

| File dalam annibale | Peran / ukuran / SHA-256 |
|---|---|
| `OS3.0.307.0.WPKCNXM_uefi_EBL_FIRST_RESEARCH.elf` | UEFI eksperimen, 2.839.004 byte; `4d27c3300126e46e0f736a45d8899a02c9277baa4250d47744fcdb35abd112cd` |
| `src/OS3.0.307.0.WPKCNXM_uefi.elf` | UEFI stock, persis `cn/uefi.elf`; 2.839.004 byte; `1488a82e6735698f84bf0dcf05894723fba5cc2656fa1ed14dd91776b623481a` |
| `src/patch_uefi_ebl_first.py` | Builder stdlib, memakai helper `src/patch.py`; menolak basis berbeda |
| `src/verify_uefi_signature.py` | Audit signature dengan helper `src/verify_signature.py` dan cryptography |
| `uefi-ebl-first-build-report.json` | Byte patch, ruang alamat, kompresi, file chain dan digest |
| `uefi-ebl-first-signature-audit.json` | Stock VALID, eksperimen INVALID; signature/cert asli dipertahankan |

ABL pada `annibale/OS3.0.307.0.WPKCNXM_abl.elf` tetap berhash
`bbf89327ec2060f83d5e9ec068fd77d2fe2010caee865be176c835bb6dc3447a`.
Ia tidak perlu diubah untuk rancangan hook ini. Jangan mengubah nama UEFI
menjadi `abl.elf` atau mengarahkannya ke partisi ABL.

## Jalur dan alamat

Angka pada kolom kedua menyebut ruang alamatnya. PE raw offset dan RVA sama
hanya pada lokasi QcomBds yang dipin ini; tidak sama dengan offset ELF.

| Bagian | Posisi / perubahan |
|---|---|
| ELF PT_LOAD | File UEFI `[0x1000,0x2B4000)`, panjang `0x2B3000` |
| FFS Main FV luar | File UEFI `0x4E238`, GUID `9e21fd93-9c72-4c15-8c4b-e77f1db2d792` |
| GUID-defined section | File UEFI `0x4E250`, GUID LZMA `ee4e5898-3914-4259-9d6e-dc7bd79403cf` |
| Stream LZMA | File UEFI `0x4E268`; 668.275 → 662.182 byte |
| Main FV | Buffer dekompresi `0x8`, panjang `0x41F000`, GUID `631008b0-b2d1-410a-8b49-2c5c4d8ecc7e` |
| FFS QcomBds | Buffer `0x3C18D0`, GUID `5a50aa81-c3ae-4608-a0e3-41a2e69baf94`, type 7 |
| PE QcomBds | Buffer `0x3C18F4`, panjang `0x20000` |
| Call | PE raw/RVA `0x5254`: `b60a0094` → `ab5d0094`; BL helper `0x7D2C` → BL stub `0x1C900` |
| Stub | PE raw/RVA `0x1C900`, 72 byte, sebelumnya nol; literal Ebl UTF-16 pada `0x1C940` |
| Main FV / ABL FV pointers | PE raw/RVA `0x1D0F8` / `0x1D0E8` |
| Stub kembali | Continuation PE RVA `0x5258` setelah LinuxLoader kembali |
| PAD FFS baru | File UEFI `0xEFD10`, panjang `0x17D0` = 6.096 byte |
| FFS berikutnya | Tetap file UEFI `0xF14E0`, tidak digeser |
| Digest PT_LOAD | File UEFI `0x2B4150`, SHA-384 baru |
| Signed range OEM | File UEFI `[0x2B4000,0x2B41B0)`, 432 byte |
| Signature / chain | File UEFI `0x2B41B0` / `0x2B4218`; blok 104 / 3.360 byte |

Alur: setelah charger dan persiapan PIL ABL asli, call LinuxLoader dialihkan
ke stub. Stub menyimpan argumen/register, memanggil helper native untuk Ebl
di Main FV, lalu memanggil LinuxLoader di ABL FV bila Ebl kembali. Status
LinuxLoader dikembalikan ke caller asli. Jika Ebl tidak kembali, alur tidak
melanjutkan LinuxLoader. Tidak ada payload GBL/SuperFastboot baru disisipkan.

Hash PE QcomBds stock:
`c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78`.
Hash hasil:
`6a2ae633b79c979dfffad7df8100c5c624fc52c5cc71601a16139f635a7da16e`.
Ada 63 byte berbeda dalam dua rentang berukuran 4 dan 72 byte. Byte stub
lengkap/listing/ABI ada di `annibale/research` dan `EBL_FIRST_FINDINGS.md`.

## Repack dan pembuktian offline

Ukuran section/FFS Main FV serta checksum header diperbarui. Ruang tersisa
diwakili PAD FFS dengan body terhapus 0xFF, agar enumerasi tidak berhenti pada
celah sebelum file berikutnya. Semua file lain mempertahankan isi/posisinya;
header ELF, program headers, panjang image, chain, signature dan 676 byte
trailing 0xFF dipertahankan. Hanya wilayah file Main FV dan 48 byte digest
PT_LOAD berubah pada ELF. Kedua header FV dan seluruh file chain diperiksa.

Ekstraktor PE independen menemukan 104 modul sebelum/sesudah: QcomBds berubah
sesuai rencana, 103 modul lain identik byte demi byte. Parser FV independen
masih menjangkau FFS berikutnya. Rebuild menghasilkan ELF/report byte-identik.
Tes negatif menolak basis salah, input/output sama, digest rusak, header PAD
rusak dan celah erased yang menyembunyikan file berikutnya.

Audit memakai cert asli: signature stock ECDSA P-384/SHA-384 valid, signature
yang sama pada image hasil invalid. DER signature UEFI 102 byte ditambah dua
nol, berbeda dari panjang DER ABL. Tiga cert tetap sama. Tidak ada private key
OEM, signature baru, atau bypass autentikasi ditemukan pada checkpoint ini.

## Reproduksi tanpa gpt.zip atau HP

Dari root repo, Python 3.10+ dengan lzma:

```bash
python3 annibale/src/patch_uefi_ebl_first.py --check
python3 -m pip install -r annibale/src/requirements.txt
python3 annibale/src/verify_uefi_signature.py --check
```

Hilangkan `--check` untuk membuat ulang berkas yang belum ada. Untuk output
baru gunakan `--output /path/hasil.elf --report /path/laporan.json`. Builder
menolak menimpa file berbeda dan tidak menjalankan adb/fastboot/akses blok.

Untuk emulasi, ekstraksi independen dan regresi penuh gunakan requirements
root lalu perintah pada `RECOVERY.md`. Buktinya berada dalam
`evidence/uefi_ebl_first_2026_11_07`. SHA paket ada di `annibale/SHA256SUMS.txt`.

## Batas pengujian berikutnya

Padding stub belum dibuktikan bebas dari semua referensi runtime. Helper UEFI
masih dimock dalam emulasi; protokol, console/input, MMU/cache, LoadImage,
autentikasi firmware dan eksekusi Ebl asli belum diuji. Prioritas selanjutnya
adalah jalur autentikasi/entry yang terjangkau, sebelum mencoba boot perangkat.
Catatan fastboot pada `annibale/notes.txt` adalah referensi sintaks per komponen,
bukan rekomendasi mem-flash kandidat signature-invalid ini pada HP sekarang.

Format PAD/checksum/alignment dirujuk ke source primer PI dan EDK II;
lihat `evidence/uefi_ebl_first_2026_11_07/source-references.json`. Alat yang
ditulis di sini bukan salinan source firmware atau implementasi OEM verifier.
