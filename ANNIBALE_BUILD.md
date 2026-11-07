# Paket annibale dan batas autentikasi ABL

7 November 2026, Asia/Jakarta. Atas permintaan pengguna, folder `annibale`
sekarang memuat ABL default, hasil patch berbentuk ELF, script reproduksi dan
`notes.txt`. **ELF berhasil direkonstruksi offline; signature OEM hasilnya
invalid.** Ini belum merupakan port SuperFastboot atau hasil boot di HP.

## Berkas dan hash

| Path relatif terhadap annibale | Peran |
|---|---|
| `OS3.0.307.0.WPKCNXM_abl.elf` | Container ELF hasil patch/repack |
| `src/OS3.0.307.0.WPKCNXM_abl.elf` | Default CN asli dari masukan pengguna |
| `src/patch.py` | Reproduksi dengan Python standar, tanpa perangkat |
| `src/verify_signature.py` | Audit ECDSA dengan public key OEM tertanam |
| `src/requirements.txt` | Dependensi audit opsional |
| `notes.txt` | File, reproduksi, sintaks fastboot dan pemulihan |
| `build-report.json` | Offset, byte, ukuran, checksum dan digest |
| `signature-audit.json` | Hasil kriptografi asli versus kandidat |
| `SHA256SUMS.txt` | Hash berkas paket |

Kedua ELF berukuran 335.672 byte. Tidak dibuat alias `boot.elf` kedua yang
dapat tertukar dengan default. Publikasi dua ELF mengikuti permintaan eksplisit
pengguna; firmware OEM/turunannya tidak direlisensi menjadi MIT. Raw log,
firmware komponen lain, loader EDL dan kredensial tidak ditambahkan.

| Objek | SHA-256 |
|---|---|
| ABL default | `d6e9b4111652bc0067547994a3f8396541383e093aee5d74b154e88f82342309` |
| ELF hasil repack | `bbf89327ec2060f83d5e9ec068fd77d2fe2010caee865be176c835bb6dc3447a` |
| PE dalam hasil | `9b55fb1ee70b3519a947160033d4d9929edf6d045d6dbc0c4e39b23fdf8fffc5` |

## Repack yang diperiksa

Empat rentang/10 byte PE mengikuti [BOOTSTATE_FINDINGS.md](BOOTSTATE_FINDINGS.md).
Basis lengkap, byte asal dan hash PE divalidasi. Tidak ditambahkan entry GBL,
driver atau menu BDS. PE berada pada buffer dekompresi `0xB8`, bukan offset ELF.

LZMA-alone memakai dictionary 16 MiB, lc=3/lp=0/pb=2, normal mode, BT4, nice
length 273. Stream berubah dari 311.404 menjadi 310.149 byte dan tetap muat
dalam PT_LOAD asli. Ukuran GUID-defined section/FFS luar dan checksum header
FFS diperbarui. Sisa PT_LOAD diisi `0xFF` seperti pola awal. FFS data-checksum
dinonaktifkan dengan sentinel `0xAA` pada layout yang diidentifikasi ini.

Header ELF/program header tetap. SHA-384 PT_LOAD diganti di `ELF:0x51150`.
Re-ekstraksi memeriksa seluruh buffer, hash PE kandidat dan checksum FV/FFS.
Pipeline utama juga memakai parser PE independen. Mengganti ekstensi PE mentah
menjadi `.elf` tidak menghasilkan struktur ini.

## Bukti signature baru

Format dibandingkan dengan source primer
[qtestsign hashseg.py](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/mbn/hashseg.py),
Git blob `619bcd6c61cb25e55f4bf4ec17257e44ac1af193`. Source tersebut tidak
disalin atau digunakan untuk menandatangani hasil. Alamat berikut adalah
**offset file ELF ABL**, bukan RVA PE.

| Bagian MBN v7 | Offset / ukuran |
|---|---|
| Header + common metadata | `0x51000`, 64 byte |
| OEM metadata | `0x51040`, 224 byte |
| Tiga digest SHA-384 | `0x51120`, 144 byte |
| Digest PT_LOAD | `0x51150`, 48 byte |
| Signed data | `[0x51000, 0x511B0)`, 432 byte |
| Signature OEM | `0x511B0`, blok 104 byte |
| DER signature | 103 byte, kemudian satu `0x00` |
| Sertifikat leaf/intermediate/root | `0x51218`, DER 600/689/724 byte |
| Padding area sertifikat | 1.347 byte `0xFF` |

Audit ECDSA secp384r1/SHA-384 memvalidasi signature asli dengan leaf public key
tertanam. Signature yang dipertahankan pada kandidat gagal setelah digest
diganti. Hubungan signature ketiga sertifikat tetap valid secara kriptografis.
Checksum/digest benar dan sertifikat valid belum cukup untuk menandatangani
image baru. Tidak ada private key OEM, signature pengganti atau bypass dalam
paket ini. Audit tidak membuktikan root key fuse, kebijakan runtime khusus,
atau penyebab brick pada percobaan lama.

## Penelusuran entry yang dilanjutkan

Call sebelum default LinuxLoader diikat ke producer protokol PIL:

| Bagian | Bukti pada PE yang dipin |
|---|---|
| GUID bersama | `1f4f1da3-4d8d-4894-ba2a-13d3207f9739` |
| QcomBds | GUID RVA `0x1D288`; call method `+0x08` pada `0x4F4C` |
| Argumen | UTF-16 `ABL`, QcomBds RVA `0x17600` |
| PILDxe | GUID RVA `0x170C8`; interface `0x171B8`, revision `0x10005` |
| Instalasi interface | PILDxe `0x1748`, Boot Services `+0x148` |
| Target method | `0x1790`, call helper `0x1FC0` pada `0x1798` |

Hash PILDxe:
`a9a04094e1685e5cbd06a2fe287da560410bd93852096be12d4d49c7f2ba82b6`.
QcomBds sama dengan basis [ENTRY_FINDINGS.md](ENTRY_FINDINGS.md). Ini
memperjelas jalur pemuatan ABL; **tidak menemukan launcher Ebl baru**.
JSON/disassembly: `evidence/annibale_2026_11_07/pil_binding.*`;
reproduksi melalui `src/trace_ebl_entry.py`.

## Reproduksi dan fastboot

```bash
python3 annibale/src/patch.py --check
python3 -m pip install -r annibale/src/requirements.txt
python3 annibale/src/verify_signature.py --check
```

Hilangkan `--check` atau berikan output baru menurut `annibale/notes.txt`
untuk membangun ulang. Paket annibale tidak memerlukan ZIP masukan karena
ABL default disertakan; verifikasi seluruh penelitian tetap mengikuti
[RECOVERY.md](RECOVERY.md).

`notes.txt` memuat pemeriksaan product/slot, contoh backup, sintaks menulis
satu slot dan pemulihan stock. Command kandidat merupakan referensi penelitian,
bukan langkah siap dipakai pada retail ketika signature masih invalid.
Tidak ada flash, reboot, relock atau perubahan HP pada checkpoint ini.
