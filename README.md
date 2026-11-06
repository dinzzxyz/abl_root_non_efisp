# Penelusuran SuperFastboot SM8750 / annibale

Tanggal: 6 November 2026. Status: **analisis statis dan rekonstruksi patch**.
Paket ini berisi source alat analisis, bukti, dan catatan pengembangan.
Belum merupakan port SuperFastboot yang dapat di-flash.

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

Baca [LAPORAN.md](LAPORAN.md) untuk offset, call graph, batas bukti,
dan tahap pengembangan berikutnya.

## Isi source

| Berkas | Fungsi |
|---|---|
| `src/fwlib.py` | Ekstraksi PE dari LZMA, pembacaan FDT dan nama FFS |
| `src/analyze.py` | Mengulang penelusuran secara offline dari `gpt.zip` |
| `src/recover_patch.py` | Rekonstruksi persis hasil patch lama dengan validasi hash |
| `evidence/` | Hasil analisis, hash, konfigurasi terpilih, dan disassembly |
| `VALIDATION.txt` | Hasil verifikasi terhadap berkas masukan yang diberikan |
| `UPSTREAM.json` | Repo dan commit acuan yang diperiksa |

Tidak ada skrip dari ZIP masukan yang dieksekusi. Alat analisis tidak
menjalankan `fastboot`, `adb`, `su`, atau membuka perangkat blok.

## Menjalankan ulang

Gunakan Python 3.10+ pada komputer Linux. Tempatkan ZIP masukan asli di luar
repo ini; firmware dan loader OEM tidak disertakan dalam source yang dibagikan.

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

Setelah integrasi GitHub di ChatGPT terhubung dan repo tujuan dipilih,
source dapat disimpan ke branch penelitian beserta riwayat commit.
Belum ada push ke akun pengguna dalam pekerjaan ini.

`history.bundle` dalam paket unduhan memuat snapshot riwayat Git sebelum
pengemasan. Untuk memulihkannya ke folder baru:

```bash
git clone history.bundle recovered-research
```

## Sumber dan lisensi

Source Python baru dalam `src/` menggunakan lisensi MIT, lihat `LICENSE`.
Proyek acuan memiliki lisensi GPL-3.0; source upstream dan firmware OEM
tidak direlisensi oleh paket ini. Catatan analisis merujuk hasil pemeriksaan
terhadap berkas yang diberikan pengguna dan repo upstream.
