# Ebl lebih dulu: program riset, bukan image partisi

Program baru `ebl_first_stub.bin` berukuran **72 byte**, terdiri dari 16
instruksi ARM64 dan literal UTF-16 `Ebl`. `ebl_first.S` adalah listing untuk
review; generator byte yang menjadi acuan ialah `src/plan_ebl_first.py`.
Jangan menganggap listing itu resep build EFI lengkap atau memakai `.bin`
ini sebagai image fastboot.

`hook-plan.json` mengikat rencana pada hash QcomBds tertentu. Usulannya:
call pada RVA `0x5254` dialihkan ke stub pada RVA `0x1C900`, memakai helper
native `0x7D2C` untuk menjalankan Ebl dalam Main FV, lalu LinuxLoader dalam
ABL FV jika Ebl kembali. Jalur charger dan persiapan ABL sebelum call tersebut
tetap berjalan. Tidak ada file UEFI atau ABL baru yang dibuat oleh generator.

Delapan kasus emulasi menguji byte ARM64, namespace, argumen, stack, register
dan status return. **Helper UEFI dimock.** Ini bukan bukti Ebl, display,
keyboard/serial, USB atau SuperFastboot berjalan di HP. Area padding kandidat
juga belum dibuktikan bebas dari seluruh referensi runtime.

Penerapan hook membutuhkan perubahan UEFI yang diterima autentikasi atau
jalur tulis RAM yang sudah tersedia sebelum dispatch. Keduanya belum terbukti.
ABL hasil repack v6 pada folder induk tetap sama dan tidak mengandung hook ini.

Reproduksi dari root repo, setelah memasang requirements.txt:

```bash
.venv/bin/python src/plan_ebl_first.py /path/to/gpt.zip --out annibale/research --emulate
.venv/bin/python src/analyze_logo_donor.py /path/to/logo.zip --firmware /path/to/gpt.zip --out generated/logo-comparison --cert-out annibale/research/certs
```

Dalam `certs/` tersedia sertifikat publik leaf/intermediate/root ABL asli,
blok chain 3.360 byte beserta padding aslinya, dan blok signature asli 104 byte,
sesuai permintaan pengguna. Semua diekstrak tanpa diubah. **Tidak ada private
key** dan tidak ada signature baru untuk payload yang diubah.

Kandidat ABL v6 sudah mempertahankan blok signature/sertifikat ini secara
identik, tetapi signature image tetap invalid setelah payload/digest berubah.
Contoh logo MediaTek menggunakan tambahan context-[0] override hash; itu
bukan mekanisme yang telah ditemukan pada Qualcomm ini.

Baca `EBL_FIRST_FINDINGS.md` di root repo untuk alamat lengkap, perbandingan
Fenrir, bukti dan batas pengujian. File logo mentah serta screenshot pengguna
tidak dipublikasikan dalam repo.
