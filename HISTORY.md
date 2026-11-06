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
