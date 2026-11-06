# Penelitian lanjutan — 6 November 2026

Temuan berikut melengkapi [LAPORAN.md](LAPORAN.md). Seluruhnya masih merupakan
analisis statis atas firmware yang diberikan. Jalur eksekusi BDS kustom di HP
belum teruji.

## A. GUID volume ABL cocok dengan argumen QcomBds

Jalur yang sekarang dapat dibuktikan dari kedua arah:

1. QcomBds memiliki konstanta GUID di RVA `0x1D0E8`:
   `046fae99-cf2e-49ed-a6a8-a1488b7e80d3`.
2. Konstanta itu menjadi argumen pemanggilan helper pada RVA `0x5254`.
3. Helper pada `0x7D2C` menyaring device path firmware volume. Cabang
   `0x7E78–0x7E8C` membandingkan GUID volume dengan argumen yang diberikan.
4. Di ABL asli, stream LZMA pada offset file ELF `0x1078` membuka section yang
   memuat FV pada offset hasil dekompresi `0x8`.
5. FV tersebut mempunyai extension header pada offset `0x60` relatif ke FV.
   GUID nama volumenya persis sama: `046fae99-cf2e-49ed-a6a8-a1488b7e80d3`.
6. Di dalamnya ditemukan aplikasi ber-UI-name `LinuxLoader`, FFS GUID
   `f536d559-459f-48fa-8bbc-43b554ecae8d`.

| Lapis | Identitas / alamat |
|---|---|
| ELF ABL | Payload mulai di `0x1000`, ukuran `0x50000` |
| Stream terkompresi | File ELF `0x1078` |
| FV bagian dalam | Offset hasil dekompresi `0x8` |
| FV name GUID | `046fae99-cf2e-49ed-a6a8-a1488b7e80d3` |
| FFS aplikasi | `f536d559-459f-48fa-8bbc-43b554ecae8d`, UI `LinuxLoader` |
| Helper QcomBds | RVA `0x7D2C` |
| Pencarian device/file path | Callsite `0x7EE0` |
| EFI LoadImage | Callsite `0x7F30`, BootServices offset `0xC8` |
| EFI StartImage | Callsite `0x8040`, BootServices offset `0xD0` |

**Implikasi:** mengganti `DefaultBDSBootApp` menjadi nama aplikasi lain tidak
otomatis mengambilnya dari `persist` atau dari main FV. Target nama harus
ditemukan dalam namespace volume yang dipilih, atau jalur dispatch harus
diubah melalui mekanisme yang diterima firmware.

Temuan ini berlaku pada CN dan engineering. Label engineering sendiri belum
memberikan bukti adanya pemanggil BDS tambahan.

## B. Digest payload SHA-384 ditemukan dalam hash segment

ELF ABL kedua ROM mempunyai tiga program header:

| Index | Type | Offset | Ukuran file | p_flags |
|---|---|---|---|---|
| 0 | PT_NULL | `0x0` | `0x94` | `0x07000000` |
| 1 | PT_LOAD | `0x1000` | `0x50000` | `0x00000007` |
| 2 | PT_NULL / hash segment | `0x51000` | `0xF38` | `0x02000000` |

Menghitung SHA-384 atas seluruh segmen PT_LOAD menghasilkan digest yang
ditemukan di offset file `0x51150` pada kedua ABL, masing-masing dengan
nilai berbeda sesuai isi payloadnya.

| Basis | SHA-384 payload PT_LOAD |
|---|---|
| CN | `d308ca5a57d726d224e46c1c8cd2756dd9ac1af3629412457809a004060c24594ff3a4b09303b97eb4e287a96d699c8d` |
| Engineering | `aeda286a5e03cc1321bb111d257d66a6a0d80bc389a08486f9d944310b9ba19538b90b96d1b426b31f2b8985bf34bca0` |

**Yang terbukti:** payload terikat pada digest yang disimpan di hash segment.
**Yang belum terbukti:** jalur penerimaan signature runtime setelah perubahan,
kemampuan menandatangani ulang dengan kunci yang diterima, atau kebijakan
autentikasi khusus pada perangkat pengguna.

Mengganti payload sekaligus memperbarui digest tidak menghasilkan signature
yang sah secara otomatis. Skrip penelitian tidak mengklaim melewati batas ini.

## C. Penyimpanan default menu juga perlu diperhatikan

Source upstream pada commit yang dipin menyimpan dua record, masing-masing
1.024 byte, pada **2.048 byte terakhir ESP**. `SuperFbStore.c`:

- `SfbRankEspEntry`, baris 110–127: nama `efisp` diutamakan, kemudian GPT type
  GUID EFI System Partition menjadi fallback.
- `SfbResolveStore`, baris 290–349: menentukan BlockIo dan offset akhir media.
- `SfbStoreWrite`, baris 441–488: menggunakan WriteBlocks dan FlushBlocks.

Ini tidak memerlukan nama partisi `efisp` secara mutlak, tetapi tetap memerlukan
ESP yang sesuai dan ruang akhir yang benar-benar dialokasikan untuk record.
Asumsi ruang kosong pada perangkat acuan tidak boleh diterapkan ke partisi
SM8750 lain tanpa pemeriksaan layout.

Pada `SfbLaunchDefaultEntry`, boot otomatis hanya dilakukan jika default yang
tersimpan valid. Jika penyimpanan tidak tersedia, kode dapat kembali ke menu.
Jadi tidak adanya ESP dapat memengaruhi persistensi default tanpa membuktikan
bahwa seluruh antarmuka BDS mustahil berjalan.

Untuk tahap diagnostik, mode tanpa penyimpanan persisten merupakan opsi
pengembangan yang perlu dirancang. Belum ada patch atau image SM8750 yang
menerapkan opsi tersebut dalam paket ini.

## D. Inventaris protokol untuk pemeriksaan port

`src/trace_paths.py` membaca deklarasi `[Protocols]` dari LinuxLoader.inf dan
FastbootLib.inf pada source yang dipin, kemudian membandingkan byte GUID
dengan PE firmware SM8750. Hasil lengkap:

- [Tabel protokol](evidence/continued/PROTOCOLS.md).
- [Manifest protokol](evidence/continued/protocol_inventory.json).
- [Container dan namespace](evidence/continued/boot_container_trace.json).

Manifest container juga menyimpan byte instruksi pada callsite yang dibahas,
byte GUID argumen, dan 96 byte awal hash segment. Itu membantu memeriksa
pemetaan pada sesi baru tanpa mengandalkan nama fungsi hasil inferensi.

Inventaris ini belum mencakup seluruh dependensi transitif hasil linking.
Kemunculan GUID dalam modul bisa berasal dari consumer maupun producer;
belum membuktikan protokol terpasang, revision cocok, atau layout method sama.
Binary BDS modul yang diberikan juga berbeda snapshot dari source upstream
yang dipin; kedua kolom pembanding sengaja dicatat terpisah.

USB fastboot, enumerasi storage, tombol dan display masih memerlukan uji
runtime setelah entry EFI berhasil dibuktikan.

## E. Urutan penelitian berikutnya

1. Cocokkan firmware HP yang benar-benar terpasang dengan hash basis.
2. Ambil informasi partisi dan visibilitas runtime EFI memakai collector yang
   hanya membaca. Data ini belum ada pada masukan awal.
3. Dapatkan log PIL/UEFI dari percobaan sebelumnya atau dari boot ABL asli.
   Tentukan apakah file yang ditulis pernah diterima sebagai container ABL.
4. Pecahkan entry dan autentikasi sebelum mengubah media boot entries.
5. Setelah BDS bisa dijalankan, uji protokol satu per satu dan pisahkan hasil
   pada ROM CN dari hasil engineering.

Tidak ada klaim bahwa mengganti nama aplikasi, menambah partisi, atau membuat
container ELF saja sudah menghasilkan port yang bekerja.
