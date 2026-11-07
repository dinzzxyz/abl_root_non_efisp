# Pemetaan Boot State CN dan diagnostik OEM

Tanggal: 6 November 2026. **Status: kandidat statis, belum diuji di HP.**

Update 7 November: kandidat CN yang dipetakan di sini kini direpack sebagai
ELF riset terpisah dalam annibale, atas permintaan pengguna. Alat struktural
di dokumen ini tetap hanya menghitung kandidat. Lihat ANNIBALE_BUILD.md untuk
script/file baru dan bukti signature OEM kandidat invalid; belum ada uji boot.

Temuan ini melengkapi BOOT_METADATA_FINDINGS.md. Hash prefix firmware HP
cocok dengan image CN; karena itu pemetaan CN lebih relevan untuk perangkat
pengguna daripada menyalin offset engineering. Hasil berikut belum menyediakan
entry GBL, container ABL yang diterima firmware, atau SuperFastboot yang bekerja.

## 1. Identitas dan ruang alamat

Semua offset patch pada dokumen ini berada dalam **PE LinuxLoader hasil
ekstraksi**, bukan dalam ELF ABL, partisi, atau buffer LZMA. Pada dua PE ini
image base nol dan offset raw section yang dibahas sama secara numerik dengan
RVA. JSON tetap menyimpan keduanya secara terpisah.

| Basis | SHA-256 PE asli | Ukuran |
|---|---|---|
| CN | `75e9d6122d708948c6a5f0b9774a061aa25ebb7a279fbe020ad8835400b065d2` | 1.179.648 byte |
| Engineering | `6270557b012660bd4d876a68368321d17a08efdb2e5a7d931a9f99346da736c7` | 1.183.744 byte |

`src/map_bootstate.py` menolak hash lain sebelum mengeluarkan resep kandidat.
Tidak ada opsi menulis file firmware atau mengakses perangkat. Perubahan
hanya dihitung dalam memori untuk kalibrasi dan pencatatan hash.

## 2. Mengapa patcher upstream melewatkan kedua ABL

Pada source acuan yang dipin, `core.c` mengharapkan bentuk:

```text
CBZ; MOV W8,#1; B +24; LDR X8,[stack]; LDRB W8,[X8]; CMP; CSET; LSL
```

Kedua ABL yang diberikan memakai bentuk berbeda:

```text
TST W8,#0xff; B.EQ; MOV W8,#1; B +20; LDRB W8,[X25/X26]; CMP; CSET; LSL
```

Susunan cabang serta akses buffernya berbeda. Mask byte upstream
menghasilkan **nol hit** pada keduanya. Pemindai baru mendekode peran instruksi
dan memastikan tujuan kedua cabangnya benar; ditemukan **satu blok** per PE.

| Bagian | CN RVA / offset PE | Engineering RVA / offset PE |
|---|---|---|
| Membaca nilai stack | `0x3B768` | `0x3BAA0` |
| TST awal blok | `0x3B76C` | `0x3BAA4` |
| MOV nilai state | `0x3B774` | `0x3BAAC` |
| LDRB alternatif | `0x3B77C`, `[X26]` | `0x3BAB4`, `[X25]` |
| Merge cabang | `0x3B78C` | `0x3BAC4` |
| Menyimpan state | `0x3B790`, `[X19,#0x438]` | `0x3BAC8`, `[X19,#0x438]` |
| Reload stack untuk byte lokal | `0x3B79C` | `0x3BAD4` |
| STRB byte lokal | `0x3B7B8`, `[SP,#0x40]` | `0x3BAEC`, `[SP,#0x40]` |

Arti aritmetika blok sebelum patch dapat ditulis sebagai:

```text
state = (stack_0x30 & 0xff) ? 1 : ((buffer_byte != 0) << 1)
```

Itu menjelaskan pemilihan angka 1 versus 0/2. Memberi nama state mengikuti
konvensi VerifiedBoot tidak membuktikan seluruh pemeriksaan keamanan atau
properti setelah boot mengikuti nilai tersebut.

## 3. Getter dan struktur DeviceInfo

| Bukti | CN | Engineering |
|---|---|---|
| Callsite awal fungsi yang dianalisis | `0x3A398` → `0x24874` | `0x3A72C` → `0x244B4` |
| Salinan hasil getter | `W23 = W0` | `W24 = W0` |
| Byte global yang dibaca getter | RVA `0x10992D` | RVA `0x10A945` |
| Basis struktur saat inisialisasi magic | RVA `0x109920` | RVA `0x10A938` |
| Selisih field terhadap basis | 13 byte | 13 byte |

Rutin inisialisasi memberikan basis struktur yang sama kepada pembandingan
magic `ANDROID-BOOT!` sepanjang 13 byte. Getter mengembalikan byte tepat
sesudah magic. Source DeviceInfo pembanding mendefinisikan `is_unlocked`
pada posisi itu dan `IsUnlocked()` mengembalikan field tersebut.

Karena itu identifikasi **IsUnlocked / DeviceInfo.is_unlocked** merupakan
inferensi yang didukung struktur, akses biner, dan source. Ini bukan simbol
OEM yang ditemukan dalam binary stripped. Konfigurasi source lain, misalnya
`AUTO_VIRT_ABL`, dapat menambah field sebelum `is_unlocked`; layout itu tidak
boleh diasumsikan sama pada perangkat lain. Byte global di file awal bernilai
nol dan bukan pembacaan status lock runtime perangkat.

Source pembanding dipin pada `REG-Linux/edk2-freeabl` commit
`4cd7fb389e22d7a3761308006fc6d79410be9ddf`:

- [DeviceInfo.h](https://github.com/REG-Linux/edk2-freeabl/blob/4cd7fb389e22d7a3761308006fc6d79410be9ddf/QcomModulePkg/Include/Library/DeviceInfo.h)
- [DeviceInfo.c](https://github.com/REG-Linux/edk2-freeabl/blob/4cd7fb389e22d7a3761308006fc6d79410be9ddf/QcomModulePkg/Library/BootLib/DeviceInfo.c)

Git blob hash kedua sumber juga dicatat pada summary bukti. Source ini dipakai
untuk pembanding semantik, bukan klaim bahwa firmware Xiaomi dibangun dari
commit tersebut.

## 4. Empat rentang kandidat pada CN

| Offset PE / RVA CN | Sebelum | Kandidat sesudah | Efek instruksi lokal |
|---|---|---|---|
| `0x3A398` | `37 a9 ff 97` | `20 00 80 52` | `BL 0x24874` → `MOV W0,#1` |
| `0x3B774` | `28 00 80 52` | `08 00 80 52` | `MOV W8,#1` → `MOV W8,#0` |
| `0x3B7B8` | `ea 03 01 39` | `ff 03 01 39` | `STRB W10` → `STRB WZR` pada `[SP,#0x40]` |
| `0x45674` | `e9 02 00 b0 29 b1 23 91` | `69 02 00 90 29 25 39 91` | Pasangan alamat `unlocked` → `locked` |

Total **10 byte berubah pada empat rentang**, dengan panjang PE tetap.
Hash kandidat CN yang dihitung di memori:

`9b55fb1ee70b3519a947160033d4d9929edf6d045d6dbc0c4e39b23fdf8fffc5`

String CN: `unlocked` di RVA `0xA28EC`, `locked` di `0x91E49`. Pasangan alamat
key `androidboot.vbmeta.device_state` ada di RVA `0x45684`. Encoder ADRP/ADD
menghitung kembali immediate menurut PC pasangan yang diganti; menyalin
instruksi ADRP dari lokasi lain dapat salah bila melintasi batas page.

Metode yang sama pada engineering menemukan empat rentang lama di LAPORAN.md.
Hasilnya **identik seluruh byte** dengan `result/boot.efi`, SHA-256
`d7456c0e5d6d102cad963ea9c27f4b5fc3c999d6ebce5ade058efd52c352ef83`,
dengan 9 byte berubah. Ini merupakan kalibrasi terhadap hasil yang sudah ada,
bukan bukti bahwa hasil lama atau kandidat CN berhasil boot.

Batas analisis dataflow: reload `[SP,#0x30]` dan STRB berikutnya berada dalam
fragmen lurus tanpa register sumber ditimpa. Fungsi besarnya mempunyai beberapa
definisi stack pada cabang berbeda. Alat belum membuktikan provenance stack
secara penuh untuk seluruh CFG, alias memori dan helper panggilan. Kemiripan
keempat lokasi dengan engineering belum menghapus kebutuhan pemeriksaan itu.

## 5. Perintah diagnostik OEM kini memiliki pemetaan handler

Penelusuran CN menemukan loop registrasi pada RVA `0x7E248–0x7E26C`:
basis `0xF1990`, load pasangan pada `+0x10`, limit index `0x220`, stride
16 byte. Hasilnya **34 entry** mulai RVA `0xF19A0`; helper registrasi dipanggil
di `0x7E264` menuju `0x7E6C0`. Tiga entry yang ditelusuri:

| Command di tabel | Pointer pair RVA | String RVA | Handler RVA | Bukti tambahan |
|---|---|---|---|---|
| `oem lkmsg` | `0xF1AE0` | `0x95B93` | `0x829FC` | Merujuk nama `md_kmsg` |
| `oem lpmsg` | `0xF1AF0` | `0x9E0B7` | `0x82A5C` | Merujuk nama `md_pmsg` |
| `oem uefilog` | `0xF1B00` | `0x8C9FD` | `0x82ABC` | LocateProtocol dan cabang `save` |

Handler uefilog merujuk GUID `7dc6c901-8f10-44b5-b2c5-be5b168595a3`, byte
`01c9c67d108fb544b2c5be5b168595a3` pada RVA `0xE9F30`. Urutan pemanggilan
LocateProtocol menggunakan BootServices offset `0x140`. Identitas/provider
protokol dan pemasangannya pada runtime belum dibuktikan hanya dari GUID.

Pada RVA `0x82B08` handler menyiapkan string `save`, membandingkannya melalui
helper `0x86278`, lalu CBZ di `0x82B14` menuju `0x82BB8`. Cabang itu memanggil
method protokol offset `0x10`; jalur lainnya menggunakan method offset `0x08`.
Diagnostik kegagalan secara eksplisit menyebut `save logfs files failed`.
Dengan demikian, handler mempunyai cabang yang mungkin menyimpan log;
seluruh perintah belum diaudit sebagai hanya membaca.

Tidak ada perintah OEM dijalankan dalam penelitian ini. Belum disediakan
resep pengambilan log melalui USB: format transfer host dan efek helper masih
perlu ditelusuri. Ketiga handler ini adalah kandidat diagnostik, bukan jalur
untuk meluncurkan EFI kustom.

## 6. Mengulang dan memeriksa bukti

Setelah memasang requirements.txt dan checkout upstream menurut RECOVERY.md:

```bash
.venv/bin/python src/map_bootstate.py /path/to/gpt.zip --out generated/bootstate
.venv/bin/python src/trace_diagnostics.py /path/to/gpt.zip --out generated/bootstate
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python src/verify_research.py /path/to/gpt.zip --upstream ../gbl_root_canoe --log generated/verification.txt
```

Keluaran berisi JSON dan potongan disassembly dengan byte asli, offset file,
RVA, dan interpretasi. Tidak ada keluaran PE, ELF, atau image partisi dari dua
alat baru. Bukti checkpoint ada di `evidence/bootstate_2026_11_06/`.

Verifikasi mencakup kalibrasi engineering, anchor unik kedua build, penolakan
mutasi satu byte, dan tabel diagnostik. Pengujian sintetis sengaja mengubah
tujuan branch dan menimpa register sink agar kemiripan bentuk tidak otomatis
diterima. Ada pula pengujian ADRP/ADD yang melintasi batas page.

## 7. Jalur port yang masih terbuka

Titik dispatch QcomBds, GUID ABL FV dan pengikatan SHA-384 dalam container
tetap berlaku seperti RESEARCH_CONTINUED.md. Perubahan PE di atas belum
menambahkan pemanggil BDS, belum memperbaiki autentikasi container, dan belum
memberi storage default menu pengganti ESP.

Source publik [FreeABL](https://github.com/REG-Linux/FreeABL/tree/63fd0a0544ef167fcdb26fade67a08e2a601b3a1)
juga diperiksa. README pada commit itu mencantumkan SM8750 sebagai **build
only**, tanpa validasi perangkat; build.sh memakai wrapper ELF32 di
`0x9FA00000` dan qtestsign v7. Keberadaan target build atau test signature
tidak membuktikan Xiaomi retail ini menerima image yang diubah. Source ini
dapat membantu pembandingan ABI/DeviceInfo, tetapi belum menyelesaikan entry.

Langkah berikut yang bernilai adalah menelusuri provider/logging protokol dan
jalur autentikasi PIL pada CN yang sudah cocok hash. Bukti eksekusi EFI serta
alasan penerimaan/penolakan image tetap diperlukan sebelum uji port fisik.
Modul spoofing Android tidak perlu dicopot untuk mengulang analisis file ini;
properti boot yang dimodifikasinya tetap tidak dijadikan bukti lock nyata.
