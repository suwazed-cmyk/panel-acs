# Panel ACS

Monitoring ONT dari **GenieACS**: daftar dan detail ONT, **history redaman (RX)** dengan grafik, ubah WiFi, reboot, refresh, tag pelanggan, faults, dan peta lokasi ONT.

Dirancang sebagai **add-on** untuk [ACS NETMAP Panel](https://github.com/suwazed-cmyk/acs-netmap-panel), tetapi juga bisa dipasang mandiri.

## Fitur

- **Dashboard**: jumlah ONT online/offline, sebaran kualitas RX, status per router, ONT yang perlu perhatian, **redaman memburuk dalam 24 jam**.
- **ONT Devices**: daftar dengan filter router, status, RX, model, dan kolom **Δ 24 jam** (perubahan redaman).
- **Detail ONT**: info lengkap, **grafik history redaman** 24 jam / 7 hari / 30 hari / 90 hari (dengan garis ambang Excellent/Fair), ubah SSID & password WiFi, reboot, refresh, area dan nama pelanggan.
- **Router otomatis**: ONT dikelompokkan per router panel utama berdasarkan **IP virtual**, tanpa mengisi tag atau prefix manual.
- **Faults** dan **Mapping** (peta lokasi ONT dengan OpenStreetMap).
- Data tersimpan di **SQLite** (`data/panel-acs.db`), tanpa server database.

## Pemasangan sebagai add-on (disarankan)

Di panel utama: **Add-on → Panel ACS → Install**. Panel utama akan:

1. memasang PHP (`php-cli`, `php-sqlite3`, `php-curl`, `php-mbstring`) jika belum ada,
2. mengunduh repo ini ke `/opt/addons/panel-acs`,
3. menyiapkan database dan penghubung ke panel utama (`data/panel-link.json`),
4. menjalankan layanan `addon-panel-acs` (127.0.0.1:8091) dan timer pencatat redaman tiap 15 menit,
5. membuka Panel ACS di alamat panel utama, misalnya `https://domainanda.com/acs/`.

Saat pertama dibuka, Panel ACS meminta Anda **membuat akun admin**. Tidak ada password bawaan.

NBI GenieACS dibaca dari dalam VPS (`http://127.0.0.1:7557`), jadi port 7557 **tidak perlu** dan **tidak boleh** dibuka ke internet.

## History redaman

- `bin/collect.php` membaca RX semua ONT dari GenieACS tiap 15 menit dan menyimpan titik baru (hanya bila GenieACS benar-benar membaca ulang nilainya).
- Data 7 hari terakhir disimpan detail; data lebih lama diringkas per jam dan disimpan sesuai pengaturan (bawaan 90 hari).
- Parameter GenieACS bawaan biasanya membaca RX **sekali sehari**. Supaya grafik lebih rapat, buka **Settings → History Redaman → Pasang provision RX**. Panel menambah provision `panel-acs-rx` dan preset-nya agar RX dibaca ulang setiap Inform berkala. Provision lain tidak diubah, dan bisa dihapus kapan saja dari tempat yang sama.

## Tag GenieACS

| Tag | Arti |
|---|---|
| Tag 1 | Area / kelompok (opsional), misalnya ODP atau dusun |
| Tag 2 | Nama pelanggan |

Jika ONT hanya punya satu tag, tag itu dianggap nama pelanggan. Router **tidak** diambil dari tag, tetapi dari panel utama.

## Pemasangan mandiri (tanpa panel utama)

1. Salin isi repo ke server PHP 7.4+ dengan ekstensi `pdo_sqlite` dan `curl`.
2. Folder `data/` harus bisa ditulis.
3. Buka alamatnya, buat akun admin, lalu isi URL NBI di **Settings**.
4. Jalankan pencatat redaman berkala, misalnya cron tiap 15 menit: `php /path/panel-acs/bin/collect.php`

Tanpa panel utama, ONT dikelompokkan memakai tag 1 (area). NBI harus bisa dijangkau dari server itu dengan aman.

## Data

Folder `data/` berisi database, pengaturan, dan kunci penghubung panel. Folder ini **tidak** ikut repo (`.gitignore`). Backup cukup salin `data/panel-acs.db`.

Data versi lama (`settings.json`, `locations.json`) diimpor otomatis saat pertama dijalankan; berkas lama disimpan sebagai `.bak`.
