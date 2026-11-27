# Panel ACS

Monitoring ONT dari **GenieACS** untuk ISP/RT-RW Net: redaman (RX) dengan history grafik, status online, WiFi, perangkat terhubung, dan nama pelanggan. Add-on untuk [ACS NETMAP Panel](https://github.com/suwazed-cmyk/acs-netmap-panel).

Versi 3 ditulis ulang dengan **Node.js** (tanpa PHP, tanpa dependensi npm) dan desain baru yang seragam dengan panel utama.

## Fitur
- **Dashboard**: total/online/offline, redaman buruk, ONT yang perlu perhatian, redaman memburuk 24 jam, status per router, kualitas redaman, merek ONT.
- **ONT**: cari (nama, label, SN, PPPoE, IP, SSID), saring status/redaman/router, urutkan kolom, unduh CSV.
- **Detail ONT**: redaman, suhu, klien WiFi, history redaman (24 jam–90 hari), WiFi (ubah SSID/password), koneksi WAN, perangkat terhubung, reboot, baca ulang.
- **Web ONT** (tombol di detail ONT): buka web ONT lewat IP VPS tanpa VPN, memakai pintu web ONT panel utama (v2.17.0 ke atas). Berlaku 1 jam sejak terakhir dipakai, beberapa ONT bisa dibuka bersamaan.
- **Router otomatis**: ONT dikelompokkan per router panel utama berdasarkan **IP virtual** (IP TR-069 ONT), tanpa tag router.
- **Nama pelanggan & label** disimpan sebagai tag GenieACS: `nama:Budi_Santoso` untuk nama, tag lain sebagai label bebas (ODP, paket, VIP, dll). Tag versi lama (tag ke-2 = nama) tetap terbaca.
- **History redaman**: dicatat tiap 15 menit oleh aplikasi sendiri (tidak perlu cron/timer), mentah 7 hari lalu diringkas per jam, disimpan 14–730 hari. Provision `panel-acs-rx` membuat GenieACS membaca ulang RX setiap inform berkala.
- **Faults** GenieACS: lihat dan hapus.

## Pemasangan
Panel utama → **Add-on → Panel ACS → Install**. Panel memasang Node.js 22 khusus add-on bila Node di VPS lebih lama dari 22.13 (Node milik GenieACS tidak diubah), lalu menjalankan layanan `addon-panel-acs`.

Pembaruan dari versi PHP: klik **Perbarui**. Database `data/panel-acs.db` dipakai apa adanya (history, lokasi, pengaturan tidak hilang). Password admin lama tetap berlaku dan diganti ke format baru saat login pertama.

### Mandiri (tanpa panel utama)
```
node --disable-warning=ExperimentalWarning server.js   # butuh Node.js 22.13+
```
Variabel: `PORT` (bawaan 8091), `HOST` (bawaan 127.0.0.1), `DATA_DIR` (bawaan `./data`). Buka di browser, buat akun admin, lalu isi alamat NBI GenieACS di Pengaturan (bawaan `http://127.0.0.1:7557`).

## Data
`data/` (tidak masuk repo): `panel-acs.db` (SQLite), `panel-link.json` (alamat + kunci panel utama, ditulis panel utama).

## Lisensi
MIT. Chart.js 4.4.1 (MIT) disertakan di `assets/`.
