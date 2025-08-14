## VPnBot — Telegram Bot untuk 3x-ui (vmess/vless/trojan)

Bot Telegram sederhana berbasis grammY untuk mengelola client di panel 3x-ui (menambah, menghapus, memperpanjang), sekaligus sistem saldo/topup ringan dan log aktivitas.

### Fitur
- **Kelola client**: tambah client vmess/vless/trojan, toggle aktif/nonaktif, perpanjang masa aktif.
- **Saldo & Topup**: saldo per pengguna, topup dengan kode unik dan verifikasi admin.
- **Menu Admin**: verifikasi topup, tambah saldo manual, hapus client, lihat log, kelola daftar BUG host (SNI) untuk trojan.

### Prasyarat
- Node.js >= 18
- Token bot Telegram (BotFather)
- Akses ke panel 3x-ui (URL, username, password)

### Konfigurasi Environment
Buat file `.env` berdasarkan `.env.example`:

```
BOT_TOKEN=123456789:ABCDEF...
XUI_BASE_URL=https://xui.example.com
XUI_USERNAME=admin
XUI_PASSWORD=changeme
PUBLIC_HOST=vpn.example.com
ADMIN_TELEGRAM_IDS=111111111,222222222
ALLOW_ADD_USER_IDS=
```

Penjelasan variabel:
- **BOT_TOKEN**: token bot Telegram.
- **XUI_BASE_URL**: URL dasar panel 3x-ui (contoh `https://panel.example.com`).
- **XUI_USERNAME/XUI_PASSWORD**: kredensial login panel 3x-ui.
- **PUBLIC_HOST**: domain/IP yang ditunjukkan pada link konfigurasi ke klien.
- **ADMIN_TELEGRAM_IDS**: daftar Telegram user ID admin, dipisahkan koma.
- **ALLOW_ADD_USER_IDS**: opsional; biarkan kosong. (Hanya admin yang dapat bypass saldo.)

Jika variabel wajib kosong, aplikasi akan berhenti dengan pesan kesalahan.

### Menjalankan Lokal
1) Install dependensi:
```
npm install
```
2) Jalankan bot:
```
npm start
```

### Menjalankan dengan Docker
Build image:
```
docker build -t vpnbot .
```
Jalankan container (persistensi folder `data/`):
```
docker run -d --name vpnbot --env-file .env -v %cd%\data:/app/data vpnbot
```
Catatan: perintah di atas untuk Windows PowerShell. Di Linux/macOS gunakan `-v "$(pwd)/data:/app/data"`.

### Struktur Data
Folder `data/` berisi penyimpanan sederhana:
- `balances.json`: saldo per user Telegram ID.
- `topups.json`: daftar permintaan topup, status, TTL.
- `logs.jsonl`: catatan aktivitas (JSON Lines).
- `bugs.json`: daftar BUG host (SNI) untuk koneksi trojan.

### Perintah Bot (Ringkas)
- `/start` — menu awal dan tombol navigasi.
- `/saldo` — cek saldo.
- `/clients` — daftar client Anda; admin dapat melihat semua.
- `/topup <nominal>` — buat permintaan topup (otomatis tambah kode unik 1..100).
- `/ref <ID_TOPUP> <KODE_REF>` — kirim referensi/topup agar diverifikasi admin.
- `/admin` — menu admin (khusus admin).
- Admin: `/topup <telegram_id> <jumlah>` untuk menambah saldo manual.

### Troubleshooting
- "Missing required env vars" — pastikan seluruh variabel di `.env` terisi.
- Pastikan `PUBLIC_HOST` sesuai domain/IP yang bisa diakses klien.

### Lisensi
MIT


