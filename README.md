# 🛡️ Bot Telegram — CrowdStrike Falcon On-Demand Scan

Bot Telegram untuk memicu, memantau, dan membatalkan **CrowdStrike Falcon On-Demand Scan (ODS)** langsung dari chat — tanpa perlu membuka Falcon Console setiap saat.

Dibangun dengan [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot) dan CrowdStrike Falcon REST API.

---

## ✨ Fitur

| Perintah | Fungsi |
|---|---|
| `/start` | Salam pembuka dan arahan singkat |
| `/help` | Menampilkan daftar perintah beserta contoh format |
| `/scan <HOST_ID atau HOSTNAME> [DRIVE...] [--duration JAM]` | Memicu On-Demand Scan pada satu host |
| `/status <SCAN_ID>` | Memeriksa status scan secara manual |
| `/cancel <SCAN_ID>` | Membatalkan scan yang sedang berjalan/pending |

**Fitur tambahan:**
- 🔎 Menerima **Host ID (AID)** maupun **hostname** — bot otomatis mencari AID dari hostname.
- 🔔 **Notifikasi otomatis**: setelah scan dipicu, bot memantau status di latar belakang dan mengirim pesan begitu scan `completed`, `cancelled`, atau `error`.
- 🔐 **Pembatasan akses** berbasis Chat ID (`ALLOWED_CHAT_IDS`) — mendukung lebih dari satu admin.
- ⚡ **Caching token** OAuth CrowdStrike untuk mengurangi pemanggilan API yang tidak perlu.

---

## 📦 Prasyarat

- Python **3.10** atau lebih baru
- Akun Telegram (untuk membuat bot via [@BotFather](https://t.me/BotFather))
- Akses ke **Falcon Console** dengan hak membuat API Client
- API Client CrowdStrike dengan scope minimal:
  - `Hosts` → **Read**
  - `On-Demand Scans (ODS)` → **Read** & **Write**

---

## 🚀 Instalasi

1. **Clone repository ini**
   ```bash
   git clone https://github.com/<username>/<nama-repo>.git
   cd <nama-repo>
   ```

2. **Buat virtual environment**
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Mac/Linux
   source .venv/bin/activate
   ```

3. **Install dependency**
   ```bash
   pip install "python-telegram-bot[job-queue]" python-dotenv requests
   ```

4. **Salin file konfigurasi**
   ```bash
   cp .env.example .env
   ```
   Lalu isi seluruh nilai pada `.env` (lihat bagian [Konfigurasi](#-konfigurasi) di bawah).

5. **Jalankan bot**
   ```bash
   python crowdstrike_bot.py
   ```
   Jika berhasil, akan muncul log:
   ```
   Bot Telegram CrowdStrike (Host ID / Hostname + Status + Auto-Notify + Cancel) sedang berjalan...
   ```

---

## ⚙️ Konfigurasi

Seluruh kredensial dan pengaturan disimpan di file `.env` (**jangan pernah di-commit ke git** — lihat `.gitignore`).

| Variabel | Keterangan |
|---|---|
| `TELEGRAM_TOKEN` | Token bot, didapat dari [@BotFather](https://t.me/BotFather) |
| `ALLOWED_CHAT_IDS` | Daftar Chat ID yang diizinkan mengakses bot, dipisah koma. Contoh: `123456789,987654321` |
| `FALCON_CLIENT_ID` | Client ID dari Falcon API Client |
| `FALCON_SECRET` | Client Secret dari Falcon API Client (hanya tampil sekali saat dibuat) |
| `FALCON_BASE_URL` | Alamat API sesuai region cloud (lihat tabel di bawah) |

**Cara mendapatkan Chat ID:**
1. Kirim pesan apa saja ke bot Anda di Telegram.
2. Buka: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Cari nilai `"chat":{"id": ... }` pada respons JSON.

**Region cloud CrowdStrike (`FALCON_BASE_URL`):**

| Region | URL |
|---|---|
| US-1 | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |
| US-GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |

Contoh isi `.env` lengkap:
```env
TELEGRAM_TOKEN=123456789:ABCDefGhIJKlmNoPQRstuVWXyz
ALLOWED_CHAT_IDS=123456789,987654321
FALCON_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
FALCON_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
FALCON_BASE_URL=https://api.crowdstrike.com
```

---

## 💬 Contoh Penggunaan

```
/scan HOST01 C:\
/scan HOST01 C:\ D:\
/scan 00a0a255908348d7831a3907f9de3428 C:\
/scan HOST01 C:\ --duration 8

/status 8e76ab6315c5448e89d33b031e6a3c9c

/cancel 8e76ab6315c5448e89d33b031e6a3c9c
```

- Argumen pertama pada `/scan` bisa berupa **Host ID (AID)** atau **hostname** — bot mencari otomatis.
- Jika drive tidak dituliskan, default adalah `C:\`.
- Flag `--duration` opsional, membatasi durasi maksimum scan (0–24 jam).

---

## 🖥️ Menjalankan di Server (Produksi)

Untuk penggunaan operasional 24/7, disarankan menjalankan bot sebagai **service** (bukan hanya lewat terminal manual), misalnya:

- **Windows Server** → gunakan [NSSM](https://nssm.cc/) untuk mendaftarkan bot sebagai Windows Service (auto-start & auto-restart).
- **Linux** → gunakan `systemd` unit atau `supervisor`.

> 📄 Panduan lengkap deployment ke Windows Server tersedia terpisah di dokumentasi internal (`Juknis_Deployment_Server.docx`).

---

## 🐛 Troubleshooting

| Gejala | Kemungkinan Penyebab | Solusi |
|---|---|---|
| `ModuleNotFoundError: No module named 'telegram'` | Interpreter/environment salah, dependency belum terinstall di situ | Aktifkan venv yang benar, install ulang dependency |
| `[CONFIG ERROR] Variabel belum diisi di .env` | Nama variabel salah ketik atau nilai kosong | Cocokkan dengan `.env.example`, lengkapi semua nilai |
| `401 Unauthorized` dari CrowdStrike | Scope API Client kurang, region salah, atau kredensial salah/dicabut | Cek scope (`Hosts: Read`, `ODS: Read/Write`) dan `FALCON_BASE_URL` |
| `PTBUserWarning: No JobQueue set up` | Package `python-telegram-bot` terinstall tanpa extra `[job-queue]` | `pip install "python-telegram-bot[job-queue]"` |
| `⛔ Akses ditolak!` | Chat ID pengirim belum ada di `ALLOWED_CHAT_IDS` | Tambahkan Chat ID ke `.env`, restart bot |

---

## 📁 Struktur Proyek

```
.
├── crowdstrike_bot.py   # Script utama bot
├── .env.example          # Contoh format konfigurasi (aman di-commit)
├── .env                   # Kredensial asli (JANGAN di-commit)
├── .gitignore
└── README.md
```

---

## 🔒 Keamanan

- **Jangan pernah** commit file `.env` ke repository — pastikan `.gitignore` sudah aktif.
- Batasi `ALLOWED_CHAT_IDS` hanya untuk pengguna yang benar-benar berwenang.
- Gunakan prinsip *least privilege* saat menentukan scope API Client CrowdStrike.
- Segera revoke & buat ulang `FALCON_SECRET` apabila dicurigai bocor.
- Untuk lingkungan produksi, pertimbangkan solusi *secrets management* (Vault, Key Vault, dsb) sebagai pengganti `.env` polos.

---

## 📄 Lisensi

Proyek internal — sesuaikan dengan kebijakan lisensi organisasi Anda.
