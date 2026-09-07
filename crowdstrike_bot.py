import os
import re
import time
import functools
import requests
import json
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from dotenv import load_dotenv

# === KONFIGURASI UTAMA ===
# Kredensial sekarang dibaca dari file .env (lihat .env.example),
# bukan hardcoded di source code.
load_dotenv()

def _parse_chat_ids(raw: str) -> set:
    """Mengubah string 'id1,id2,id3' dari .env menjadi set integer chat ID."""
    ids = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            print(f"[CONFIG WARNING] ALLOWED_CHAT_IDS mengandung nilai bukan angka, dilewati: '{part}'")
    return ids


TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
# Mendukung banyak Chat ID admin, dipisah koma di .env, contoh:
# ALLOWED_CHAT_IDS=123456789,987654321
ALLOWED_CHAT_IDS = _parse_chat_ids(os.getenv("ALLOWED_CHAT_IDS", ""))
FALCON_CLIENT_ID = os.getenv("FALCON_CLIENT_ID")
FALCON_SECRET = os.getenv("FALCON_SECRET")
FALCON_BASE_URL = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")
# Sesuaikan FALCON_BASE_URL di .env dengan region cloud Anda:
# US-1: https://api.crowdstrike.com
# US-2: https://api.us-2.crowdstrike.com
# EU-1: https://api.eu-1.crowdstrike.com
# US-GOV-1: https://api.laggar.gcw.crowdstrike.com

# Validasi awal supaya error jelas sejak start, bukan crash aneh di tengah jalan
def _validate_config():
    missing = []
    if not TELEGRAM_TOKEN:
        missing.append("TELEGRAM_TOKEN")
    if not ALLOWED_CHAT_IDS:
        missing.append("ALLOWED_CHAT_IDS")
    if not FALCON_CLIENT_ID:
        missing.append("FALCON_CLIENT_ID")
    if not FALCON_SECRET:
        missing.append("FALCON_SECRET")
    if missing:
        raise SystemExit(
            f"[CONFIG ERROR] Variabel berikut belum diisi di .env: {', '.join(missing)}\n"
            f"Salin .env.example menjadi .env lalu isi nilainya."
        )


# Interval polling status scan otomatis (detik)
STATUS_POLL_INTERVAL = 30
# Timeout maksimum polling (detik) - jaga-jaga kalau scan macet / tidak pernah selesai
STATUS_POLL_TIMEOUT = 6 * 60 * 60  # 6 jam


# === CACHE TOKEN CROWDSTRIKE ===
# Menyimpan token di memori supaya tidak selalu request baru ke /oauth2/token
# setiap kali command dipanggil. Token CrowdStrike umumnya valid ~30 menit (1799s),
# kita kasih margin 60 detik sebelum expiry supaya tidak kepakai token yang mepet.
_token_cache = {"access_token": None, "expires_at": 0}


def get_falcon_token(force_refresh: bool = False):
    """Mengambil (atau memakai cache) token akses dari CrowdStrike."""
    now = time.time()
    if not force_refresh and _token_cache["access_token"] and now < _token_cache["expires_at"]:
        return _token_cache["access_token"]

    url = f"{FALCON_BASE_URL}/oauth2/token"
    payload = {'client_id': FALCON_CLIENT_ID, 'client_secret': FALCON_SECRET}

    try:
        response = requests.post(url, data=payload)
        if response.status_code != 201:
            print(f"[DEBUG AUTH ERROR] Gagal Login! Status Code: {response.status_code}")
            return None

        data = response.json()
        access_token = data.get("access_token")
        expires_in = data.get("expires_in", 1799)  # detik, default aman ~30 menit

        _token_cache["access_token"] = access_token
        _token_cache["expires_at"] = now + max(expires_in - 60, 30)  # margin 60 detik

        return access_token
    except Exception as e:
        print(f"[DEBUG AUTH CRITICAL] Error Koneksi: {str(e)}")
        return None


def resolve_host_id(token, host_input):
    """
    Mengembalikan Host ID (AID) yang valid.
    Jika host_input sudah berupa AID (32 karakter hex), langsung dipakai.
    Jika bukan, dianggap sebagai hostname dan dicari AID-nya via Hosts API.
    Return: (host_id, error_message)
    """
    host_input = host_input.strip()

    # Cek apakah input sudah berupa AID (32 karakter hex)
    if re.fullmatch(r"[a-fA-F0-9]{32}", host_input):
        return host_input, None

    # Sanitasi dasar: FQL filter CrowdStrike memakai tanda kutip tunggal sebagai
    # delimiter, jadi kita escape/tolak karakter yang bisa merusak filter.
    if "'" in host_input or '"' in host_input:
        return None, "Nama host tidak boleh mengandung karakter kutip (' atau \")."

    # Kalau bukan AID, cari berdasarkan hostname
    url = f"{FALCON_BASE_URL}/devices/queries/devices/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"filter": f"hostname:'{host_input}'"}

    try:
        response = requests.get(url, headers=headers, params=params)
        print(f"[DEBUG HOST LOOKUP] Status: {response.status_code} | Response: {response.text}")

        if response.status_code != 200:
            return None, f"Gagal query hostname (status {response.status_code})."

        resources = response.json().get("resources", [])

        if not resources:
            return None, f"Hostname `{host_input}` tidak ditemukan di CrowdStrike."
        if len(resources) > 1:
            # resources di sini berisi daftar Host ID (AID), bukan hostname,
            # jadi labelnya diperjelas agar tidak membingungkan.
            return None, (
                f"Ditemukan {len(resources)} host dengan nama serupa. "
                f"Host ID: {', '.join(resources)}. Gunakan salah satu Host ID spesifik."
            )

        return resources[0], None

    except Exception as e:
        return None, f"Error saat mencari hostname: {str(e)}"


def trigger_ods(token, host_ids, target_drives, max_duration=None):
    """
    Memicu On-Demand Scan menggunakan Host ID.
    Return: (sukses: bool, scan_id: str atau None, error_detail: str atau None)
    """
    url = f"{FALCON_BASE_URL}/ods/entities/scans/v1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "description": "Scan Multi-Drive berbasis Host ID dipicu dari Telegram Bot",
        "hosts": host_ids,          # Field yang benar adalah 'hosts', bukan 'host_ids'
        "cpu_priority": 3,
        "file_paths": target_drives
    }

    # max_duration opsional (dalam jam, 0-24 sesuai batas API)
    if max_duration is not None:
        payload["max_duration"] = max_duration

    try:
        response = requests.post(url, headers=headers, json=payload)
        print(f"\n[DEBUG ODS] Status Code CrowdStrike: {response.status_code}")
        print(f"[DEBUG ODS] Payload yang dikirim: {json.dumps(payload)}")
        print(f"[DEBUG ODS] Respon JSON API: {response.text}\n")

        if response.status_code in (200, 201):
            resources = response.json().get("resources", [])
            scan_id = resources[0]["id"] if resources else None
            return True, scan_id, None
        else:
            errors = response.json().get("errors", [])
            error_detail = errors[0]["message"] if errors else f"Status code {response.status_code}"
            return False, None, error_detail

    except Exception as e:
        print(f"[DEBUG ODS CRITICAL] Gagal mengirim perintah ODS: {str(e)}")
        return False, None, str(e)


def cancel_ods_scan(token, scan_id):
    """
    Membatalkan scan yang sedang berjalan/pending.
    Return: (sukses: bool, error_detail: str atau None)
    """
    url = f"{FALCON_BASE_URL}/ods/entities/scan-control-actions/cancel/v1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {"ids": [scan_id]}

    try:
        response = requests.post(url, headers=headers, json=payload)
        print(f"[DEBUG CANCEL] Status Code: {response.status_code} | Response: {response.text}")

        if response.status_code in (200, 201):
            return True, None
        else:
            errors = response.json().get("errors", [])
            error_detail = errors[0]["message"] if errors else f"Status code {response.status_code}"
            return False, error_detail

    except Exception as e:
        print(f"[DEBUG CANCEL CRITICAL] Gagal membatalkan scan: {str(e)}")
        return False, str(e)


def get_scan_status(token, scan_id):
    """
    Mengambil status scan berdasarkan scan_id.
    Return: (data_scan: dict atau None, error_detail: str atau None)
    """
    url = f"{FALCON_BASE_URL}/ods/entities/scans/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"ids": scan_id}

    try:
        response = requests.get(url, headers=headers, params=params)
        print(f"[DEBUG STATUS] Status Code: {response.status_code} | Response: {response.text}")

        if response.status_code != 200:
            return None, f"Gagal mengambil status (status {response.status_code})."

        resources = response.json().get("resources", [])
        if not resources:
            return None, f"Scan ID `{scan_id}` tidak ditemukan."

        return resources[0], None

    except Exception as e:
        return None, f"Error saat mengambil status: {str(e)}"


def format_scan_status(scan_data):
    """Format data scan menjadi teks yang mudah dibaca di Telegram."""
    status = scan_data.get("status", "unknown")
    scan_id = scan_data.get("id", "-")
    file_paths = ", ".join(scan_data.get("file_paths", []))
    targeted = scan_data.get("targeted_host_count", 0)
    missing = scan_data.get("missing_host_count", 0)
    filecount = scan_data.get("filecount", {})

    status_emoji = {
        "pending": "⏳",
        "running": "🔄",
        "completed": "✅",
        "cancelled": "🛑",
        "error": "💥",
    }.get(status, "❔")

    text = (
        f"{status_emoji} *Status Scan*\n"
        f"🆔 ID: `{scan_id}`\n"
        f"📌 Status: *{status}*\n"
        f"📂 Lokasi: {file_paths}\n"
        f"🖥️ Host ditarget: {targeted} (hilang/offline: {missing})\n"
    )

    if filecount:
        traversed = filecount.get("traversed", 0)
        malicious = filecount.get("malicious", 0)
        quarantined = filecount.get("quarantined", 0)
        skipped = filecount.get("skipped", 0)
        text += (
            f"📊 File diperiksa: {traversed}\n"
            f"⚠️ Malicious ditemukan: {malicious}\n"
            f"🔒 Dikarantina: {quarantined}\n"
            f"⏭️ Dilewati: {skipped}\n"
        )

    return text


# === DECORATOR AKSES ===
def restricted(func):
    """Membatasi command hanya untuk ALLOWED_CHAT_ID, menghindari pengulangan cek di tiap handler."""
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        if update.effective_chat.id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("⛔ Akses ditolak! Anda tidak memiliki izin.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper


# === JOB POLLING OTOMATIS (notifikasi saat scan selesai) ===
async def poll_scan_job(context: ContextTypes.DEFAULT_TYPE):
    """Dipanggil berkala oleh JobQueue untuk mengecek status scan dan mengirim notifikasi saat selesai."""
    job_data = context.job.data
    scan_id = job_data["scan_id"]
    chat_id = job_data["chat_id"]
    elapsed = job_data.get("elapsed", 0)

    token = get_falcon_token()
    if not token:
        # Gagal ambil token, coba lagi di polling berikutnya (jangan langsung stop)
        job_data["elapsed"] = elapsed + STATUS_POLL_INTERVAL
        if job_data["elapsed"] >= STATUS_POLL_TIMEOUT:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"⌛ Pemantauan scan `{scan_id}` dihentikan (timeout), gagal mengambil token berkali-kali.",
                parse_mode="Markdown"
            )
            context.job.schedule_removal()
        return

    scan_data, error_msg = get_scan_status(token, scan_id)

    if error_msg:
        job_data["elapsed"] = elapsed + STATUS_POLL_INTERVAL
        if job_data["elapsed"] >= STATUS_POLL_TIMEOUT:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"⌛ Pemantauan scan `{scan_id}` dihentikan (timeout). Error terakhir: {error_msg}",
                parse_mode="Markdown"
            )
            context.job.schedule_removal()
        return

    status = scan_data.get("status", "unknown")

    # Status final: hentikan job dan kirim notifikasi hasil akhir
    if status in ("completed", "cancelled", "error"):
        await context.bot.send_message(
            chat_id=chat_id,
            text="🔔 *Scan Selesai!*\n\n" + format_scan_status(scan_data),
            parse_mode="Markdown"
        )
        context.job.schedule_removal()
        return

    # Masih berjalan, cek timeout
    job_data["elapsed"] = elapsed + STATUS_POLL_INTERVAL
    if job_data["elapsed"] >= STATUS_POLL_TIMEOUT:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⌛ Pemantauan otomatis untuk scan `{scan_id}` dihentikan karena sudah "
                f"{STATUS_POLL_TIMEOUT // 3600} jam belum selesai (status terakhir: *{status}*).\n"
                f"Cek manual dengan `/status {scan_id}`."
            ),
            parse_mode="Markdown"
        )
        context.job.schedule_removal()


def parse_duration_flag(args):
    """
    Mencari flag --duration <jam> di antara argumen.
    Return: (args_tanpa_flag, duration_jam_atau_None, error_msg_atau_None)
    """
    cleaned_args = []
    duration = None
    i = 0
    while i < len(args):
        if args[i].lower() == "--duration":
            if i + 1 >= len(args):
                return None, None, "Flag `--duration` harus diikuti angka jam, contoh: `--duration 8`."
            try:
                duration = int(args[i + 1])
            except ValueError:
                return None, None, "Nilai `--duration` harus berupa angka (jam)."
            if duration < 0 or duration > 24:
                return None, None, "Nilai `--duration` harus antara 0-24 jam."
            i += 2  # lewati flag dan nilainya
        else:
            cleaned_args.append(args[i])
            i += 1
    return cleaned_args, duration, None


# === FUNGSI TELEGRAM BOT ===
@restricted
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /start - salam pembuka singkat, arahkan ke /help."""
    await update.message.reply_text(
        "👋 Halo! Bot CrowdStrike ODS siap digunakan.\nKetik /help untuk melihat daftar perintah."
    )


@restricted
async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /help - menampilkan daftar perintah yang tersedia."""
    text = (
        "*📖 Daftar Perintah*\n\n"
        "`/scan HOST_ID_ATAU_HOSTNAME [DRIVE...] [--duration JAM]`\n"
        "Memicu On-Demand Scan. Drive default `C:\\` jika tidak diisi.\n"
        "Contoh:\n"
        "  `/scan HOST01 C:\\ D:\\`\n"
        "  `/scan 1a2b3c... C:\\ --duration 8`\n\n"
        "`/status SCAN_ID`\n"
        "Cek status scan secara manual.\n\n"
        "`/cancel SCAN_ID`\n"
        "Membatalkan scan yang sedang berjalan/pending.\n\n"
        "`/help`\n"
        "Menampilkan pesan ini."
    )
    await update.message.reply_text(text, parse_mode="Markdown")


@restricted
async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Validasi Input: Pastikan ada teks setelah kata /scan
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ Format salah. Contoh:\n"
            "`/scan HOST_ID C:\\ D:\\`\n"
            "`/scan NAMA_HOST C:\\ D:\\`\n"
            "`/scan NAMA_HOST C:\\ D:\\ --duration 8`",
            parse_mode="Markdown"
        )
        return

    # Cari & pisahkan flag --duration dari daftar argumen
    cleaned_args, max_duration, dur_error = parse_duration_flag(context.args)
    if dur_error:
        await update.message.reply_text(f"❌ {dur_error}", parse_mode="Markdown")
        return

    if not cleaned_args:
        await update.message.reply_text("❌ Host ID/nama host tidak ditemukan pada command.")
        return

    # Argumen pertama: bisa Host ID atau hostname
    raw_host_input = str(cleaned_args[0]).strip()

    # Membaca daftar drive (argumen kedua dan seterusnya)
    input_drives = cleaned_args[1:]

    if not input_drives:
        target_drives = ["C:\\"]
    else:
        target_drives = []
        for drive in input_drives:
            # Membersihkan karakter kutip yang merusak tanda baca Windows
            clean_drive = drive.replace('"', '').replace("'", "").strip()

            if ":" in clean_drive:
                letter = clean_drive.split(":")[0]
                clean_drive = f"{letter}:\\"

            target_drives.append(clean_drive)

    drives_text = ", ".join([f"`{d}`" for d in target_drives])
    duration_text = f" (durasi maks {max_duration} jam)" if max_duration is not None else ""

    await update.message.reply_text(
        f"⏳ Sedang memproses scan untuk: *{raw_host_input}*\n🎯 Target lokasi: {drives_text}{duration_text}...",
        parse_mode="Markdown"
    )

    try:
        # 1. Dapatkan Token (memakai cache kalau masih berlaku)
        falcon_token = get_falcon_token()
        if not falcon_token:
            await update.message.reply_text("❌ Gagal terhubung ke CrowdStrike. Periksa kredensial API Anda di .env.")
            return

        # 2. Resolusi host: terima Host ID langsung atau hostname
        target_host_id, error_msg = resolve_host_id(falcon_token, raw_host_input)
        if error_msg:
            await update.message.reply_text(f"❌ {error_msg}", parse_mode="Markdown")
            return

        # 3. Jalankan Scan
        sukses, scan_id, ods_error = trigger_ods(falcon_token, [target_host_id], target_drives, max_duration)

        if sukses:
            await update.message.reply_text(
                f"✅ *Sukses!* Scan pada drive {drives_text} telah dikirim ke *{raw_host_input}* (ID: `{target_host_id}`).\n"
                f"🆔 Scan ID: `{scan_id}`\n"
                f"Gunakan `/status {scan_id}` untuk cek manual, atau tunggu notifikasi otomatis saat scan selesai.",
                parse_mode="Markdown"
            )

            # Jadwalkan polling otomatis kalau job_queue tersedia
            if context.job_queue is not None and scan_id:
                context.job_queue.run_repeating(
                    poll_scan_job,
                    interval=STATUS_POLL_INTERVAL,
                    first=STATUS_POLL_INTERVAL,
                    data={"scan_id": scan_id, "chat_id": update.effective_chat.id, "elapsed": 0},
                    name=f"scan_poll_{scan_id}",
                )
        else:
            await update.message.reply_text(f"❌ Gagal memicu scan. Detail: {ods_error}")

    except Exception as e:
        await update.message.reply_text(f"💥 Terjadi error pada sistem: {str(e)}")


@restricted
async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /status <scan_id> - cek status scan secara manual."""
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ Format salah. Contoh:\n`/status <scan_id>`",
            parse_mode="Markdown"
        )
        return

    scan_id = context.args[0].strip()

    falcon_token = get_falcon_token()
    if not falcon_token:
        await update.message.reply_text("❌ Gagal terhubung ke CrowdStrike. Periksa kredensial API Anda.")
        return

    scan_data, error_msg = get_scan_status(falcon_token, scan_id)
    if error_msg:
        await update.message.reply_text(f"❌ {error_msg}", parse_mode="Markdown")
        return

    await update.message.reply_text(format_scan_status(scan_data), parse_mode="Markdown")


@restricted
async def cancel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /cancel <scan_id> - membatalkan scan yang sedang berjalan/pending."""
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ Format salah. Contoh:\n`/cancel <scan_id>`",
            parse_mode="Markdown"
        )
        return

    scan_id = context.args[0].strip()

    falcon_token = get_falcon_token()
    if not falcon_token:
        await update.message.reply_text("❌ Gagal terhubung ke CrowdStrike. Periksa kredensial API Anda.")
        return

    sukses, error_msg = cancel_ods_scan(falcon_token, scan_id)

    if not sukses:
        await update.message.reply_text(f"❌ Gagal membatalkan scan. Detail: {error_msg}")
        return

    # Hentikan job polling otomatis yang sedang memantau scan ini (kalau ada)
    if context.job_queue is not None:
        jobs = context.job_queue.get_jobs_by_name(f"scan_poll_{scan_id}")
        for job in jobs:
            job.schedule_removal()

    await update.message.reply_text(
        f"🛑 Perintah pembatalan untuk scan `{scan_id}` telah dikirim.\n"
        f"Gunakan `/status {scan_id}` untuk konfirmasi status akhirnya.",
        parse_mode="Markdown"
    )


# === MENJALANKAN BOT ===
def main():
    _validate_config()

    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("cancel", cancel_cmd))
    print("Bot Telegram CrowdStrike (Host ID / Hostname + Status + Auto-Notify + Cancel) sedang berjalan...")
    app.run_polling()


if __name__ == '__main__':
    main()