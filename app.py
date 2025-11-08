import os
import shutil
import logging
import json
import time
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session
import clamd  # <-- ClamAV integration

# --- Configuration File Path ---
CONFIG_FILE = "config.json"

# --- Default File Categories ---
DEFAULT_CATEGORIES = {
    "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg"],
    "Videos": [".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv"],
    "Documents": [".pdf", ".doc", ".docx", ".txt", ".rtf", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".csv"],
    "Audio": [".mp3", ".wav", ".flac", ".aac", ".ogg"],
    "Code": [".py", ".java", ".c", ".cpp", ".html", ".css", ".js", ".ts", ".jsx", ".tsx", ".json", ".xml", ".sh"],
    "Archives": [".zip", ".rar", ".7z", ".tar", ".gz"],
    "Executables": [".exe", ".msi", ".dmg"],
}

# --- Logging Setup ---
log_file_path = "file_organizer_activity.log"
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path, mode='a', encoding='utf-8'),
    ]
)

# --- Flask App Setup ---
app = Flask(__name__)
app.secret_key = 'super_secret_key_for_sessions_advanced'

# --- ClamAV Configuration ---
CLAMAV_HOST = '127.0.0.1'
CLAMAV_PORT = 3310
QUARANTINE_DIR = "quarantine"

def init_clamav():
    """Initialize ClamAV connection."""
    try:
        cd = clamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=CLAMAV_PORT)
        cd.ping()
        logging.info("✅ Connected to ClamAV daemon successfully.")
        return cd
    except Exception:
        logging.warning("⚠️ ClamAV daemon not running.")
        return None

def scan_with_clamav(target_path):
    """Scan directory recursively for viruses. If ClamAV inactive → skip."""
    cd = init_clamav()

    # ✅ Changed behavior: If ClamAV is not running → skip scan
    if cd is None:
        return True, "⚠️ ClamAV not running. Skipping antivirus scan and continuing."

    if not os.path.isdir(target_path):
        return False, f"Invalid directory: {target_path}"

    logging.info(f"🔍 Starting ClamAV scan on: {target_path}")
    infected_files = []

    for root, _, files in os.walk(target_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                result = cd.scan(file_path)
                if result and file_path in result and result[file_path][0] == 'FOUND':
                    virus_name = result[file_path][1]
                    infected_files.append((file_path, virus_name))
                    logging.warning(f"⚠️ Infected: {file_path} ({virus_name})")

                    os.makedirs(QUARANTINE_DIR, exist_ok=True)
                    quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
                    shutil.move(file_path, quarantine_path)
                    logging.info(f"🦠 Quarantined: {file_path} → {quarantine_path}")
            except Exception as e:
                logging.error(f"Error scanning {file_path}: {e}")

    if not infected_files:
        return True, f"✅ No infected files found in {target_path}."
    else:
        return True, f"⚠️ {len(infected_files)} infected file(s) found and quarantined."

# --- Configuration Management ---
def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                processed = {
                    cat: [f".{e.strip().lstrip('.').lower()}" for e in exts if e.strip()]
                    for cat, exts in config.items()
                }
                return {k: v for k, v in processed.items() if v}
    except Exception as e:
        logging.warning(f"Failed to load config: {e}")
    return DEFAULT_CATEGORIES

def save_config(new_categories):
    try:
        clean = {}
        for cat, exts in new_categories.items():
            valid = [f".{e.strip().lstrip('.').lower()}" for e in exts if e.strip()]
            if cat.strip() and valid:
                clean[cat.strip()] = valid
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(clean or DEFAULT_CATEGORIES, f, indent=4)
        return True, "Configuration saved successfully."
    except Exception as e:
        return False, f"Failed to save config: {e}"

# --- File Category Helper ---
def get_category(ext, mapping):
    ext = ext.lower()
    for cat, exts in mapping.items():
        if ext in exts:
            return cat
    return "Others"

# --- Organizer Core Logic ---
def organize_directory(target_path, dry_run=False, recursive=False, max_age_days=None, archive_mode=False, delete_empty_folders=False):
    if not os.path.isdir(target_path):
        return False, f"Invalid path: {target_path}"

    mapping = load_config()
    moved, skipped, errors, deleted = 0, 0, 0, 0
    folders_checked = set()

    for root, dirs, files in os.walk(target_path, topdown=True):
        if not recursive and root != target_path:
            dirs[:] = []
            continue
        if recursive and root != target_path:
            folders_checked.add(root)
        files_to_process = [f for f in files if f not in [os.path.basename(log_file_path), CONFIG_FILE, "app.py", "index.html"]]

        for item in files_to_process:
            src = os.path.join(root, item)
            if os.path.isdir(src):
                continue

            file_mtime = os.path.getmtime(src)
            if max_age_days:
                age_days = (time.time() - file_mtime) / 86400
                if age_days < max_age_days:
                    skipped += 1
                    continue

            _, ext = os.path.splitext(item)
            category = get_category(ext, mapping)
            dest_folder = os.path.join(target_path, category)

            if archive_mode:
                dt = datetime.fromtimestamp(file_mtime)
                dest_folder = os.path.join(dest_folder, dt.strftime("%Y/%m"))

            if not dry_run:
                os.makedirs(dest_folder, exist_ok=True)

            dest_path = os.path.join(dest_folder, item)
            base, e = os.path.splitext(item)
            counter = 1
            while os.path.exists(dest_path):
                dest_path = os.path.join(dest_folder, f"{base} ({counter}){e}")
                counter += 1

            if dry_run:
                logging.info(f"[DRY RUN] Would move: {src} → {dest_path}")
                moved += 1
            else:
                try:
                    shutil.move(src, dest_path)
                    logging.info(f"MOVED: {src} → {dest_path}")
                    moved += 1
                except Exception as e:
                    logging.error(f"Error moving {src}: {e}")
                    errors += 1

    if delete_empty_folders and not dry_run:
        for folder in sorted(folders_checked, key=len, reverse=True):
            try:
                os.rmdir(folder)
                deleted += 1
                logging.info(f"Deleted empty folder: {folder}")
            except:
                pass

    msg = f"Done. Moved: {moved}, Skipped: {skipped}, Errors: {errors}, Deleted: {deleted}"
    logging.info(msg)
    return True, msg

# --- Flask Routes ---
@app.route('/', methods=['GET', 'POST'])
def index():
    message = session.pop('message', None)
    categories = load_config()

    log_content = "Log is empty."
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_content = "".join(f.readlines()[-30:])
    except Exception as e:
        log_content = f"Error reading log: {e}"

    config_data = [{'name': k, 'exts_str': ", ".join([e.lstrip('.') for e in v])} for k, v in categories.items()]
    while len(config_data) < 10:
        config_data.append({'name': '', 'exts_str': ''})

    if request.method == 'POST':
        target_path = request.form.get('target_path')
        if not target_path:
            session['message'] = "Please enter a valid folder path."
            return redirect(url_for('index'))

        dry_run = request.form.get('dry_run_mode') == 'on'
        recursive = request.form.get('recursive_mode') == 'on'
        archive = request.form.get('archive_mode') == 'on'
        delete_empty = request.form.get('delete_empty_folders') == 'on'
        age_input = request.form.get('max_age_days')
        max_age = int(age_input) if age_input and age_input.isdigit() else None

        scan_ok, scan_msg = scan_with_clamav(target_path)

        # Continue even if scan skipped
        success, result_message = organize_directory(
            target_path, dry_run, recursive, max_age, archive, delete_empty
        )
        session['message'] = f"{scan_msg} | {result_message}"
        return redirect(url_for('index'))

    return render_template('index.html', message=message, log_content=log_content, config_data=config_data)

@app.route('/save_config', methods=['POST'])
def save_custom_config():
    data = {}
    for i in range(10):
        name = request.form.get(f'category_name_{i}')
        exts = request.form.get(f'category_exts_{i}')
        if name and exts:
            data[name] = [e.strip() for e in exts.split(',') if e.strip()]
    success, msg = save_config(data or DEFAULT_CATEGORIES)
    session['message'] = msg
    return redirect(url_for('index'))

@app.route('/clear_log', methods=['POST'])
def clear_log():
    try:
        with open(log_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{datetime.now()} - INFO - Log cleared.\n")
        session['message'] = "Log cleared successfully."
    except Exception as e:
        session['message'] = f"Error clearing log: {e}"
    return redirect(url_for('index'))

@app.route('/download_log')
def download_log():
    from flask import send_file
    if os.path.exists(log_file_path):
        return send_file(log_file_path, as_attachment=True, download_name='file_organizer_activity.log')
    session['message'] = "No log file found."
    return redirect(url_for('index'))

@app.route('/show_config')
def show_config():
    data = load_config()
    html = "<h2 class='text-2xl font-bold mb-4'>Current Configuration</h2><ul>"
    for k, v in data.items():
        html += f"<li><b>{k}</b>: {', '.join([e.lstrip('.') for e in v])}</li>"
    html += "</ul>"
    return html

@app.route('/chatbot', methods=['POST'])
def chatbot():
    user_message = request.form.get('user_message', '').strip().lower()
    if not user_message:
        return {"response": "Please enter a message."}

    # Simple AI-style responses (can be expanded easily)
    if "hello" in user_message or "hi" in user_message:
        bot_reply = "Hello! 👋 How can I assist you today?"
    elif "organize" in user_message:
        bot_reply = "To organize files, enter the folder path and click 'Start Organizing'."
    elif "virus" in user_message or "scan" in user_message:
        bot_reply = "I use ClamAV to scan files for viruses before organizing them!"
    elif "config" in user_message:
        bot_reply = "You can update the file type configuration using the form above the log."
    elif "scan mode" in user_message:
        bot_reply = "Scan moves without changing files."
    elif "archive mode" in user_message:
        bot_reply = "Archive files that are older than the specified age."
    elif "delete empty folders" in user_message:
        bot_reply = "Delete empty folders after organizing files."  
    elif "recursive mode" in user_message:
        bot_reply = "Organize files in subfolders recursively."
    else:
        bot_reply = "I'm a simple assistant bot. Try asking about 'organize', 'virus','scan mode', 'archive mode', 'delete empty folders', 'recursive mode' or 'config'. 😊"

    return {"response": bot_reply}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)










