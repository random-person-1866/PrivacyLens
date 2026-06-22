#!/usr/bin/env pythonw
# -*- coding: utf-8 -*-
"""
PrivacyLens — Windows metadata hygiene utility.
First-run wizard + background scheduler.
"""
import os
import sys
import json
import time
import logging
import threading
import ctypes
from io import BytesIO
from pathlib import Path

try:
    import winreg
    _WIN_AVAILABLE = True
except ImportError:
    _WIN_AVAILABLE = False

try:
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED = True
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    _TK_AVAILABLE = True
except ImportError:
    _TK_AVAILABLE = False


# Constants
APP_NAME = "PrivacyLens"
APP_DIR = os.path.join(os.environ.get('APPDATA', str(Path.home())), APP_NAME)
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
LOG_PATH = os.path.join(APP_DIR, "privacy_lens.log")
SUPPORTED_EXTS = ('.jpg', '.jpeg', '.png', '.webp')
SCHEDULER_TICK_SECS = 60
DEFAULT_SCHEDULE_HRS = {'Daily': 24.0, 'Weekly': 168.0}


# ============================================================
# ConfigManager
# ============================================================
class ConfigManager:
    DEFAULT_CONFIG = {
        "first_run": True,
        "scan_dirs": [],
        "schedule_type": "Daily",
        "schedule_value": "",
        "exclusions": [],
        "last_run_timestamp": 0,
        "app_version": "1.0.0"
    }

    def __init__(self, path):
        self.config_path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.config = self._load()

    def _load(self):
        try:
            if not os.path.exists(self.config_path):
                return dict(self.DEFAULT_CONFIG)
            with open(self.config_path, 'r', encoding='utf-8') as f:
                raw = json.load(f) or {}
        except json.JSONDecodeError as e:
            logging.getLogger(APP_NAME).error("Config JSON malformed: %s.", e)
            return dict(self.DEFAULT_CONFIG)
        except (PermissionError, OSError) as e:
            logging.getLogger(APP_NAME).error("Config read denied (%s).", e)
            return dict(self.DEFAULT_CONFIG)
        merged = dict(self.DEFAULT_CONFIG)
        merged.update(raw)
        return merged

    def reload(self):
        self.config = self._load()

    def save(self, cfg=None):
        cfg = self.config if cfg is None else cfg
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=4)
            self.config = cfg
            return True
        except (PermissionError, OSError) as e:
            logging.getLogger(APP_NAME).error("Config save denied: %s", e)
            return False

    def update_last_run(self, ts):
        self.config['last_run_timestamp'] = ts
        self.save(self.config)


# ============================================================
# PrivacyLogger
# ============================================================
class PrivacyLogger:
    def __init__(self, name, log_path):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        if self.logger.handlers:
            return
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            handler = logging.FileHandler(log_path, encoding='utf-8')
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)-7s | %(threadName)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            if sys.stderr is not None:
                err = logging.StreamHandler(sys.stderr)
                err.setFormatter(formatter)
                err.setLevel(logging.ERROR)
                self.logger.addHandler(err)
        except (PermissionError, OSError) as e:
            self.logger.addHandler(logging.StreamHandler())
            self.logger.error("File logging failed (%s); stderr only.", e)


# ============================================================
# StartupManager
# ============================================================
class StartupManager:
    RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    VALUE_NAME = APP_NAME

    @staticmethod
    def _pythonw_path():
        if getattr(sys, 'frozen', False):
            return sys.executable
        exe_dir = os.path.dirname(sys.executable)
        base = os.path.basename(sys.executable).lower()
        if base.endswith('w.exe'):
            return sys.executable
        candidate = os.path.join(exe_dir, 'pythonw.exe')
        if os.path.exists(candidate):
            return candidate
        return sys.executable

    @staticmethod
    def build_command():
        if getattr(sys, 'frozen', False):
            return f'"{sys.executable}" --boot'
        return f'"{StartupManager._pythonw_path()}" "{os.path.abspath(__file__)}" --boot'

    @staticmethod
    def add():
        if not _WIN_AVAILABLE:
            logging.getLogger(APP_NAME).warning("winreg unavailable; cannot add to startup.")
            return False
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, StartupManager.RUN_KEY_PATH) as key:
                winreg.SetValueEx(key, StartupManager.VALUE_NAME, 0, winreg.REG_SZ,
                                  StartupManager.build_command())
            return True
        except PermissionError as e:
            logging.getLogger(APP_NAME).error("Registry write denied: %s", e)
            return False
        except Exception as e:
            logging.getLogger(APP_NAME).error("Startup registration failed: %s", e)
            return False


# ============================================================
# WinTimestamps — preserve file creation time via ctypes
# ============================================================
class WinTimestamps:
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    FILE_ATTR_NORMAL = 0x80
    INVALID_HANDLE_VALUE = -1

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLow", ctypes.c_uint32), ("dwHigh", ctypes.c_uint32)]

    @staticmethod
    def set_creation_time(path, unix_secs):
        if not _WIN_AVAILABLE:
            return False
        try:
            ft = WinTimestamps._FILETIME()
            hundredths = int((unix_secs + 11644473600) * 1e7)
            ft.dwLow = hundredths & 0xFFFFFFFF
            ft.dwHigh = (hundredths >> 32) & 0xFFFFFFFF
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            handle = kernel32.CreateFileW(
                path,
                WinTimestamps.GENERIC_WRITE | WinTimestamps.GENERIC_READ,
                0, None,
                WinTimestamps.OPEN_EXISTING,
                WinTimestamps.FILE_ATTR_NORMAL, None)
            if handle == ctypes.c_void_p(WinTimestamps.INVALID_HANDLE_VALUE):
                return False
            try:
                return bool(kernel32.SetFileTime(handle, ctypes.byref(ft), None, None))
            finally:
                kernel32.CloseHandle(handle)
        except Exception as e:
            logging.getLogger(APP_NAME).debug("set_creation_time failed (%s): %s", path, e)
            return False


# ============================================================
# MetadataStripper
# ============================================================
class MetadataStripper:
    def __init__(self, logger):
        self.logger = logger

    def has_metadata(self, img):
        info = img.info or {}
        if info.get('exif') or info.get('icc_profile'):
            return True
        if info.get('XMP') or info.get('xmp'):
            return True
        if info.get('APNG') or info.get('iptc'):
            return True
        try:
            exif = img.getexif()
            if exif and len(exif) > 0:
                return True
        except Exception:
            pass
        return False

    def strip(self, path):
        try:
            ext = os.path.splitext(path)[1].lower()
            if ext not in SUPPORTED_EXTS:
                return False, 'unsupported'

            stat = os.stat(path)
            atime, mtime, ctime = stat.st_atime, stat.st_mtime, stat.st_ctime

            with open(path, 'rb') as f:
                original_bytes = f.read()

            try:
                img = Image.open(BytesIO(original_bytes))
                img.load()
            except (OSError, IOError, ValueError) as e:
                self.logger.warning("Cannot open image (%s); skipping: %s", e, path)
                return False, 'corrupt'

            if not self.has_metadata(img):
                return False, 'no_metadata'

            try:
                stripped = self._encode_metadata_free(img)
            except Exception as e:
                self.logger.error("Encoding failed (%s); file unchanged: %s", e, path)
                return False, 'encode_error'

            tmp = path + '.privacylens.tmp'
            try:
                with open(tmp, 'wb') as f:
                    f.write(stripped)
                os.replace(tmp, path)
            except PermissionError as e:
                if os.path.exists(tmp):
                    try: os.remove(tmp)
                    except OSError: pass
                self.logger.warning("Permission denied writing %s (%s).", path, e)
                return False, 'in_use'
            except FileNotFoundError as e:
                if os.path.exists(tmp):
                    try: os.remove(tmp)
                    except OSError: pass
                self.logger.warning("File disappeared during strip (%s): %s", e, path)
                return False, 'not_found'

            try:
                os.utime(path, (atime, mtime))
                WinTimestamps.set_creation_time(path, ctime)
            except OSError as e:
                self.logger.debug("Could not restore timestamps for %s: %s", path, e)

            return True, 'stripped'

        except PermissionError as e:
            self.logger.warning("Permission error on %s: %s", path, e)
            return False, 'permission_error'
        except FileNotFoundError as e:
            self.logger.warning("File not found during strip: %s: %s", path, e)
            return False, 'not_found'
        except Exception as e:
            self.logger.error("Unexpected error on %s: %s", path, e, exc_info=True)
            return False, 'error'

    def _encode_metadata_free(self, img):
        buffer = BytesIO()
        fmt = (img.format or '').upper()
        original_quality = img.info.get('quality', 95)
        save_kwargs = {}

        if fmt in ('JPEG', 'JPG'):
            save_kwargs['quality'] = max(1, min(100, int(original_quality)))
            if img.info.get('subsampling'):
                save_kwargs['subsampling'] = img.info['subsampling']
            save_kwargs['optimize'] = False
            save_kwargs['progressive'] = bool(img.info.get('progression', False))
        elif fmt == 'PNG':
            save_kwargs['compress_level'] = 6
        elif fmt == 'WEBP':
            save_kwargs['quality'] = 100
            save_kwargs['method'] = 4

        n_frames = getattr(img, 'n_frames', 1)
        if n_frames > 1:
            save_kwargs['save_all'] = True
            frames = []
            for i in range(1, n_frames):
                img.seek(i)
                frames.append(img.copy())
            img.seek(0)
            save_kwargs['append_images'] = frames

        img.save(buffer, format=fmt, **save_kwargs)
        return buffer.getvalue()


# ============================================================
# BackgroundScanner
# ============================================================
class BackgroundScanner:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.stripper = MetadataStripper(logger)
        self._lock = threading.Lock()

    def _is_excluded(self, path, exclusions):
        for exc in exclusions:
            try:
                path.relative_to(exc)
                return True
            except ValueError:
                continue
        return False

    def scan(self):
        if not self._lock.acquire(blocking=False):
            self.logger.info("Scan already in progress; skipping trigger.")
            return {'scanned': 0, 'stripped': 0, 'skipped': 0, 'errors': 0, 'reason': 'busy'}
        try:
            cfg = self.config.config
            scan_dirs = list(cfg.get('scan_dirs', []) or [])
            exclusions = [Path(p).resolve() for p in (cfg.get('exclusions', []) or [])]
            self.logger.info("Scan started | dirs=%s | exclusions=%s",
                             scan_dirs, [str(e) for e in exclusions])
            results = {'scanned': 0, 'stripped': 0, 'skipped': 0, 'errors': 0}
            for d in scan_dirs:
                try:
                    root = Path(d).resolve()
                    if not root.exists() or not root.is_dir():
                        self.logger.warning("Scan dir missing: %s", root)
                        continue
                    self._walk_dir(root, exclusions, results)
                except PermissionError as e:
                    self.logger.error("Permission denied walking %s: %s", d, e)
                except Exception as e:
                    self.logger.error("Error scanning %s: %s", d, e, exc_info=True)
            self.config.update_last_run(time.time())
            self.logger.info("Scan complete | scanned=%d stripped=%d skipped=%d errors=%d",
                             results['scanned'], results['stripped'],
                             results['skipped'], results['errors'])
            results['reason'] = 'ok'
            return results
        finally:
            self._lock.release()

    def _walk_dir(self, root_dir, exclusions, results):
        for current_root, dirs, files in os.walk(root_dir):
            current_path = Path(current_root).resolve()
            dirs[:] = [d for d in dirs
                       if not self._is_excluded((current_path / d).resolve(), exclusions)]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext not in SUPPORTED_EXTS:
                    continue
                full_path = os.path.join(current_root, f)
                results['scanned'] += 1
                try:
                    success, reason = self.stripper.strip(full_path)
                    if reason == 'stripped':
                        results['stripped'] += 1
                        self.logger.info("Stripped metadata: %s", full_path)
                    elif reason in ('no_metadata', 'unsupported'):
                        results['skipped'] += 1
                        self.logger.debug("Skipped (%s): %s", reason, full_path)
                    else:
                        results['errors'] += 1
                except PermissionError as e:
                    results['errors'] += 1
                    self.logger.warning("Permission denied on %s: %s", full_path, e)
                except FileNotFoundError as e:
                    results['errors'] += 1
                    self.logger.warning("File not found during scan: %s: %s", full_path, e)
                except Exception as e:
                    results['errors'] += 1
                    self.logger.error("Unexpected error on %s: %s", full_path, e, exc_info=True)


# ============================================================
# BackgroundScheduler
# ============================================================
class BackgroundScheduler:
    def __init__(self, config, logger, scanner):
        self.config = config
        self.logger = logger
        self.scanner = scanner
        self._stop_event = threading.Event()
        self._thread = None

    def _interval_hours(self):
        cfg = self.config.config
        sched_type = cfg.get('schedule_type', 'Daily')
        if sched_type == 'Daily':
            return DEFAULT_SCHEDULE_HRS['Daily']
        if sched_type == 'Weekly':
            return DEFAULT_SCHEDULE_HRS['Weekly']
        if sched_type == 'Custom Hours':
            try:
                hrs = float(cfg.get('schedule_value', 0) or 0)
                if hrs <= 0:
                    self.logger.warning("Invalid custom hours (<=0); using 24h.")
                    return 24.0
                return hrs
            except (TypeError, ValueError):
                self.logger.warning("Custom hours non-numeric; using 24h.")
                return 24.0
        return 24.0

    def _should_run_now(self):
        try:
            cfg = self.config.config
            last_run = float(cfg.get('last_run_timestamp', 0) or 0)
            if last_run <= 0:
                return True
            interval_hours = self._interval_hours()
            elapsed_hours = (time.time() - last_run) / 3600.0
            return elapsed_hours >= interval_hours
        except Exception as e:
            self.logger.error("Scheduler decision error: %s", e, exc_info=True)
            return False

    def _loop(self):
        self.logger.info("BackgroundScheduler thread started.")
        while not self._stop_event.is_set():
            try:
                self.config.reload()
                if self._should_run_now():
                    self.logger.info("Interval reached — triggering scan.")
                    try:
                        self.scanner.scan()
                    except Exception as e:
                        self.logger.error("Scanner crash isolated: %s", e, exc_info=True)
            except Exception as e:
                self.logger.error("Scheduler tick error: %s", e, exc_info=True)
            self._stop_event.wait(SCHEDULER_TICK_SECS)
        self.logger.info("BackgroundScheduler thread exiting.")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="PL-Scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        self.logger.info("BackgroundScheduler stopped.")


# ============================================================
# SetupWizard
# ============================================================
class SetupWizard:
    TITLE = "PrivacyLens — First Run Setup"
    BG = "#1c1c1e"
    FG = "#e6e6e6"
    PANEL = "#2a2a2e"
    ACCENT = "#2d6cdf"
    ACCENT_HOVER = "#23589a"
    MUTE = "#a0a0a0"
    DAYS_OF_WEEK = ['Monday', 'Tuesday', 'Wednesday',
                    'Thursday', 'Friday', 'Saturday', 'Sunday']

    def __init__(self, config_manager):
        self.config_manager = config_manager
        cfg = config_manager.config or {}
        self.scan_dirs = list(cfg.get('scan_dirs', []) or [])
        if not self.scan_dirs:
            home = str(Path.home())
            for sub in ('Downloads', 'Pictures'):
                cand = os.path.join(home, sub)
                if os.path.isdir(cand):
                    self.scan_dirs.append(cand)
        self.exclusions = list(cfg.get('exclusions', []) or [])
        self.schedule_type = cfg.get('schedule_type', 'Daily')
        self.schedule_value = cfg.get('schedule_value', '')
        self.root = None
        self._scan_list = None
        self._excl_list = None
        self._sched_type_var = None
        self._sched_value_combo = None
        self._sched_value_var = None

    def _apply_theme(self):
        c = {'bg': self.BG, 'fg': self.FG, 'panel': self.PANEL,
             'accent': self.ACCENT, 'hover': self.ACCENT_HOVER}
        self.colors = c
        self.root.configure(bg=c['bg'])
        s = ttk.Style()
        try: s.theme_use('clam')
        except Exception: pass
        s.configure('TFrame', background=c['bg'])
        s.configure('TPanel.TFrame', background=c['panel'])
        s.configure('TLabel', background=c['bg'], foreground=c['fg'], font=('Segoe UI', 10))
        s.configure('TTitle', background=c['bg'], foreground=c['accent'], font=('Segoe UI', 22, 'bold'))
        s.configure('TSubtitle', background=c['bg'], foreground=self.MUTE, font=('Segoe UI', 10, 'italic'))
        s.configure('TSection', background=c['bg'], foreground=c['accent'], font=('Segoe UI', 12, 'bold'))
        s.configure('TButton', background=c['accent'], foreground='white', borderwidth=0, padding=(16, 8), font=('Segoe UI', 10, 'bold'))
        s.map('TButton', background=[('active', c['hover']), ('disabled', '#444')])
        s.configure('TExit', background='#444', foreground=c['fg'], borderwidth=0, padding=(16, 8), font=('Segoe UI', 10, 'bold'))
        s.map('TExit', background=[('active', '#555')])
        s.configure('TEntry', fieldbackground=c['panel'], foreground=c['fg'], borderwidth=1, padding=4)
        s.configure('TCombobox', fieldbackground=c['panel'], foreground=c['fg'], background=c['bg'], borderwidth=1, padding=4)
        s.map('TCombobox', fieldbackground=[('readonly', c['panel'])], background=[('readonly', c['bg'])])

    def _build(self):
        c = self.colors
        root = self.root
        header = ttk.Frame(root, style='TFrame')
        header.pack(fill='x', padx=20, pady=(20, 8))
        ttk.Label(header, text="PrivacyLens", style='TTitle').pack(anchor='w')
        ttk.Label(header, text="Configure metadata hygiene for your images.", style='TSubtitle').pack(anchor='w')
        ttk.Separator(root, orient='thin').pack(fill='x', padx=20, pady=6)
        body = ttk.Frame(root)
        body.pack(fill='both', expand=True, padx=20, pady=4)

        # Section 1: scan dirs
        sec1 = ttk.Frame(body, style='TFrame')
        sec1.pack(fill='both', anchor='w', pady=(4, 8))
        ttk.Label(sec1, text="Scan Directories", style='TSection').pack(anchor='w')
        ttk.Label(sec1, text="Folders PrivacyLens will recursively scan for new images.", style='TSubtitle').pack(anchor='w', pady=(0, 4))
        scan_frame = ttk.Frame(sec1, style='TPanel.TFrame')
        scan_frame.pack(fill='both', expand=True, anchor='w', pady=4)
        h1 = ttk.Frame(scan_frame, style='TPanel.TFrame')
        h1.pack(side='left', fill='both', expand=True, padx=(6, 4), pady=6)
        sb1 = ttk.Scrollbar(h1, orient='vertical')
        self._scan_list = tk.Listbox(h1, bg=c['panel'], fg=c['fg'], bd=0, font=('Segoe UI', 10), highlightthickness=0, selectbackground=c['accent'], yscrollcommand=sb1.set)
        sb1.config(command=self._scan_list.yview)
        self._scan_list.pack(side='left', fill='both', expand=True)
        sb1.pack(side='right', fill='y')
        for d in self.scan_dirs: self._scan_list.insert('end', d)
        hb1 = ttk.Frame(scan_frame, style='TPanel.TFrame')
        hb1.pack(side='left', fill='y', padx=(0, 6), pady=6)
        ttk.Button(hb1, text="Add Folder…", command=self._add_scan_dir).pack(fill='x', pady=(2, 4))
        ttk.Button(hb1, text="Remove", command=self._remove_scan_dir).pack(fill='x', pady=2)
        ttk.Button(hb1, text="Clear", command=self._clear_scan_dirs).pack(fill='x', pady=2)

        # Section 2: exclusions
        sec2 = ttk.Frame(body, style='TFrame')
        sec2.pack(fill='both', expand=True, anchor='w', pady=(8, 4))
        ttk.Label(sec2, text="Exclusions", style='TSection').pack(anchor='w')
        ttk.Label(sec2, text="Subfolders to skip during recursive scans.", style='TSubtitle').pack(anchor='w', pady=(0, 4))
        excl_frame = ttk.Frame(sec2, style='TPanel.TFrame')
        excl_frame.pack(fill='both', expand=True, anchor='w', pady=4)
        h2 = ttk.Frame(excl_frame, style='TPanel.TFrame')
        h2.pack(side='left', fill='both', expand=True, padx=(6, 4), pady=6)
        sb2 = ttk.Scrollbar(h2, orient='vertical')
        self._excl_list = tk.Listbox(h2, bg=c['panel'], fg=c['fg'], bd=0, font=('Segoe UI', 10), highlightthickness=0, selectbackground=c['accent'], yscrollcommand=sb2.set)
        sb2.config(command=self._excl_list.yview)
        self._excl_list.pack(side='left', fill='both', expand=True)
        sb2.pack(side='right', fill='y')
        for d in self.exclusions: self._excl_list.insert('end', d)
        hb2 = ttk.Frame(excl_frame, style='TPanel.TFrame')
        hb2.pack(side='left', fill='y', padx=(0, 6), pady=6)
        ttk.Button(hb2, text="Add Folder…", command=self._add_excl_dir).pack(fill='x', pady=(2, 4))
        ttk.Button(hb2, text="Remove", command=self._remove_excl_dir).pack(fill='x', pady=2)

        # Section 3: schedule
        sec3 = ttk.Frame(body, style='TFrame')
        sec3.pack(fill='x', anchor='w', pady=(12, 4))
        ttk.Label(sec3, text="Scan Schedule", style='TSection').pack(anchor='w')
        ttk.Label(sec3, text="How often PrivacyLens should run scans.", style='TSubtitle').pack(anchor='w', pady=(0, 4))
        sf = ttk.Frame(sec3, style='TFrame')
        sf.pack(fill='x', anchor='w', pady=4)
        sf.columnconfigure(1, weight=1)
        self._sched_type_var = tk.StringVar(value=self.schedule_type)
        ttk.Label(sf, text="Type:", style='TLabel').grid(row=0, column=0, sticky='w', padx=(0, 8), pady=4)
        tc = ttk.Combobox(sf, textvariable=self._sched_type_var, values=['Daily', 'Weekly', 'Custom Hours'], state='readonly', width=20)
        tc.grid(row=0, column=1, sticky='w', pady=4)
        tc.bind('<<ComboboxSelected>>', self._on_type_change)
        ttk.Label(sf, text="Value:", style='TLabel').grid(row=1, column=0, sticky='w', padx=(0, 8), pady=4)
        self._sched_value_var = tk.StringVar(value=self.schedule_value or self._default_value_for_type(self.schedule_type))
        self._sched_value_combo = ttk.Combobox(sf, textvariable=self._sched_value_var, width=20)
        self._sched_value_combo.grid(row=1, column=1, sticky='w', pady=4)
        self._on_type_change()

        # Footer
        footer = ttk.Frame(root)
        footer.pack(fill='x', side='bottom', padx=20, pady=(8, 16))
        ttk.Button(footer, text="Finish Setup", style='TButton', command=self._on_finish).pack(side='right')
        ttk.Button(footer, text="Cancel", style='TExit', command=self._on_cancel).pack(side='right', padx=(0, 8))

    def _default_value_for_type(self, sched_type):
        if sched_type == 'Daily': return ''
        if sched_type == 'Weekly': return self.DAYS_OF_WEEK[0]
        if sched_type == 'Custom Hours': return '6'
        return ''

    def _on_type_change(self, event=None):
        t = self._sched_type_var.get()
        if t == 'Daily':
            self._sched_value_combo.config(values=[], state='disabled')
            self._sched_value_combo.set('')
        elif t == 'Weekly':
            self._sched_value_combo.config(values=self.DAYS_OF_WEEK, state='readonly')
            if self._sched_value_combo.get() not in self.DAYS_OF_WEEK:
                self._sched_value_combo.set(self.DAYS_OF_WEEK[0])
        elif t == 'Custom Hours':
            self._sched_value_combo.config(values=[], state='normal')
            try: int(self._sched_value_combo.get())
            except (ValueError, TypeError): self._sched_value_combo.set('6')

    def _add_scan_dir(self):
        d = filedialog.askdirectory(title="Add scan folder")
        if d:
            d = os.path.normpath(d)
            if d not in self.scan_dirs:
                self.scan_dirs.append(d)
                self._scan_list.insert('end', d)

    def _add_excl_dir(self):
        d = filedialog.askdirectory(title="Add exclusion folder")
        if d:
            d = os.path.normpath(d)
            if d not in self.exclusions:
                self.exclusions.append(d)
                self._excl_list.insert('end', d)

    def _remove_scan_dir(self):
        self._remove_selected(self._scan_list, self.scan_dirs)

    def _remove_excl_dir(self):
        self._remove_selected(self._excl_list, self.exclusions)

    def _remove_selected(self, listbox, backing_list):
        sel = listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        path = listbox.get(idx)
        listbox.delete(idx)
        if path in backing_list:
            backing_list.remove(path)

    def _clear_scan_dirs(self):
        self.scan_dirs.clear()
        self._scan_list.delete(0, 'end')

    def _on_cancel(self):
        self.root.destroy()
        sys.exit(0)

    def _on_finish(self):
        if not self.scan_dirs:
            messagebox.showwarning("PrivacyLens", "Add at least one scan directory before finishing.")
            return
        sched_type = self._sched_type_var.get()
        sched_value = self._sched_value_combo.get()
        if sched_type == 'Custom Hours':
            try:
                hrs = float(sched_value)
                if hrs <= 0:
                    raise ValueError
            except (ValueError, TypeError):
                messagebox.showwarning("PrivacyLens", "Custom Hours value must be a positive number.")
                return
        cfg = dict(self.config_manager.config or {})
        cfg['first_run'] = False
        cfg['scan_dirs'] = self.scan_dirs
        cfg['exclusions'] = self.exclusions
        cfg['schedule_type'] = sched_type
        cfg['schedule_value'] = sched_value
        cfg['last_run_timestamp'] = 0
        self.config_manager.config = cfg
        self.config_manager.save(cfg)
        messagebox.showinfo("PrivacyLens", "Setup complete! PrivacyLens will now run in the background.", parent=self.root)
        self.root.destroy()

    def run(self):
        if not _TK_AVAILABLE:
            sys.stderr.write("Tkinter is required for first-run setup. Aborting.\n")
            sys.exit(2)
        self.root = tk.Tk()
        self.root.title(self.TITLE)
        self.root.geometry("880x820")
        self.root.minsize(760, 760)
        self._apply_theme()
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.root.mainloop()


# ============================================================
# PrivacyLensApp
# ============================================================
class PrivacyLensApp:
    def __init__(self):
        os.makedirs(APP_DIR, exist_ok=True)
        self.privacy_logger = PrivacyLogger(APP_NAME, LOG_PATH)
        self.logger = self.privacy_logger.logger
        self.logger.info("PrivacyLens starting (pid=%d).", os.getpid())
        self.config = ConfigManager(CONFIG_PATH)
        self._stop_main = threading.Event()

    def _register_startup(self):
        StartupManager.add()

    def run(self, background=False):
        if not background:
            if self.config.config.get('first_run', True):
                self.logger.info("First run detected — launching SetupWizard.")
                try:
                    SetupWizard(self.config).run()
                except SystemExit:
                    raise
                except Exception as e:
                    self.logger.error("SetupWizard crashed (%s).", e, exc_info=True)
                self.config.reload()
                if self.config.config.get('first_run', True):
                    self.logger.warning("Setup incomplete; exiting.")
                    return
            self._register_startup()

        if not _PIL_AVAILABLE:
            self.logger.error("PIL not available; cannot strip images. Aborting.")
            return

        scanner = BackgroundScanner(self.config, self.logger)
        scheduler = BackgroundScheduler(self.config, self.logger, scanner)
        scheduler.start()

        try:
            while not self._stop_main.is_set():
                self._stop_main.wait(1.0)
        except KeyboardInterrupt:
            self.logger.info("KeyboardInterrupt — shutting down.")
            scheduler.stop()


def _main():
    background = '--boot' in sys.argv or '--background' in sys.argv
    PrivacyLensApp().run(background=background)


if __name__ == "__main__":
    _main()
