#All the python imports needed!
import os
import re
import sys
import csv
import platform
import datetime
import threading

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import psutil
except ImportError:
    print("Psutil Not Found! Run pip install psutil in CMD Terminal!")
    sys.exit(1)


# ==============================================================================
# SECTION 1 — CUSTOM DATA STRUCTURE
# ==============================================================================

class ThreatNode:
    def __init__(self, threat):
        self.threat = threat
        self.next = None


class ThreatLinkedList:
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def append(self, threat):
        node = ThreatNode(threat)
        if self.tail is None:
            # list is empty — head and tail point to the same node
            self.head = self.tail = node
        else:
            self.tail.next = node
            self.tail = node
        self.size += 1

    def remove_by_name(self, name):
        """Remove the first threat with this name. Returns True if something was removed."""
        prev = None
        curr = self.head
        while curr:
            if curr.threat.get("name") == name:
                if prev:
                    prev.next = curr.next
                else:
                    self.head = curr.next
                # fix the tail if we deleted the last node
                if curr == self.tail:
                    self.tail = prev
                self.size -= 1
                return True
            prev = curr
            curr = curr.next
        return False

    def search(self, name):
        """Find a threat by name. Returns the dict or None."""
        curr = self.head
        while curr:
            if curr.threat.get("name") == name:
                return curr.threat
            curr = curr.next
        return None

    def to_list(self):
        """Dump everything into a plain Python list."""
        result = []
        curr = self.head
        while curr:
            result.append(curr.threat)
            curr = curr.next
        return result

    def clear(self):
        """Wipe the list."""
        self.head = self.tail = None
        self.size = 0

    def __len__(self):
        return self.size

    def __iter__(self):
        curr = self.head
        while curr:
            yield curr.threat
            curr = curr.next


class HashTable:
    def __init__(self, capacity=128):
        self.capacity = capacity
        # each slot starts as an empty list — this is the "separate chaining" part
        self.buckets = [[] for _ in range(capacity)]
        self.count = 0

    def _hash(self, key):
        """Turn a string key into a bucket index using DJB2."""
        h = 5381
        for ch in key:
            h = ((h << 5) + h) + ord(ch)   # same as h * 33 + ord(ch)
        return h % self.capacity

    def insert(self, key, value):
        """Add or update a key-value pair."""
        idx = self._hash(key)
        for i, (k, v) in enumerate(self.buckets[idx]):
            if k == key:
                # key already exists — just update the value
                self.buckets[idx][i] = (key, value)
                return
        self.buckets[idx].append((key, value))
        self.count += 1

    def lookup(self, key):
        """Return the value for a key, or None if it doesn't exist."""
        for k, v in self.buckets[self._hash(key)]:
            if k == key:
                return v
        return None

    def delete(self, key):
        """Remove a key. Returns True if it was there, False if not."""
        idx = self._hash(key)
        for i, (k, v) in enumerate(self.buckets[idx]):
            if k == key:
                self.buckets[idx].pop(i)
                self.count -= 1
                return True
        return False

    def keys(self):
        """Get all keys in the table."""
        return [k for bucket in self.buckets for k, v in bucket]

    def __contains__(self, key):
        return self.lookup(key) is not None

    def __len__(self):
        return self.count


class ScanHistoryStack:
    """
    A small bounded stack that holds the last N scan summaries.
    Most recent scan is always on top. When we hit the limit, the
    oldest entry falls off the bottom.
    """

    def __init__(self, max_size=20):
        self.data = []
        self.max_size = max_size

    def push(self, scan_summary):
        """Push a scan result onto the stack. Drops the oldest if full."""
        if len(self.data) >= self.max_size:
            self.data.pop(0)   # remove oldest (bottom of stack)
        self.data.append(scan_summary)

    def pop(self):
        """Remove and return the most recent entry."""
        return self.data.pop() if self.data else None

    def peek(self):
        """Look at the most recent entry without removing it."""
        return self.data[-1] if self.data else None

    def is_empty(self):
        return len(self.data) == 0

    def to_list(self):
        """Return all entries newest-first."""
        return list(reversed(self.data))

    def __len__(self):
        return len(self.data)


# ==============================================================================
# SECTION 2 — SIGNATURE & HEURISTIC DATABASE
# ==============================================================================

# Known malicious process names and their severity / category
MALICIOUS_PROCESSES = [
    {"name": "keylogger.exe",  "severity": "CRITICAL", "category": "Keylogger", "detail": "Known keylogger process"},
    {"name": "spyware.exe",    "severity": "CRITICAL", "category": "Spyware",   "detail": "Generic spyware signature"},
    {"name": "ratclient.exe",  "severity": "CRITICAL", "category": "RAT",       "detail": "Remote Access Trojan client"},
    {"name": "njrat.exe",      "severity": "CRITICAL", "category": "RAT",       "detail": "njRAT — common remote access trojan"},
    {"name": "darkcomet.exe",  "severity": "CRITICAL", "category": "RAT",       "detail": "DarkComet RAT"},
    {"name": "remcos.exe",     "severity": "CRITICAL", "category": "RAT",       "detail": "Remcos RAT"},
    {"name": "asyncrat.exe",   "severity": "CRITICAL", "category": "RAT",       "detail": "AsyncRAT — open source RAT"},
    {"name": "hawkeye.exe",    "severity": "HIGH",     "category": "Keylogger", "detail": "HawkEye keylogger/credential stealer"},
    {"name": "lokibot.exe",    "severity": "HIGH",     "category": "Stealer",   "detail": "LokiBot info-stealer"},
    {"name": "redline.exe",    "severity": "HIGH",     "category": "Stealer",   "detail": "Redline credential stealer"},
    {"name": "recordme.exe",   "severity": "HIGH",     "category": "Keylogger", "detail": "Screen/key recorder"},
    {"name": "winvnc.exe",     "severity": "MEDIUM",   "category": "Remote",    "detail": "VNC server — verify intent"},
    {"name": "tightvnc.exe",   "severity": "MEDIUM",   "category": "Remote",    "detail": "TightVNC remote desktop"},
    {"name": "logmein.exe",    "severity": "LOW",      "category": "Remote",    "detail": "LogMeIn — verify intent"},
]

# Ports known to be used by RATs and malware C2 servers
# HTTP/HTTPS traffic to bypass firewalls — we flag unknown processes using them
SUSPICIOUS_PORTS = [
    {"port": 80,    "severity": "LOW",      "detail": "HTTP — RATs sometimes tunnel through this to bypass firewalls"},
    {"port": 443,   "severity": "LOW",      "detail": "HTTPS — encrypted traffic can hide C2 communication"},
    {"port": 1337,  "severity": "HIGH",     "detail": "Common RAT/backdoor port"},
    {"port": 4444,  "severity": "CRITICAL", "detail": "Metasploit default listener"},
    {"port": 5555,  "severity": "HIGH",     "detail": "Common RAT C2 port"},
    {"port": 6666,  "severity": "HIGH",     "detail": "Common malware C2 port"},
    {"port": 7777,  "severity": "MEDIUM",   "detail": "Often used by trojans"},
    {"port": 8888,  "severity": "MEDIUM",   "detail": "Alternate C2 port"},
    {"port": 9999,  "severity": "MEDIUM",   "detail": "Alternate C2 port"},
    {"port": 31337, "severity": "CRITICAL", "detail": "Back Orifice RAT port"},
    {"port": 12345, "severity": "HIGH",     "detail": "NetBus trojan port"},
    {"port": 54321, "severity": "HIGH",     "detail": "Back Orifice 2000 port"},
]

# Processes that are trusted system apps and shouldn't be flagged on port 80/443
TRUSTED_NET_PROCESSES = {
    # Browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "safari", "vivaldi.exe", "iexplore.exe",
    # Command-line HTTP tools
    "curl", "curl.exe", "wget", "wget.exe",
    # Runtimes / package managers
    "python.exe", "python3", "python3.exe", "python", "pip", "pip.exe",
    "node.exe", "node", "npm", "npm.exe", "npx", "npx.exe",
    "java", "java.exe", "javaw.exe",
    "ruby", "ruby.exe", "gem", "gem.exe",
    "dotnet", "dotnet.exe",
    "go", "go.exe",
    "cargo", "cargo.exe",
    "rustup", "rustup.exe",
    # Windows system processes
    "svchost.exe", "services.exe", "wininit.exe", "explorer.exe",
    "wuauclt.exe", "msiexec.exe", "powershell.exe", "pwsh.exe",
    "wsl.exe", "wslhost.exe", "backgroundtaskhost.exe",
    # Dev tools
    "code.exe", "code", "git.exe", "git",
    "ssh.exe", "ssh", "sftp.exe", "sftp",
    # Collaboration / productivity
    "slack.exe", "discord.exe", "teams.exe", "zoom.exe",
    "webex.exe", "msteams.exe",
    # Cloud sync
    "onedrive.exe", "dropbox.exe", "googledrivesync.exe", "box.exe",
    # Mail clients
    "outlook.exe", "thunderbird.exe",
    # Security tools (should not be flagged as suspicious)
    "mbam.exe", "avpui.exe", "avgui.exe", "avgnt.exe",
}

# Suspicious strings in startup entry names — spyware often take Windows names
SUSPICIOUS_STARTUP_PATTERNS = [
    "svchost32", "winlogon32", "csrss32", "lsass32",
    "services32", "explorer32", "update_helper",
    "sys_monitor", "keymon", "input_monitor",
    "screen_capture",
]

# File extensions that normal software doesn't create
SUSPICIOUS_FILE_EXTENSIONS = {".keylog", ".spy", ".caplog", ".crklog"}

# Heuristic flags — process behaviour patterns that look suspicious even without a signature match
# Each tuple is (condition_description, severity)
HEURISTIC_RULES = [
    # process name mimics a system process but has digits appended
    ("name_mimics_system", "HIGH"),
    # running from a temp or unusual directory
    ("running_from_temp", "HIGH"),
    # unusually high CPU with no window (possible background spy process)
    ("high_cpu_no_window", "MEDIUM"),
]

# How many risk points each severity level is worth
SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       5,
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4d",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#4caf50",
    "SAFE":     "#2ecc71",
}


# ==============================================================================
# SECTION 3 — DETECTION ENGINE
# ==============================================================================

class SpywareDetector:
    """
    The main scanning engine. Coordinates all scan modules and stores results
    in our custom data structures.
    """

    def __init__(self):
        self.threat_log = ThreatLinkedList()      # all threats found this session
        self.signatures = HashTable(capacity=128)  # signature lookup table
        self.scan_history = ScanHistoryStack(max_size=20)  # past scan summaries
        self._load_signatures()

    def _load_signatures(self):
        """Load all known malicious process names into the hash table for fast lookup."""
        for entry in MALICIOUS_PROCESSES:
            self.signatures.insert(entry["name"].lower(), entry)

    def _make_threat(self, name, severity, category, detail, pid=None):
        """Helper to build a consistent threat dictionary."""
        return {
            "name":      name,
            "severity":  severity,
            "category":  category,
            "detail":    detail,
            "pid":       pid,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _calculate_risk_score(self):
        """
        Add up severity weights for every threat we found, then cap at 100.
        This gives a simple 0-100 score of how risky the system looks.
        """
        total = sum(SEVERITY_WEIGHTS.get(t["severity"], 0) for t in self.threat_log)
        return min(total, 100)

    # --------------------------------------------------------------------------
    # Scan Module 1: Process Scanner
    # --------------------------------------------------------------------------

    def scan_processes(self):
        """
        Walk every running process and check its name against our signature hash table.
        Hash table lookup is O(1) average, so even with hundreds of processes this is fast.
        Also runs heuristic checks on each process.
        """
        found = []
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent",
                                             "memory_info", "num_handles"]):
                try:
                    name = (proc.info["name"] or "").lower()

                    # --- Signature check ---
                    match = self.signatures.lookup(name)
                    if match:
                        threat = self._make_threat(
                            name=name,
                            severity=match["severity"],
                            category=match["category"],
                            detail=match["detail"],
                            pid=proc.info["pid"]
                        )
                        self.threat_log.append(threat)
                        found.append(threat)
                        continue  # already flagged — skip heuristics for this one

                    # --- Heuristic checks ---
                    heuristic_hits = self._check_process_heuristics(proc, name)
                    for h in heuristic_hits:
                        self.threat_log.append(h)
                        found.append(h)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as err:
            print(f"[ERROR] Process scan: {err}")
        return found

    def _check_process_heuristics(self, proc, name):
        """
        Check a single process for suspicious behaviour patterns.
        These are heuristics — they might not be malware, but they look odd.
        Returns a list of threats (empty if nothing suspicious).
        """
        hits = []
        exe_path = ""
        try:
            exe_path = proc.exe() or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Heuristic 1: Name mimics a known Windows system process but adds digits or
        # common spoofing suffixes (e.g. 'svchost2.exe', 'svch0st.exe').
        # We only flag when the name is a clear near-clone of the exact system name,
        # NOT when a legitimate program just happens to contain the substring
        # (e.g. 'services_manager.exe' or 'file_explorer_helper.exe' are fine).
        system_names = ["svchost", "csrss", "lsass", "winlogon", "explorer",
                        "services", "smss", "wininit", "taskhost"]
        base_name = name.replace(".exe", "").replace(".com", "")
        for sys_name in system_names:
            # Only flag if the base name IS the system name plus trailing digits/symbols,
            # or a simple character-substitution variant (same length ±1, very similar).
            if base_name == sys_name:
                break   # exact match — totally legit, skip
            # Pattern: system name immediately followed by digits or common suffixes
            if re.fullmatch(rf"{re.escape(sys_name)}[\d_\-]+", base_name):
                hits.append(self._make_threat(
                    name=name,
                    severity="HIGH",
                    category="Heuristic",
                    detail=f"Name mimics system process '{sys_name}' — possible masquerading",
                    pid=proc.info.get("pid")
                ))
                break

        # Heuristic 2: Process is running from a temp folder
        # Legitimate software rarely runs directly from %TEMP% or /tmp
        temp_dirs = [os.environ.get("TEMP", ""), os.environ.get("TMP", ""),
                     "/tmp", "/var/tmp"]
        if exe_path and any(t and exe_path.lower().startswith(t.lower())
                            for t in temp_dirs if t):
            hits.append(self._make_threat(
                name=name,
                severity="HIGH",
                category="Heuristic",
                detail=f"Running from temp directory: {exe_path}",
                pid=proc.info.get("pid")
            ))

        # Heuristic 3: High CPU usage from a process with very few handles.
        # Keyloggers and RATs often run silently in the background burning CPU.
        # NOTE: psutil returns cpu_percent=0 on the very first call for a process
        # (it needs two samples), so we skip zero readings to avoid false positives.
        # num_handles is only meaningful on Windows; we skip this check on Linux/macOS.
        try:
            if platform.system() == "Windows":
                cpu = proc.info.get("cpu_percent") or 0
                num_handles = proc.info.get("num_handles") or 0
                if cpu > 30 and num_handles < 5:
                    hits.append(self._make_threat(
                        name=name,
                        severity="MEDIUM",
                        category="Heuristic",
                        detail=f"High CPU ({cpu:.1f}%) with very few handles — possible hidden process",
                        pid=proc.info.get("pid")
                    ))
        except Exception:
            pass

        return hits

    # --------------------------------------------------------------------------
    # Scan Module 2: Network Scanner
    # --------------------------------------------------------------------------

    def scan_network(self):
        """
        Look at every active network connection.
        Flags connections to known bad ports, and also flags unknown processes
        using port 80/443 — RATs often piggyback on HTTP/HTTPS to sneak past firewalls.
        """
        found = []
        # build a quick lookup dict from our suspicious ports list
        port_lookup = {e["port"]: e for e in SUSPICIOUS_PORTS}

        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr:
                    continue   # no remote address means it's just listening, skip it

                remote_port = conn.raddr.port
                remote_ip   = conn.raddr.ip
                pid         = conn.pid

                # get the process name for this connection if we can
                proc_name = ""
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                if remote_port in port_lookup:
                    entry = port_lookup[remote_port]
                    severity = entry["severity"]

                    # For ports 80/443: only flag if the process is NOT a known browser/app
                    # This avoids drowning the user in false positives from normal web browsing
                    if remote_port in (80, 443):
                        if proc_name in TRUSTED_NET_PROCESSES:
                            continue   # totally normal — skip
                        # Also skip if the process runs from a known system/program directory
                        try:
                            exe_path = psutil.Process(pid).exe().lower() if pid else ""
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            exe_path = ""
                        system_dirs = [
                            os.environ.get("WINDIR", "c:\\windows").lower(),
                            os.environ.get("PROGRAMFILES", "c:\\program files").lower(),
                            os.environ.get("PROGRAMFILES(X86)", "c:\\program files (x86)").lower(),
                            "/usr/bin", "/usr/lib", "/usr/local", "/opt",
                        ]
                        if exe_path and any(exe_path.startswith(d) for d in system_dirs if d):
                            continue   # running from a system location — skip
                        # unknown process using HTTP/HTTPS → worth flagging
                        severity = "MEDIUM"
                        detail   = f"Unknown process '{proc_name}' using port {remote_port} — RATs often tunnel through HTTP/HTTPS"
                    else:
                        detail = entry["detail"]

                    threat = self._make_threat(
                        name=f"{proc_name or 'unknown'} → {remote_ip}:{remote_port}",
                        severity=severity,
                        category="Suspicious Network",
                        detail=detail,
                        pid=pid
                    )
                    self.threat_log.append(threat)
                    found.append(threat)

        except (psutil.AccessDenied, PermissionError):
            # on Windows you often need admin rights for net_connections
            found.append(self._make_threat(
                name="Network Scan",
                severity="LOW",
                category="Warning",
                detail="Run as Administrator for a full network scan."
            ))
        except Exception as err:
            print(f"[ERROR] Network scan: {err}")

        return found

    # --------------------------------------------------------------------------
    # Scan Module 3: Persistence / Startup Scanner
    # --------------------------------------------------------------------------

    def scan_startup_entries(self):
        """
        Check startup locations for suspicious entries.
        """
        if platform.system() == "Windows":
            return self._scan_startup_windows()
        return self._scan_startup_unix()

    def _scan_startup_windows(self):
        """Scan Windows Registry Run keys for anything that looks out of place."""
        found = []
        try:
            import winreg
            # both HKCU and HKLM can have startup entries
            hives = [
                (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hive, path in hives:
                try:
                    key = winreg.OpenKey(hive, path)
                    i = 0
                    while True:
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, i)
                            for pattern in SUSPICIOUS_STARTUP_PATTERNS:
                                if pattern.lower() in val_name.lower():
                                    threat = self._make_threat(
                                        name=val_name,
                                        severity="HIGH",
                                        category="Suspicious Startup",
                                        detail=f"Matches pattern '{pattern}': {val_data}"
                                    )
                                    self.threat_log.append(threat)
                                    found.append(threat)
                                    break
                            i += 1
                        except OSError:
                            break   # no more values in this key
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        except ImportError:
            pass   # not on Windows
        return found

    def _scan_startup_unix(self):
        """Scan Linux/macOS autostart directories."""
        found = []
        autostart_dirs = [
            os.path.expanduser("~/.config/autostart"),
            "/etc/init.d",
            "/etc/rc.local",
        ]
        for folder in autostart_dirs:
            if not os.path.isdir(folder):
                continue
            for fname in os.listdir(folder):
                for pattern in SUSPICIOUS_STARTUP_PATTERNS:
                    if pattern.lower() in fname.lower():
                        threat = self._make_threat(
                            name=fname,
                            severity="MEDIUM",
                            category="Suspicious Startup",
                            detail=f"Pattern '{pattern}' found in {folder}"
                        )
                        self.threat_log.append(threat)
                        found.append(threat)
                        break
        return found

    # --------------------------------------------------------------------------
    # Scan Module 4: File System Scanner
    # --------------------------------------------------------------------------

    def scan_sensitive_files(self):
        """
        Look in common spyware drop locations for files with suspicious extensions.
        We limit depth to 2 folders deep so this doesn't take forever.
        """
        found = []
        # common places spyware drops its log files
        scan_dirs = [
            os.path.expanduser("~"),
            os.environ.get("TEMP", "/tmp"),
            os.environ.get("APPDATA", ""),
        ]
        for base in scan_dirs:
            if not base or not os.path.isdir(base):
                continue
            for root, subdirs, files in os.walk(base):
                # stop going deeper than 2 levels
                depth = root[len(base):].count(os.sep)
                if depth > 2:
                    subdirs.clear()
                    continue
                for fname in files:
                    _, ext = os.path.splitext(fname)
                    if ext.lower() in SUSPICIOUS_FILE_EXTENSIONS:
                        full_path = os.path.join(root, fname)
                        threat = self._make_threat(
                            name=fname,
                            severity="HIGH",
                            category="Suspicious File",
                            detail=f"Extension '{ext}' found at {full_path}"
                        )
                        self.threat_log.append(threat)
                        found.append(threat)
        return found

    # --------------------------------------------------------------------------
    # Full Scan Orchestrator
    # --------------------------------------------------------------------------

    def run_full_scan(self, progress_callback=None):
        """
        Run all four scan modules in sequence and combine the results.
        progress_callback(step, total, message) is called before each step so the GUI
        can update its progress bar.
        """
        self.threat_log.clear()

        results = {
            "processes":    [],
            "network":      [],
            "startup":      [],
            "files":        [],
            "risk_score":   0,
            "total_threats": 0,
            "scan_time":    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        steps = [
            ("Scanning running processes + heuristics…", "processes", self.scan_processes),
            ("Scanning network connections…",            "network",   self.scan_network),
            ("Scanning startup / persistence entries…",  "startup",   self.scan_startup_entries),
            ("Scanning file system for spy files…",      "files",     self.scan_sensitive_files),
        ]

        for i, (msg, key, scan_fn) in enumerate(steps):
            if progress_callback:
                progress_callback(i, len(steps), msg)
            results[key] = scan_fn()

        results["risk_score"]    = self._calculate_risk_score()
        results["total_threats"] = len(self.threat_log)

        # save a summary in our history stack
        self.scan_history.push({
            "scan_time":     results["scan_time"],
            "total_threats": results["total_threats"],
            "risk_score":    results["risk_score"],
        })

        if progress_callback:
            progress_callback(len(steps), len(steps), "Scan complete.")

        return results


# ==============================================================================
# SECTION 4 — Applying Tkinter
# ==============================================================================

# Dark theme colours
PALETTE = {
    "bg":       "#0d1117",
    "surface":  "#161b22",
    "border":   "#30363d",
    "accent":   "#58a6ff",
    "text":     "#e6edf3",
    "subtext":  "#8b949e",
    "critical": "#ff4d4d",
    "high":     "#ff8c00",
    "medium":   "#ffd700",
    "low":      "#4caf50",
    "safe":     "#2ecc71",
}


class SpyShieldApp(tk.Tk):
    """Main Tkinter Window"""

    def __init__(self):
        super().__init__()
        self.detector     = SpywareDetector()
        self.scan_results = {}
        self._setup_window()
        self._setup_styles()
        self._build_ui()

    # Window and style setup
    def _setup_window(self):
        self.title("Spyware Detection")
        self.geometry("1100x750")
        self.minsize(900, 600)
        self.configure(bg=PALETTE["bg"])

    #Configure all the ttk styles.
    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        s.configure("TNotebook",      background=PALETTE["bg"], borderwidth=0)
        s.configure("TNotebook.Tab",  background=PALETTE["surface"],
                    foreground=PALETTE["subtext"], padding=[16, 8],
                    font=("Consolas", 10))
        s.map("TNotebook.Tab",
              background=[("selected", PALETTE["accent"])],
              foreground=[("selected", "#ffffff")])

        s.configure("Dark.TFrame",    background=PALETTE["bg"])
        s.configure("Surface.TFrame", background=PALETTE["surface"])

        s.configure("Accent.TButton", background=PALETTE["accent"],
                    foreground="#ffffff", font=("Consolas", 11, "bold"),
                    padding=[20, 10], relief="flat")
        s.map("Accent.TButton",
              background=[("active", "#79b8ff"), ("pressed", "#388bfd")])

        s.configure("Outline.TButton", background=PALETTE["surface"],
                    foreground=PALETTE["accent"], font=("Consolas", 10),
                    padding=[12, 6], relief="flat")

        s.configure("Scan.Horizontal.TProgressbar",
                    troughcolor=PALETTE["surface"],
                    background=PALETTE["accent"], thickness=8)

        s.configure("Main.Treeview", background=PALETTE["surface"],
                    foreground=PALETTE["text"], fieldbackground=PALETTE["surface"],
                    rowheight=28, font=("Consolas", 10))
        s.configure("Main.Treeview.Heading", background=PALETTE["border"],
                    foreground=PALETTE["text"], font=("Consolas", 10, "bold"))
        s.map("Main.Treeview",
              background=[("selected", PALETTE["accent"])],
              foreground=[("selected", "#ffffff")])

    # Building User Interface
    def _build_ui(self):
        self._build_header()
        self._build_notebook()
        self._build_status_bar()

    def _build_header(self):
        """Top bar with logo, subtitle, and the main action buttons."""
        header = tk.Frame(self, bg=PALETTE["bg"], pady=16)
        header.pack(fill="x", padx=24)

        # left side: branding
        left = tk.Frame(header, bg=PALETTE["bg"])
        left.pack(side="left")
        tk.Label(left, text="Spyware Detector", bg=PALETTE["bg"],
                 fg=PALETTE["accent"], font=("Consolas", 22, "bold")).pack(anchor="w")
        tk.Label(left, text="Developed by Aayush Kadel for Educational Purpose.",
                 bg=PALETTE["bg"], fg=PALETTE["subtext"],
                 font=("Consolas", 10)).pack(anchor="w")

        # right side: action buttons
        right = tk.Frame(header, bg=PALETTE["bg"])
        right.pack(side="right")
        ttk.Button(right, text="⟳  Full Scan", style="Accent.TButton",
                   command=self._start_full_scan).pack(side="right", padx=(8, 0))
        ttk.Button(right, text="💾  Export Report", style="Outline.TButton",
                   command=self._export_report).pack(side="right")

        # thin divider line
        tk.Frame(self, bg=PALETTE["border"], height=1).pack(fill="x")

    def _build_notebook(self):
        """Create the tab container and add all tabs to it."""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        self._build_dashboard_tab()
        self._build_threats_tab()
        self._build_processes_tab()
        self._build_network_tab()
        self._build_history_tab()
        self._build_about_tab()

    def _build_status_bar(self):
        """Bottom bar with a status message and a scan progress bar."""
        bar = tk.Frame(self, bg=PALETTE["surface"], pady=4)
        bar.pack(fill="x", side="bottom")

        self.status_var = tk.StringVar(value="Ready. Press 'Full Scan' to begin.")
        tk.Label(bar, textvariable=self.status_var, bg=PALETTE["surface"],
                 fg=PALETTE["subtext"], font=("Consolas", 9),
                 anchor="w").pack(side="left", padx=12)

        self.progress = ttk.Progressbar(bar, style="Scan.Horizontal.TProgressbar",
                                        length=200, mode="determinate")
        self.progress.pack(side="right", padx=12)

    # --------------------------------------------------------------------------
    # Tabs
    # --------------------------------------------------------------------------

    def _build_dashboard_tab(self):
        """Overview tab: metric cards, risk bar, and usage instructions."""
        frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(frame, text="  Dashboard  ")

        # top row of summary cards
        cards_row = tk.Frame(frame, bg=PALETTE["bg"])
        cards_row.pack(fill="x", padx=24, pady=(20, 12))

        self.card_vars = {}
        card_defs = [
            ("risk_score",    "Risk Score",      "0 / 100", PALETTE["accent"]),
            ("total_threats", "Total Threats",   "0",       PALETTE["critical"]),
            ("processes",     "Process Hits",    "0",       PALETTE["high"]),
            ("network",       "Network Hits",    "0",       PALETTE["medium"]),
        ]
        for key, label, default, color in card_defs:
            card = tk.Frame(cards_row, bg=PALETTE["surface"], padx=20, pady=16)
            card.pack(side="left", expand=True, fill="x", padx=(0, 12))
            tk.Label(card, text=label, bg=PALETTE["surface"],
                     fg=PALETTE["subtext"], font=("Consolas", 9)).pack(anchor="w")
            var = tk.StringVar(value=default)
            self.card_vars[key] = var
            tk.Label(card, textvariable=var, bg=PALETTE["surface"],
                     fg=color, font=("Consolas", 22, "bold")).pack(anchor="w")

        # risk score progress bar
        gauge = tk.Frame(frame, bg=PALETTE["surface"], padx=24, pady=20)
        gauge.pack(fill="x", padx=24, pady=(0, 12))
        tk.Label(gauge, text="System Risk Level", bg=PALETTE["surface"],
                 fg=PALETTE["text"], font=("Consolas", 12, "bold")).pack(anchor="w")
        self.risk_bar = ttk.Progressbar(gauge, length=600, maximum=100,
                                        mode="determinate",
                                        style="Scan.Horizontal.TProgressbar")
        self.risk_bar.pack(fill="x", pady=(8, 4))
        self.risk_label = tk.Label(gauge, text="No scan run yet.",
                                   bg=PALETTE["surface"], fg=PALETTE["subtext"],
                                   font=("Consolas", 10))
        self.risk_label.pack(anchor="w")

    def _build_threats_tab(self):
        """Threats tab: filterable table of everything that was detected."""
        frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(frame, text="  Threats  ")

        hdr = tk.Frame(frame, bg=PALETTE["bg"], pady=12)
        hdr.pack(fill="x", padx=24)
        tk.Label(hdr, text="Detected Threats", bg=PALETTE["bg"],
                 fg=PALETTE["text"], font=("Consolas", 14, "bold")).pack(side="left")
        ttk.Button(hdr, text="Clear", style="Outline.TButton",
                   command=self._clear_threats).pack(side="right")

        # severity filter radio buttons
        flt = tk.Frame(frame, bg=PALETTE["bg"])
        flt.pack(fill="x", padx=24, pady=(0, 8))
        tk.Label(flt, text="Filter:", bg=PALETTE["bg"],
                 fg=PALETTE["subtext"], font=("Consolas", 9)).pack(side="left")
        self.severity_filter = tk.StringVar(value="ALL")
        for sev in ("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"):
            ttk.Radiobutton(flt, text=sev, variable=self.severity_filter,
                            value=sev,
                            command=self._refresh_threats_table).pack(side="left", padx=6)

        # main threats table
        cols = ("Severity", "Category", "Name", "Detail", "PID", "Time")
        self.threats_tree = ttk.Treeview(frame, columns=cols,
                                         show="headings", style="Main.Treeview")
        for col, width in zip(cols, (90, 120, 200, 340, 60, 140)):
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=width, anchor="w")
        # colour each row by severity
        for sev, color in SEVERITY_COLORS.items():
            self.threats_tree.tag_configure(sev, foreground=color)

        sb = ttk.Scrollbar(frame, orient="vertical",
                           command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=sb.set)
        self.threats_tree.pack(side="left", fill="both", expand=True,
                               padx=(24, 0), pady=(0, 16))
        sb.pack(side="right", fill="y", pady=(0, 16), padx=(0, 8))

    def _build_processes_tab(self):
        """Processes tab: live list of all running processes, with suspicious ones highlighted."""
        frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(frame, text="  Processes  ")

        hdr = tk.Frame(frame, bg=PALETTE["bg"], pady=12)
        hdr.pack(fill="x", padx=24)
        tk.Label(hdr, text="Running Processes", bg=PALETTE["bg"],
                 fg=PALETTE["text"], font=("Consolas", 14, "bold")).pack(side="left")
        ttk.Button(hdr, text="↻ Refresh", style="Outline.TButton",
                   command=self._refresh_process_list).pack(side="right")

        cols = ("PID", "Name", "CPU %", "Memory MB", "Status", "User")
        self.proc_tree = ttk.Treeview(frame, columns=cols,
                                      show="headings", style="Main.Treeview")
        for col, width in zip(cols, (70, 200, 80, 100, 90, 150)):
            self.proc_tree.heading(col, text=col)
            self.proc_tree.column(col, width=width, anchor="w")
        self.proc_tree.tag_configure("suspicious", foreground=PALETTE["critical"])

        sb = ttk.Scrollbar(frame, orient="vertical", command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=sb.set)
        self.proc_tree.pack(side="left", fill="both", expand=True,
                            padx=(24, 0), pady=(0, 16))
        sb.pack(side="right", fill="y", pady=(0, 16), padx=(0, 8))
        self._refresh_process_list()

    def _build_network_tab(self):
        """Network tab: all active connections with suspicious ones flagged."""
        frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(frame, text="  Network  ")

        hdr = tk.Frame(frame, bg=PALETTE["bg"], pady=12)
        hdr.pack(fill="x", padx=24)
        tk.Label(hdr, text="Active Network Connections", bg=PALETTE["bg"],
                 fg=PALETTE["text"], font=("Consolas", 14, "bold")).pack(side="left")
        ttk.Button(hdr, text="↻ Refresh", style="Outline.TButton",
                   command=self._refresh_network_list).pack(side="right")

        cols = ("PID", "Process", "Local Address", "Remote Address", "Status", "Flag")
        self.net_tree = ttk.Treeview(frame, columns=cols,
                                     show="headings", style="Main.Treeview")
        for col, width in zip(cols, (60, 140, 180, 200, 90, 120)):
            self.net_tree.heading(col, text=col)
            self.net_tree.column(col, width=width, anchor="w")
        self.net_tree.tag_configure("suspicious", foreground=PALETTE["critical"])
        self.net_tree.tag_configure("warning",    foreground=PALETTE["medium"])

        sb = ttk.Scrollbar(frame, orient="vertical", command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=sb.set)
        self.net_tree.pack(side="left", fill="both", expand=True,
                           padx=(24, 0), pady=(0, 16))
        sb.pack(side="right", fill="y", pady=(0, 16), padx=(0, 8))
        self._refresh_network_list()

    def _build_history_tab(self):
        """History tab: previous scan summaries stored in our ScanHistoryStack."""
        frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(frame, text="  History  ")

        tk.Label(frame, text="Scan History (most recent first)",
                 bg=PALETTE["bg"], fg=PALETTE["text"],
                 font=("Consolas", 14, "bold")).pack(anchor="w", padx=24, pady=12)

        cols = ("#", "Scan Time", "Threats Found", "Risk Score")
        self.history_tree = ttk.Treeview(frame, columns=cols,
                                         show="headings", style="Main.Treeview")
        for col in cols:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=180, anchor="w")
        self.history_tree.pack(fill="both", expand=True, padx=24, pady=(0, 16))

    def _build_about_tab(self):
        """About tab: brief description of how the tool works."""
        frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(frame, text="  About  ")

        card = tk.Frame(frame, bg=PALETTE["surface"], padx=40, pady=32)
        card.pack(fill="both", expand=True, padx=40, pady=30)

        tk.Label(card, text="Spyware Detector", bg=PALETTE["surface"],
                 fg=PALETTE["accent"], font=("Consolas", 24, "bold")).pack(anchor="w")
        tk.Label(card, text="Aayush Kadel",
                 bg=PALETTE["surface"], fg=PALETTE["subtext"],
                 font=("Consolas", 10)).pack(anchor="w", pady=(4, 24))
        tk.Label(card, text=(
            "Detection Modules:\n"
            "  • Process Scanner    — signature matching via HashTable (O(1) avg lookup)\n"
            "  • Heuristics Engine  — flags masquerading names, temp-dir processes, silent high-CPU\n"
            "  • Network Monitor    — flags C2 ports + unknown processes on port 80/443 (RAT tunneling)\n"
            "  • Startup Auditor    — checks Registry / autostart for persistence mechanisms\n"
            "  • File System Watch  — scans drop locations for spyware file extensions\n\n"
            "Custom Data Structures:\n"
            "  • HashTable          — DJB2 hashing, separate chaining, O(1) avg lookup\n"
            "  • ThreatLinkedList   — singly-linked list, O(1) append, ordered threat log\n"
            "  • ScanHistoryStack   — bounded LIFO stack, auto-evicts oldest scan summary\n\n"
            "Disclaimer: Educational use only. Scans local host only."
        ), bg=PALETTE["surface"], fg=PALETTE["text"],
           font=("Consolas", 10), justify="left").pack(anchor="w")

    # --------------------------------------------------------------------------
    # Actions / event handlers
    # --------------------------------------------------------------------------

    def _start_full_scan(self):
        """Kick off a full scan in a background thread so the GUI stays responsive."""
        self.status_var.set("Scanning… please wait.")
        self.progress["value"] = 0

        def on_progress(step, total, msg):
            # update progress bar — called from background thread, so we push to main thread
            pct = int((step / total) * 100) if total else 0
            self.progress["value"] = pct
            self.status_var.set(msg)
            self.update_idletasks()

        def run_scan():
            results = self.detector.run_full_scan(on_progress)
            # update the GUI back on the main thread
            self.after(0, lambda: self._on_scan_complete(results))

        threading.Thread(target=run_scan, daemon=True).start()

    def _on_scan_complete(self, results):
        """Called after the scan finishes — updates all GUI elements with the new results."""
        # update dashboard cards
        self.card_vars["risk_score"].set(f"{results['risk_score']} / 100")
        self.card_vars["total_threats"].set(str(results["total_threats"]))
        self.card_vars["processes"].set(str(len(results["processes"])))
        self.card_vars["network"].set(str(len(results["network"])))

        # pick a colour for the risk bar based on the actual highest severity found
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severities_found = {t.get("severity") for t in self.detector.threat_log}
        highest = next((s for s in severity_order if s in severities_found), None)

        if highest == "CRITICAL":
            bar_color, label = PALETTE["critical"], "CRITICAL"
        elif highest == "HIGH":
            bar_color, label = PALETTE["high"],     "High"
        elif highest == "MEDIUM":
            bar_color, label = PALETTE["medium"],   "Medium"
        elif highest == "LOW":
            bar_color, label = PALETTE["low"],      "Low"
        else:
            bar_color, label = PALETTE["safe"],     "Low"

        score = results["risk_score"]
        self.risk_bar["value"] = score
        self.risk_label.config(
            text=f"Score: {score}/100 — {label}",
            fg=bar_color
        )

        # refresh all the data tables
        self._refresh_threats_table()
        self._refresh_history_table()

        self.progress["value"] = 100
        self.status_var.set(
            f"Scan complete — {results['total_threats']} threat(s) found. "
            f"Risk score: {results['risk_score']}/100."
        )

        # pop-up summary
        if results["total_threats"] > 0:
            messagebox.showwarning(
                "Threats Detected",
                f"Found {results['total_threats']} threat(s).\n"
                f"Risk Score: {results['risk_score']}/100\n\n"
                "See the 'Threats' tab for details."
            )
        else:
            messagebox.showinfo("Scan Complete",
                                "No threats detected. System appears clean.")

    def _refresh_threats_table(self):
        """Repopulate the threats table, applying the current severity filter."""
        for row in self.threats_tree.get_children():
            self.threats_tree.delete(row)

        active_filter = self.severity_filter.get()
        for threat in self.detector.threat_log:
            sev = threat.get("severity", "LOW")
            if active_filter != "ALL" and sev != active_filter:
                continue
            self.threats_tree.insert("", "end", tags=(sev,), values=(
                sev,
                threat.get("category"),
                threat.get("name"),
                threat.get("detail"),
                threat.get("pid", "—"),
                threat.get("timestamp"),
            ))

    def _refresh_process_list(self):
        """Reload the live process list and flag any that match known signatures."""
        for row in self.proc_tree.get_children():
            self.proc_tree.delete(row)

        for proc in psutil.process_iter(["pid", "name", "cpu_percent",
                                         "memory_info", "status", "username"]):
            try:
                info = proc.info
                name = info.get("name") or ""
                mem_mb = round(info["memory_info"].rss / 1024 / 1024, 1) \
                         if info.get("memory_info") else 0
                is_sus = self.detector.signatures.lookup(name.lower()) is not None
                self.proc_tree.insert("", "end",
                    tags=("suspicious",) if is_sus else (),
                    values=(
                        info.get("pid"),
                        name,
                        info.get("cpu_percent", 0.0),
                        mem_mb,
                        info.get("status"),
                        info.get("username"),
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _refresh_network_list(self):
        """Reload the network connections table and flag suspicious ones."""
        for row in self.net_tree.get_children():
            self.net_tree.delete(row)

        sus_ports     = {e["port"] for e in SUSPICIOUS_PORTS}
        web_ports     = {80, 443}

        try:
            for conn in psutil.net_connections(kind="inet"):
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

                # try to find out which process owns this connection
                proc_name = ""
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                remote_port = conn.raddr.port if conn.raddr else None
                if remote_port in sus_ports:
                    if remote_port in web_ports and proc_name.lower() in TRUSTED_NET_PROCESSES:
                        flag = "OK"
                        tag  = ()
                    elif remote_port in web_ports:
                        flag = "⚠ UNKNOWN ON 80/443"
                        tag  = ("warning",)
                    else:
                        flag = "⚠ SUSPICIOUS"
                        tag  = ("suspicious",)
                else:
                    flag = "OK"
                    tag  = ()

                self.net_tree.insert("", "end", tags=tag, values=(
                    conn.pid or "", proc_name, laddr, raddr, conn.status, flag
                ))

        except (psutil.AccessDenied, PermissionError):
            self.net_tree.insert("", "end",
                values=("", "Access Denied", "Run as Administrator", "", "", ""))

    def _refresh_history_table(self):
        """Repopulate the scan history table from our ScanHistoryStack."""
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)

        for i, entry in enumerate(self.detector.scan_history.to_list(), 1):
            self.history_tree.insert("", "end", values=(
                i,
                entry["scan_time"],
                entry["total_threats"],
                f"{entry['risk_score']}/100",
            ))

    def _clear_threats(self):
        """Wipe the current threat log and reset the table."""
        self.detector.threat_log.clear()
        self._refresh_threats_table()
        self.card_vars["total_threats"].set("0")
        self.status_var.set("Threat log cleared.")

    def _export_report(self):
        """Save all detected threats to a CSV file."""
        if len(self.detector.threat_log) == 0:
            messagebox.showinfo("Export", "No threats to export. Run a scan first.")
            return

        filename = f"scanreport.csv"
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            initialfile=filename
        )
        if not path:
            return   # user cancelled

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["name", "severity", "category", "detail", "pid", "timestamp"])
            writer.writeheader()
            for threat in self.detector.threat_log:
                writer.writerow(threat)

        messagebox.showinfo("Exported", f"Report saved to:\n{path}")
        self.status_var.set(f"Report exported → {path}")

#Entry-Points
if __name__ == "__main__":
    app = SpyShieldApp()
    app.mainloop()
