import os
import hashlib
import mimetypes
from datetime import datetime
import math

# Optional dependency for advanced PE analysis
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

class MalwareScanner:
    def __init__(self):
        # ─── 1. SIGNATURE DATABASE ────────────────────────────────────────────
        self.malware_signatures = [
            # EICAR Standard Test (Must be first for testing)
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            
            # Common shell injection / backdoor patterns
            b"eval(base64_decode(", b"exec(base64_decode(", b"system($_GET",
            b"system($_POST", b"passthru($_GET", b"passthru($_POST",
            b"shell_exec($_GET", b"shell_exec($_POST", b"<?php eval(",
            b"<?php system(", b"preg_replace('/.*/e", b"assert($_GET",
            b"assert($_POST", b"call_user_func_array(base64",
            
            # Python backdoor patterns
            b"import socket;s=socket.socket(", b"exec(compile(base64",
            b"__import__('os').system(", b"subprocess.Popen(['/bin/sh'",
            b"os.system('nc ",
            
            # Ransomware markers
            b"YOUR FILES HAVE BEEN ENCRYPTED", b"All your files are encrypted",
            b"bitcoin payment", b"RANSOM", b"decrypt your files",
            
            # Windows malware patterns
            b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
            b"cmd.exe /c powershell", b"powershell -enc ", b"powershell -EncodedCommand",
            b"powershell -w hidden", b"net user /add",
            b"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            
            # Rootkit / privilege escalation
            b"chmod 777 /etc/passwd", b"echo root::0:0:",
            b"/bin/bash -i >& /dev/tcp/", b"bash -i >& /dev/tcp/",
            b"0<&196;exec 196<>/dev/tcp/",
            
            # Crypto miner markers
            b"stratum+tcp://", b"cryptonight", b"monero", b"xmrig",
            b"pool.minexmr.com", b"minexmr.com:4444",
            
            # JavaScript malware
            b"document.write(unescape('%3C%73%63%72%69%70%74",
            b"String.fromCharCode(118,97,114", b"<script>eval(atob(",
            b"fromCharCode(104,116,116,112",
            
            # Trojan / spyware patterns
            b"keylogger", b"GetAsyncKeyState", b"SetWindowsHookEx",
            b"WH_KEYBOARD_LL",
            
            # SQL injection patterns in files
            b"UNION SELECT NULL,NULL,NULL", b"1=1--", b"OR 1=1", b"DROP TABLE",
        ]

        # ─── 2. SAFE DIRECTORIES (AUDITED) ────────────────────────────────────
        self.safe_directories = [
            ".git", "node_modules", "venv", "__pycache__",
            "dart-sdk", "flutter", ".gradle", ".idea", ".vscode"
        ]

        # ─── 3. SAFE EXTENSIONS (AUDITED) ─────────────────────────────────────
        self.safe_extensions = [
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
            '.mp4', '.mp3', '.wav', '.avi', '.mkv', '.mov', '.flv', '.wmv',
            '.ttf', '.otf', '.woff', '.woff2',
            '.pyc', '.class', '.o', '.obj'
        ]
        
        # ─── 4. BEHAVIORAL INDICATORS (API Calls) ─────────────────────────────
        self.suspicious_apis = {
            # Low Risk (1 point)
            b"OpenProcess": 1, b"ReadProcessMemory": 1, 
            b"GetForegroundWindow": 1, b"CreateProcessA": 1, b"CreateProcessW": 1,
            
            # Medium Risk (2 points)
            b"VirtualAlloc": 2, b"InternetOpenA": 2, b"InternetOpenUrlA": 2,
            b"HttpSendRequestA": 2, b"ShellExecuteA": 2, b"WinExec": 2,
            b"RegCreateKeyExA": 2, b"RegSetValueExA": 2,
            
            # High Risk (3 points)
            b"WriteProcessMemory": 3, b"GetAsyncKeyState": 3, 
            b"SetWindowsHookExA": 3, b"URLDownloadToFileA": 3,
            b"IsDebuggerPresent": 3, b"CheckRemoteDebuggerPresent": 3,
            
            # Critical Risk (4 points)
            b"CreateRemoteThread": 4, 
        }

        # ─── 5. SEVERITY MAPPING ──────────────────────────────────────────────
        self.signature_severity = { 0: "CRITICAL" } # Default mapping

    def compute_hash(self, file_path):
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception:
            return "N/A", "N/A"

    def get_file_metadata(self, file_path):
        try:
            stat = os.stat(file_path)
            size_bytes = stat.st_size
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes / 1024:.1f} KB"
            else:
                size_str = f"{size_bytes / (1024*1024):.2f} MB"

            mime_type, _ = mimetypes.guess_type(file_path)
            return {
                "size": size_str,
                "size_bytes": size_bytes,
                "mime_type": mime_type or "application/octet-stream",
                "extension": os.path.splitext(file_path)[1].lower() or "none",
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        except Exception:
            return {"size": "N/A", "size_bytes": 0, "mime_type": "unknown",
                    "extension": "N/A", "modified": "N/A"}

    def calculate_entropy(self, data):
        """Calculate Shannon Entropy (0.0 - 8.0). High (>7.2) = Packing/Encryption."""
        if not data: return 0.0
        entropy = 0
        byte_counts = [0] * 256
        for byte in data: byte_counts[byte] += 1
        total_bytes = len(data)
        for count in byte_counts:
            if count == 0: continue
            p = count / total_bytes
            entropy -= p * math.log2(p)
        return entropy

    def is_safe_path(self, file_path):
        if not os.path.isfile(file_path): return True
        # Normalize
        npath = os.path.normpath(file_path.lower())
        for safe_dir in self.safe_directories:
             # Ensure directory match
             if os.sep + safe_dir.lower() + os.sep in npath:
                 return True
        if any(file_path.lower().endswith(ext) for ext in self.safe_extensions):
            return True
        return False
        
    def check_pe_headers(self, file_path):
        """Analyze PE Import Table for suspicious API calls. Returns (Score, List of APIs)."""
        if not PEFILE_AVAILABLE:
            return 0, []
        
        score = 0
        found_apis = []
        try:
            pe = pefile.PE(file_path, fast_load=True)
            # Implied parse of data directories
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if not imp or not imp.name: continue
                        api_name = imp.name
                        if api_name in self.suspicious_apis:
                            weight = self.suspicious_apis[api_name]
                            decoded_name = api_name.decode()
                            if decoded_name not in found_apis: # Count unique APIs only
                                score += weight
                                found_apis.append(decoded_name)
        except Exception:
             pass
        return score, found_apis

    def scan_file(self, file_path):
        # 1. Start with clean slate
        md5, sha256 = self.compute_hash(file_path)
        metadata = self.get_file_metadata(file_path)
        
        result_base = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'is_malicious': False,
            'threat_name': None,
            'severity': None,
            'md5': md5,
            'sha256': sha256,
            'metadata': metadata,
            'entropy': 0.0,
            'scanned_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # 2. Exclusions
        if self.is_safe_path(file_path):
            return result_base

        # 3. Read Content
        try:
            file_size = os.path.getsize(file_path)
            MAX_SCAN_SIZE = 100 * 1024 * 1024 # 100MB Safety Cap for Signatures
            
            with open(file_path, "rb") as f:
                if file_size > MAX_SCAN_SIZE:
                    content_head = f.read(10 * 1024 * 1024)
                    try: 
                        f.seek(-1024 * 1024, 2)
                        content_tail = f.read()
                    except: 
                        content_tail = b""
                    chunks = [content_head, content_tail]
                    entropy_data = content_head
                else:
                    content = f.read()
                    chunks = [content]
                    entropy_data = content

            # A. Entropy Check
            entropy = self.calculate_entropy(entropy_data)
            result_base['entropy'] = round(entropy, 3)
            metadata['entropy'] = round(entropy, 3)

            # B. Signature Scanning
            for content in chunks:
                for idx, sig in enumerate(self.malware_signatures):
                    if sig in content:
                        result_base.update({
                            'is_malicious': True,
                            'threat_name': f"Signature-{idx:03d}",
                            'severity': self.signature_severity.get(idx, "HIGH")
                        })
                        if b"EICAR" in sig:
                             result_base['threat_name'] = "EICAR-Test-Signature"
                             result_base['severity'] = "CRITICAL"
                        return result_base
            
            # C. Heuristic: PE Header Analysis (Behavioral)
            # Only for executables
            if PEFILE_AVAILABLE and file_path.lower().endswith(('.exe', '.dll', '.sys')):
                 pe_score, apis = self.check_pe_headers(file_path)
                 if pe_score >= 6: # Threshold for malicious behavior
                      api_summary = ", ".join(apis[:3]) # Show top 3 suspicious APIs
                      result_base.update({
                          'is_malicious': True,
                          'threat_name': f"Heuristic:SuspiciousBehavior (Score={pe_score}) [{api_summary}...]",
                          'severity': "HIGH" if pe_score > 10 else "MEDIUM"
                      })
                      return result_base
            
            # D. Heuristic: High Entropy (Packed Code)
            # Trigger only if NO signature match and NO PE threat found yet
            SUSPICIOUS_EXTS = ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.scr']
            is_suspicious_type = any(file_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTS)
            
            if entropy > 7.5 and is_suspicious_type:
                result_base.update({
                    'is_malicious': True, # Flag as heuristic threat
                    'threat_name': "Heuristic:HighEntropy (Packed/Obfuscated)",
                    'severity': "MEDIUM"
                })

        except Exception:
            pass

        return result_base