import os

class MalwareScanner:
    def __init__(self):
        self.malware_signatures = [
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        ]
        
        self.safe_directories = [
            "flutter", "node_modules", "Program Files", "Windows\\System32",
            ".git", "venv", "__pycache__", "dart-sdk", "cache", "artifacts"
        ]
        
        self.safe_extensions = [
            '.md', '.txt', '.json', '.yaml', '.yml', '.xml', '.dart', '.wasm',
            '.otf', '.ttf', '.pdb', '.snapshot', '.map', '.css', '.html', '.js'
        ]
    
    def is_malicious_file(self, file_path):
        if not os.path.isfile(file_path) or ".." in file_path:
            return False
            
        for safe_dir in self.safe_directories:
            if safe_dir.lower() in file_path.lower():
                return False
                
        if any(file_path.lower().endswith(ext) for ext in self.safe_extensions):
            return False
            
        if 'codepoints' in os.path.basename(file_path).lower():
            return False
            
        try:
            with open(file_path, "rb") as file:
                chunk_size = 8192
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    for signature in self.malware_signatures:
                        if signature in chunk:
                            return True
            return False
        except:
            return False
    
    def scan_file(self, file_path):
        return {
            'file_path': file_path,
            'is_malicious': self.is_malicious_file(file_path),
            'file_name': os.path.basename(file_path)
        }
    
    def scan_directory(self, directory, callback=None):
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                result = self.scan_file(file_path)
                if callback:
                    callback(result)
                yield result