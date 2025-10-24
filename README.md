# 🛡️ Python Antivirus Scanner

A modern, GUI-based antivirus scanner built with Python and Tkinter. Features real-time scanning, threat detection, and user-friendly virus management with confirmation dialogs.

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## 📋 Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Usage](#-usage)
- [File Structure](#-file-structure)
- [How It Works](#-how-it-works)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔍 **Scanning Capabilities**
- **Single File Scan** - Upload and scan individual files
- **Directory Scan** - Recursive scanning of entire folders
- **Quick Scan** - Fast scan of common locations (Desktop, Downloads, Temp)
- **Real-time Progress** - Live progress bars and status updates

### 🦠 **Threat Detection**
- **Malware Signature Detection** - Identifies known malware patterns
- **EICAR Test File Support** - Standard antivirus test file detection
- **False Positive Prevention** - Smart filtering for development files
- **Safe Directory Whitelisting** - Skips system and development folders

### 🎨 **User Interface**
- **Modern Dark Theme** - Professional and easy on the eyes
- **Responsive Design** - Threaded operations keep UI smooth
- **Color-coded Results** - Red highlights for threats, green for clean files
- **Real-time Statistics** - Live count of scanned files and threats

### ⚠️ **Virus Management**
- **Confirmation Dialogs** - Always asks before deleting files
- **Single File Confirmation** - Detailed popup for individual threats
- **Batch Confirmation** - Manage multiple threats at once
- **Safe Deletion** - Proper error handling and user feedback

### 🧹 **Additional Tools**
- **Temp File Cleaner** - Remove temporary files safely
- **Detailed Logging** - Timestamped scan results
- **Cross-platform** - Works on Windows, Linux, and macOS

## 📸 Screenshots

### Main Interface
```
🛡️ Python Antivirus Scanner
┌─────────────────────────────────────────┐
│  📁 Scan Single File  │  📂 Scan Directory │
│  🔍 Quick Scan       │  🧹 Clean Temp Files │
├─────────────────────────────────────────┤
│ ████████████████████ Scanning...        │
│ Status: Scanning file.exe               │
├─────────────────────────────────────────┤
│ Scan Results:                           │
│ [17:30:15] ✅ Clean: document.pdf       │
│ [17:30:16] ⚠️ THREAT: malware.exe       │
│ [17:30:17] ✅ Clean: image.jpg          │
├─────────────────────────────────────────┤
│ Files: 156 | Threats: 2 | Clean: 154   │
└─────────────────────────────────────────┘
```

### Virus Confirmation Dialog
```
⚠️ VIRUS DETECTED!
┌─────────────────────────────────────┐
│ Infected File: malware.exe          │
│ Location: C:\Downloads\malware.exe  │
│                                     │
│ What would you like to do?          │
│                                     │
│  🗑️ Delete Virus  │  📁 Keep File   │
└─────────────────────────────────────┘
```

## 🚀 Installation

### Prerequisites
- **Python 3.7 or higher**
- **tkinter** (usually included with Python)
- **Operating System**: Windows, Linux, or macOS

### Method 1: Clone Repository
```bash
# Clone the repository
git clone https://github.com/Mrutyunjaypathe/Antivirus.git
cd Antivirus

# No additional dependencies needed - uses Python standard library only!
```

### Method 2: Download ZIP
1. Download the ZIP file from GitHub
2. Extract to your desired location
3. Navigate to the extracted folder

### Verify Installation
```bash
# Check Python version
python --version

# Test the GUI (should open without errors)
python antivirus_gui.py
```

## 🎯 Usage

### Starting the Application
```bash
cd antivirus
python antivirus_gui.py
```

### Using as Python Package
```python
from antivirus import AntivirusGUI, MalwareScanner
import tkinter as tk

# Create GUI application
root = tk.Tk()
app = AntivirusGUI(root)
root.mainloop()

# Or use scanner directly
scanner = MalwareScanner()
result = scanner.scan_file('path/to/file')
print(f"Malicious: {result['is_malicious']}")
```

### Scanning Files

#### 1. **Single File Scan**
- Click **📁 Scan Single File**
- Select file using file dialog
- Wait for scan completion
- Handle any detected threats via confirmation dialog

#### 2. **Directory Scan**
- Click **📂 Scan Directory**
- Select folder to scan
- Monitor progress in real-time
- Review batch confirmation for multiple threats

#### 3. **Quick Scan**
- Click **🔍 Quick Scan**
- Automatically scans:
  - Desktop folder
  - Downloads folder
  - System temp directories

#### 4. **Clean Temp Files**
- Click **🧹 Clean Temp Files**
- Removes `.tmp` files from system temp directories
- Shows count of cleaned files

### Understanding Results

| Symbol | Meaning |
|--------|---------|
| ✅ | Clean file - no threats detected |
| ⚠️ | Threat detected - requires action |
| ❌ | Error occurred during scanning |
| 🗑️ | File successfully deleted |

### Virus Confirmation Process

1. **Threat Detected** → Confirmation dialog appears
2. **Choose Action**:
   - **Delete Virus**: Permanently removes the file
   - **Keep File**: Leaves file untouched (not recommended)
3. **Confirmation**: Success/error message displayed
4. **Logging**: Action recorded in scan results

## 📁 File Structure

```
antivirus/
├── README.md                 # Project documentation
├── requirements.txt          # Dependencies (none needed)
├── __init__.py              # Package initialization
├── antivirus_gui.py         # Main GUI application
├── scanner.py               # Malware detection engine
├── file_manager.py          # File operations and utilities
└── ui_components.py         # GUI dialogs and interface elements
```

### Core Modules Description

| Module | Purpose |
|--------|---------|
| `antivirus_gui.py` | **Main application** - GUI interface and event handling |
| `scanner.py` | **Detection engine** - Malware signature matching and file analysis |
| `file_manager.py` | **File operations** - Safe deletion, temp cleanup, system utilities |
| `ui_components.py` | **Interface elements** - Confirmation dialogs and styled components |
| `__init__.py` | **Package definition** - Module imports and version info |

## ⚙️ How It Works

### Malware Detection Engine

1. **Signature Matching**: Compares file contents against known malware signatures
2. **Safe Directory Filtering**: Skips system and development directories
3. **File Type Filtering**: Ignores safe file extensions (`.md`, `.txt`, `.json`, etc.)
4. **Chunked Reading**: Efficiently processes large files in 8KB chunks

### Current Signatures
- **EICAR Test File**: Standard antivirus test signature
- **Extensible**: Easy to add new malware signatures

### Safe Directories (Automatically Skipped)
- `flutter/` - Flutter SDK files
- `node_modules/` - Node.js packages
- `Program Files/` - System programs
- `Windows\System32/` - Windows system files
- `.git/` - Git repositories
- `venv/`, `__pycache__/` - Python environments

### Safe File Extensions (Automatically Skipped)
- Documentation: `.md`, `.txt`, `.html`
- Configuration: `.json`, `.yaml`, `.yml`, `.xml`
- Source Code: `.dart`, `.js`, `.css`
- Fonts: `.otf`, `.ttf`
- Binary Assets: `.wasm`, `.pdb`, `.snapshot`

## 🔧 Configuration

### Adding New Malware Signatures
Edit `scanner.py`:
```python
self.malware_signatures = [
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    b"your_new_signature_here",
]
```

### Modifying Safe Directories
Edit `scanner.py`:
```python
self.safe_directories = [
    "flutter", "node_modules", "Program Files",
    "your_safe_directory",
]
```

### Customizing File Extensions
Edit `scanner.py`:
```python
self.safe_extensions = ['.md', '.txt', '.json', '.your_extension']
```

## 🧪 Testing

### Test with EICAR File
Create a test file to verify detection:
```bash
# Create EICAR test file (safe test virus)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
```

**⚠️ Warning**: This creates a harmless test file that antivirus software will detect as a threat.

### Testing Individual Modules
```bash
# Test scanner module
python -c "from scanner import MalwareScanner; s = MalwareScanner(); print('Scanner loaded')"

# Test file manager
python -c "from file_manager import FileManager; f = FileManager(); print('File manager loaded')"

# Test as package
python -c "import antivirus; print(f'Version: {antivirus.__version__}')"
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Code Style
- Follow PEP 8 Python style guidelines
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small

### Adding Features
- **New scan types**: Add methods to `AntivirusGUI` class
- **Better detection**: Extend `MalwareScanner` class in `scanner.py`
- **UI improvements**: Add components to `ui_components.py`
- **File operations**: Extend `FileManager` class in `file_manager.py`
- **New signatures**: Update `malware_signatures` in `scanner.py`

## 📝 License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2024 Python Antivirus Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ⚠️ Disclaimer

This antivirus scanner is designed for **educational purposes** and basic threat detection. For production environments, use professional antivirus solutions. The developers are not responsible for any damage caused by undetected threats or false positives.

## 📞 Support

- **Issues**: Report bugs on GitHub Issues
- **Questions**: Create a discussion on GitHub
- **Email**: your-email@example.com

---

**Made with ❤️ and Python** | **Star ⭐ if you found this helpful!**