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
git clone https://github.com/yourusername/python-antivirus.git
cd python-antivirus

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
├── README.md                 # This file
├── requirements.txt          # Dependencies (none needed)
├── antivirus_gui.py         # Main GUI application
├── detect_virus.py          # Single file virus detection
├── is_file_corrupted.py     # File signature validation
├── scan_and_detect.py       # Directory scanning with signature check
└── scan_directory.py        # Basic directory file listing
```

### Core Files Description

| File | Purpose |
|------|---------|
| `antivirus_gui.py` | **Main application** - GUI interface with all features |
| `detect_virus.py` | Command-line virus detection for single files |
| `is_file_corrupted.py` | File signature validation utility |
| `scan_and_detect.py` | Directory scanner with signature checking |
| `scan_directory.py` | Basic directory listing tool |

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
Edit `antivirus_gui.py`, line ~15:
```python
self.malware_signatures = [
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    b"your_new_signature_here",  # Add new signatures
]
```

### Modifying Safe Directories
Edit `antivirus_gui.py`, line ~20:
```python
self.safe_directories = [
    "flutter", "node_modules", "Program Files",
    "your_safe_directory",  # Add new safe directories
]
```

### Customizing File Extensions
Edit the `is_malicious_file` method:
```python
safe_extensions = ['.md', '.txt', '.json', '.your_extension']
```

## 🧪 Testing

### Test with EICAR File
Create a test file to verify detection:
```bash
# Create EICAR test file (safe test virus)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
```

**⚠️ Warning**: This creates a harmless test file that antivirus software will detect as a threat.

### Running Individual Components
```bash
# Test single file detection
python detect_virus.py

# Test file signature checking
python is_file_corrupted.py

# Test directory scanning
python scan_directory.py
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
- **Better detection**: Improve `is_malicious_file` method
- **UI improvements**: Modify `setup_ui` method
- **New signatures**: Update `malware_signatures` list

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