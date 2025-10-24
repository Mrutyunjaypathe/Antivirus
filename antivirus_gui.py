import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from datetime import datetime

from scanner import MalwareScanner
from file_manager import FileManager
from ui_components import VirusConfirmationDialog, UIHelpers

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Antivirus Scanner")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        
        self.scanner = MalwareScanner()
        self.file_manager = FileManager()
        self.detected_threats = []
        
        self.setup_ui()
        
    def setup_ui(self):
        title_frame = tk.Frame(self.root, bg='#2c3e50')
        title_frame.pack(pady=20)
        
        title_label = tk.Label(title_frame, text="🛡️ Python Antivirus Scanner", 
                              font=('Arial', 24, 'bold'), fg='#ecf0f1', bg='#2c3e50')
        title_label.pack()
        
        main_frame = tk.Frame(self.root, bg='#34495e', relief='raised', bd=2)
        main_frame.pack(padx=20, pady=10, fill='both', expand=True)
        
        button_frame = tk.Frame(main_frame, bg='#34495e')
        button_frame.pack(pady=20)
        
        UIHelpers.create_styled_button(button_frame, "📁 Scan Single File", self.scan_single_file, '#e74c3c', 0, 0)
        UIHelpers.create_styled_button(button_frame, "📂 Scan Directory", self.scan_directory, '#3498db', 0, 1)
        UIHelpers.create_styled_button(button_frame, "🔍 Quick Scan", self.quick_scan, '#f39c12', 1, 0)
        UIHelpers.create_styled_button(button_frame, "🧹 Clean Temp Files", self.clean_temp, '#27ae60', 1, 1)
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(pady=10, padx=20, fill='x')
        
        self.status_label = tk.Label(main_frame, text="Ready to scan", 
                                   font=('Arial', 12), fg='#ecf0f1', bg='#34495e')
        self.status_label.pack(pady=5)
        
        results_frame = tk.Frame(main_frame, bg='#34495e')
        results_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        tk.Label(results_frame, text="Scan Results:", font=('Arial', 14, 'bold'), 
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, 
                                                     bg='#2c3e50', fg='#ecf0f1', 
                                                     font=('Consolas', 10))
        self.results_text.pack(fill='both', expand=True, pady=5)
        
        stats_frame = tk.Frame(main_frame, bg='#34495e')
        stats_frame.pack(pady=10, fill='x')
        
        self.stats_label = tk.Label(stats_frame, text="Files: 0 | Threats: 0 | Clean: 0", 
                                   font=('Arial', 10), fg='#bdc3c7', bg='#34495e')
        self.stats_label.pack()
        
    def log_result(self, message, threat=False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.results_text.configure(state='normal')
        self.results_text.insert(tk.END, f"[{timestamp}] {message}\n")
        
        if threat:
            start_line = self.results_text.index(tk.END + "-2l linestart")
            end_line = self.results_text.index(tk.END + "-2l lineend")
            self.results_text.tag_add("threat", start_line, end_line)
            self.results_text.tag_config("threat", foreground="#e74c3c", font=('Consolas', 10, 'bold'))
            
        self.results_text.configure(state='disabled')
        self.results_text.see(tk.END)
        
    def update_stats(self, files=0, threats=0, clean=0):
        self.stats_label.config(text=f"Files: {files} | Threats: {threats} | Clean: {clean}")
        
    def scan_single_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*")]
        )
        
        if file_path:
            threading.Thread(target=self._scan_file_thread, args=(file_path,), daemon=True).start()
            
    def _scan_file_thread(self, file_path):
        self.progress.start()
        self.status_label.config(text="Scanning file...")
        
        self.log_result(f"Scanning: {self.scanner.scan_file(file_path)['file_name']}")
        
        result = self.scanner.scan_file(file_path)
        
        if result['is_malicious']:
            self.log_result(f"⚠️ THREAT DETECTED: {result['file_name']}", threat=True)
            self.update_stats(1, 1, 0)
            self._show_single_virus_confirmation(file_path)
        else:
            self.log_result(f"✅ Clean: {result['file_name']}")
            self.update_stats(1, 0, 1)
            
        self.progress.stop()
        self.status_label.config(text="Scan complete")
        
    def scan_directory(self):
        directory = filedialog.askdirectory(title="Select directory to scan")
        
        if directory:
            threading.Thread(target=self._scan_directory_thread, args=(directory,), daemon=True).start()
            
    def _scan_directory_thread(self, directory):
        self.progress.start()
        self.status_label.config(text="Scanning directory...")
        
        files_scanned = 0
        threats_found = 0
        clean_files = 0
        self.detected_threats = []
        
        self.log_result(f"Starting directory scan: {directory}")
        
        try:
            for result in self.scanner.scan_directory(directory):
                files_scanned += 1
                self.status_label.config(text=f"Scanning: {result['file_name']}")
                
                if result['is_malicious']:
                    threats_found += 1
                    self.log_result(f"⚠️ THREAT: {result['file_path']}", threat=True)
                    self.detected_threats.append(result['file_path'])
                else:
                    clean_files += 1
                    
                self.update_stats(files_scanned, threats_found, clean_files)
                    
        except Exception as e:
            self.log_result(f"❌ Error scanning directory: {e}")
            
        self.log_result(f"Directory scan complete. Files: {files_scanned}, Threats: {threats_found}")
        
        if self.detected_threats:
            self._show_batch_virus_confirmation()
            
        self.progress.stop()
        self.status_label.config(text="Directory scan complete")
        
    def quick_scan(self):
        threading.Thread(target=self._quick_scan_thread, daemon=True).start()
        
    def _quick_scan_thread(self):
        self.progress.start()
        self.status_label.config(text="Running quick scan...")
        
        locations = self.file_manager.get_quick_scan_locations()
        total_files = 0
        total_threats = 0
        
        for location in locations:
            self.log_result(f"Quick scanning: {location}")
            try:
                for result in self.scanner.scan_directory(location):
                    total_files += 1
                    if result['is_malicious']:
                        total_threats += 1
                        self.log_result(f"⚠️ THREAT: {result['file_path']}", threat=True)
                    
                    if total_files >= 50:
                        break
            except:
                continue
                
        self.update_stats(total_files, total_threats, total_files - total_threats)
        self.log_result(f"Quick scan complete. Scanned {total_files} files, found {total_threats} threats")
        
        self.progress.stop()
        self.status_label.config(text="Quick scan complete")
        
    def clean_temp(self):
        threading.Thread(target=self._clean_temp_thread, daemon=True).start()
        
    def _clean_temp_thread(self):
        self.progress.start()
        self.status_label.config(text="Cleaning temporary files...")
        
        cleaned_files = self.file_manager.clean_temp_files()
        self.log_result(f"✅ Cleaned {cleaned_files} temporary files")
        
        self.progress.stop()
        self.status_label.config(text="Cleanup complete")
        
    def _show_single_virus_confirmation(self, file_path):
        VirusConfirmationDialog.show_single_virus_dialog(
            self.root, file_path, self._delete_file, self._keep_file
        )
        
    def _show_batch_virus_confirmation(self):
        threats = self.detected_threats.copy()
        self.detected_threats = []
        
        VirusConfirmationDialog.show_batch_virus_dialog(
            self.root, threats, self._delete_all_files, self._keep_all_files
        )
        
    def _delete_file(self, file_path):
        success, message = self.file_manager.delete_file(file_path)
        if success:
            self.log_result(f"✅ {message}")
            messagebox.showinfo("Success", "Virus file deleted successfully!")
        else:
            self.log_result(f"❌ {message}")
            messagebox.showerror("Error", f"Failed to delete file: {message}")
            
    def _keep_file(self, file_path):
        import os
        self.log_result(f"⚠️ User chose to keep infected file: {os.path.basename(file_path)}")
        
    def _delete_all_files(self, threats):
        deleted = 0
        failed = 0
        for threat in threats:
            success, message = self.file_manager.delete_file(threat)
            if success:
                deleted += 1
                self.log_result(f"✅ {message}")
            else:
                failed += 1
                self.log_result(f"❌ {message}")
        
        messagebox.showinfo("Cleanup Complete", f"Deleted: {deleted} files\nFailed: {failed} files")
        
    def _keep_all_files(self, threats):
        self.log_result(f"⚠️ User chose to keep {len(threats)} infected files")

def main():
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()