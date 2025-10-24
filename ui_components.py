import tkinter as tk
from tkinter import messagebox, scrolledtext
import os

class VirusConfirmationDialog:
    @staticmethod
    def show_single_virus_dialog(parent, file_path, delete_callback, keep_callback):
        confirm_window = tk.Toplevel(parent)
        confirm_window.title("⚠️ Virus Detected!")
        confirm_window.geometry("500x300")
        confirm_window.configure(bg='#e74c3c')
        confirm_window.transient(parent)
        confirm_window.grab_set()
        
        confirm_window.geometry("+%d+%d" % (parent.winfo_rootx() + 150, parent.winfo_rooty() + 100))
        
        title_frame = tk.Frame(confirm_window, bg='#e74c3c')
        title_frame.pack(pady=20)
        
        tk.Label(title_frame, text="⚠️ VIRUS DETECTED!", font=('Arial', 18, 'bold'), 
                fg='white', bg='#e74c3c').pack()
        
        info_frame = tk.Frame(confirm_window, bg='white', relief='raised', bd=2)
        info_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(info_frame, text="Infected File:", font=('Arial', 12, 'bold'), 
                fg='#e74c3c', bg='white').pack(pady=5)
        tk.Label(info_frame, text=os.path.basename(file_path), font=('Arial', 11), 
                fg='black', bg='white', wraplength=400).pack(pady=2)
        tk.Label(info_frame, text=f"Location: {file_path}", font=('Arial', 9), 
                fg='gray', bg='white', wraplength=400).pack(pady=2)
        
        tk.Label(confirm_window, text="What would you like to do?", font=('Arial', 14, 'bold'), 
                fg='white', bg='#e74c3c').pack(pady=10)
        
        button_frame = tk.Frame(confirm_window, bg='#e74c3c')
        button_frame.pack(pady=20)
        
        def delete_action():
            delete_callback(file_path)
            confirm_window.destroy()
            
        def keep_action():
            keep_callback(file_path)
            confirm_window.destroy()
        
        tk.Button(button_frame, text="🗑️ Delete Virus", command=delete_action, 
                 bg='#c0392b', fg='white', font=('Arial', 12, 'bold'), 
                 padx=20, pady=10, cursor='hand2').pack(side='left', padx=10)
        
        tk.Button(button_frame, text="📁 Keep File", command=keep_action, 
                 bg='#7f8c8d', fg='white', font=('Arial', 12, 'bold'), 
                 padx=20, pady=10, cursor='hand2').pack(side='left', padx=10)
    
    @staticmethod
    def show_batch_virus_dialog(parent, threats, delete_all_callback, keep_all_callback):
        if not threats:
            return
            
        confirm_window = tk.Toplevel(parent)
        confirm_window.title(f"⚠️ {len(threats)} Viruses Detected!")
        confirm_window.geometry("600x400")
        confirm_window.configure(bg='#e74c3c')
        confirm_window.transient(parent)
        confirm_window.grab_set()
        
        confirm_window.geometry("+%d+%d" % (parent.winfo_rootx() + 100, parent.winfo_rooty() + 50))
        
        tk.Label(confirm_window, text=f"⚠️ {len(threats)} VIRUSES DETECTED!", 
                font=('Arial', 16, 'bold'), fg='white', bg='#e74c3c').pack(pady=10)
        
        list_frame = tk.Frame(confirm_window, bg='white')
        list_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        tk.Label(list_frame, text="Infected Files:", font=('Arial', 12, 'bold'), 
                fg='#e74c3c', bg='white').pack(anchor='w', pady=5)
        
        threat_list = scrolledtext.ScrolledText(list_frame, height=10, bg='#f8f9fa', 
                                               fg='black', font=('Consolas', 9))
        threat_list.pack(fill='both', expand=True, pady=5)
        
        for threat in threats:
            threat_list.insert(tk.END, f"• {threat}\n")
        threat_list.configure(state='disabled')
        
        button_frame = tk.Frame(confirm_window, bg='#e74c3c')
        button_frame.pack(pady=15)
        
        def delete_all_action():
            delete_all_callback(threats)
            confirm_window.destroy()
            
        def keep_all_action():
            keep_all_callback(threats)
            confirm_window.destroy()
        
        tk.Button(button_frame, text=f"🗑️ Delete All ({len(threats)})", command=delete_all_action, 
                 bg='#c0392b', fg='white', font=('Arial', 12, 'bold'), 
                 padx=20, pady=10, cursor='hand2').pack(side='left', padx=10)
        
        tk.Button(button_frame, text="📁 Keep All Files", command=keep_all_action, 
                 bg='#7f8c8d', fg='white', font=('Arial', 12, 'bold'), 
                 padx=20, pady=10, cursor='hand2').pack(side='left', padx=10)

class UIHelpers:
    @staticmethod
    def create_styled_button(parent, text, command, color, row, col):
        btn = tk.Button(parent, text=text, command=command, 
                       bg=color, fg='white', font=('Arial', 12, 'bold'),
                       relief='flat', padx=20, pady=10, cursor='hand2')
        btn.grid(row=row, column=col, padx=10, pady=5, sticky='ew')
        parent.grid_columnconfigure(col, weight=1)
        
        colors = {'#e74c3c': '#ec7063', '#3498db': '#5dade2', 
                 '#f39c12': '#f8c471', '#27ae60': '#58d68d'}
        hover_color = colors.get(color, color)
        
        def on_enter(e):
            btn.configure(bg=hover_color)
        def on_leave(e):
            btn.configure(bg=color)
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        
        return btn