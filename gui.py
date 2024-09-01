import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from vulnerabilities import apply_vulnerabilities, VULNERABILITY_OPTIONS
import customtkinter as ctk
import math

class VulndowsPenGUI:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        self.root = ctk.CTk()
        self.root.title("VulndowsPen - Vulnerability Configuration")
        self.root.geometry("1000x1000") 
        
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.root.grid_columnconfigure(0, weight=2)
        self.root.grid_rowconfigure(0, weight=2)
        
        self.canvas = ctk.CTkCanvas(self.main_frame, highlightthickness=0)
        self.scrollbar = ctk.CTkScrollbar(self.main_frame, command=self.canvas.yview, orientation="vertical")
        self.scrollable_frame = ctk.CTkFrame(self.canvas)

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.grid(row=2, column=0, sticky="nsew")
        self.scrollbar.grid(row=1, column=1, sticky="ns")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.scrollable_frame.bind("<Configure>", self.update_scroll_region)
        self.root.bind("<Configure>", self.resize_canvas)
        self.root.bind_all("<MouseWheel>", self._on_mousewheel)

        self.create_widgets()

    def update_scroll_region(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def resize_canvas(self, event):
        canvas_width = self.main_frame.winfo_width() - self.scrollbar.winfo_width()
        self.canvas.configure(width=canvas_width)

    def create_collapsible_frame(self, parent, text):
        container = ctk.CTkFrame(parent)
        
        def toggle_frame():
            if toggle_button.cget("text") == "▶":
                toggle_button.configure(text="▼")
                frame.grid()
            else:
                toggle_button.configure(text="▶")
                frame.grid_remove()

        toggle_button = ctk.CTkButton(container, text="▼", command=toggle_frame, width=15, height=15, font=ctk.CTkFont(size=12))
        toggle_button.grid(row=0, column=0, sticky="w", padx=(10, 0))
        
        label = ctk.CTkLabel(container, text=text, font=ctk.CTkFont(size=12, weight="bold"))
        label.grid(row=0, column=1, sticky="w", padx=(10, 0))
        
        frame = ctk.CTkFrame(container)
        frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=(0, 5))
        
        # Create a canvas and scrollbar for the frame
        canvas = ctk.CTkCanvas(frame, background="#121212", height=170, highlightthickness=1, highlightbackground="#121212")  # Set a fixed height for the scrollable area
        scrollbar = ctk.CTkScrollbar(frame, command=canvas.yview, orientation="vertical")
        scrollable_frame = ctk.CTkFrame(canvas)

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # Bind mousewheel event to the canvas for smooth scrolling
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", lambda e: self._on_category_mousewheel(e, canvas)))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))
        
        # Set background color to match the dark theme
        canvas.configure(bg=self.root.cget("bg"))
        scrollable_frame.configure(fg_color=self.root.cget("bg"))
        
        container.grid_columnconfigure(1, weight=1)
        
        return container, scrollable_frame

    def create_widgets(self):
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Load the logo.svg file
        logo_image = Image.open(".\\hacker.png")
        self.logo_image = ctk.CTkImage(logo_image, size=(24, 24))
        title_label = ctk.CTkLabel(self.main_frame, text="VulndowsPen", font=ctk.CTkFont(size=24, weight="bold"), text_color="#FF474C", image=self.logo_image, compound="left")
        title_label.grid(row=0, column=0, pady=10)

        self.category_frames = {}
        self.vuln_vars = {}
        
        self.categories_frame = ctk.CTkFrame(self.main_frame)
        self.categories_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        num_categories = len(VULNERABILITY_OPTIONS)
        num_columns = min(3, num_categories)
        num_rows = math.ceil(num_categories / num_columns)

        for row in range(num_rows * 2):
            self.categories_frame.grid_rowconfigure(row, weight=1, minsize=20)
        for col in range(num_columns):
            self.categories_frame.grid_columnconfigure(col, weight=1)

        for i, (category, vulns) in enumerate(VULNERABILITY_OPTIONS.items()):
            container, frame = self.create_collapsible_frame(self.categories_frame, category)
            container.grid(row=i // num_columns * 2, column=i % num_columns, sticky="nsew", padx=2, pady=2)
            
            for vuln in vulns:
                var = tk.BooleanVar(value=True)
                checkbox = ctk.CTkCheckBox(frame, text=vuln, variable=var, font=ctk.CTkFont(size=12))
                checkbox.pack(anchor="w", pady=1)
                self.vuln_vars[vuln] = (var, checkbox)
            
            self.category_frames[category] = frame
        
        self.update_scroll_region(None)

        self.difficulty_frame = ctk.CTkFrame(self.main_frame)
        self.difficulty_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        
        difficulty_label = ctk.CTkLabel(self.difficulty_frame, text="Difficulty:", font=ctk.CTkFont(size=14))
        difficulty_label.grid(row=0, column=0, padx=5, sticky="w")
        
        self.difficulty_slider = ctk.CTkSlider(self.difficulty_frame, from_=0, to=7, number_of_steps=7, command=self.update_difficulty)
        self.difficulty_slider.grid(row=0, column=1, padx=5, sticky="ew")
        self.difficulty_slider.set(0)
        
        self.difficulty_value_label = ctk.CTkLabel(self.difficulty_frame, text="Babies Only", font=ctk.CTkFont(size=14))
        self.difficulty_value_label.grid(row=0, column=2, padx=5, sticky="e")

        # Add Select All / Unselect All checkbox
        self.select_all_var = tk.BooleanVar(value=True)
        self.select_all_checkbox = ctk.CTkCheckBox(self.difficulty_frame, text="Select All", variable=self.select_all_var, command=self.toggle_all_vulnerabilities, font=ctk.CTkFont(size=14))
        self.select_all_checkbox.grid(row=0, column=3, padx=5, sticky="e")

        self.apply_button = ctk.CTkButton(self.main_frame, text="Apply Vulnerabilities", command=self.apply_vulnerabilities, 
            font=ctk.CTkFont(size=14), corner_radius=6, border_width=2, border_color="black",
            fg_color=("red", "#FF474C"), hover_color=("#3D91F7", "#1F6AA5"))
        self.apply_button.grid(row=3, column=0, pady=10, sticky="ew")

        # Add styled footer
        footer_label = ctk.CTkLabel(self.main_frame, text="Dylan Vaca - 2024", font=ctk.CTkFont(size=12))
        footer_label.grid(row=4, column=0, pady=5)

    def update_difficulty(self, value):
        difficulty = int(float(value))
        difficulties = ["Babies Only", "Easy", "Somewhat Easy", "Medium", "Medium-ish", "Hard", "Harder", "Epic"]
        self.difficulty_value_label.configure(text=difficulties[difficulty])
        self.update_checkboxes_from_difficulty(difficulty)

    def update_checkboxes_from_difficulty(self, difficulty):
        difficulties = {
            0: [],  # Babies Only: All vulnerabilities enabled
            1: ["Enable Weak Kerberos Encryption Types", "Enable Telnet Server", "Disable Account Lockout", "Enable Remote Desktop without Network Level Authentication"],
            2: ["Disable PowerShell Script Block Logging", "Add Guest to Administrators Group", "Enable AutoRun for All Drives", "Disable Windows Defender Application Guard"],
            3: ["Enable Guest Account", "Disable Windows SmartScreen", "Enable Anonymous Enumeration of SAM Accounts", "Disable Windows Event Log", "Enable Weak BitLocker Encryption"],
            4: ["Disable Windows Defender Antivirus", "Disable Windows Defender Tamper Protection", "Disable Windows Firewall Logging", "Enable Weak FTP Server Settings", "Disable User Account Control (UAC)"],
            5: ["Disable Windows Defender Real-time Protection", "Disable Windows Defender Network Protection", "Enable Weak DNS Security Extensions (DNSSEC)", "Enable Weak Remote Desktop Protocol (RDP) Encryption", "Enable Weak Group Policy Password Settings"],
            6: ["Disable Windows Firewall for All Profiles", "Enable Weak Wireless Encryption (WEP)", "Disable Windows Updates", "Enable Weak NTFS Permissions", "Disable Windows Defender Credential Guard"], 
            7: ["Enable Weak SNMP Community Strings", "Enable Anonymous Share Access", "Disable Windows Defender Memory Integrity", "Enable Weak Wi-Fi Protected Access (WPA) Encryption"],
        }

        disabled_vulns = []
        for i in range(0, difficulty + 1):
            disabled_vulns.extend(difficulties.get(i, []))

        for vuln, (var, checkbox) in self.vuln_vars.items():
            if vuln in disabled_vulns:
                var.set(False)
                checkbox.deselect()
            else:
                var.set(True)
                checkbox.select()

        # Update Select All checkbox state
        self.select_all_var.set(all(var.get() for var, _ in self.vuln_vars.values()))

    def toggle_all_vulnerabilities(self):
        select_all = self.select_all_var.get()
        for var, checkbox in self.vuln_vars.values():
            var.set(select_all)
            if select_all:
                checkbox.select()
            else:
                checkbox.deselect()

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_category_mousewheel(self, event, canvas):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def apply_vulnerabilities(self):
        selected_vulns = [vuln for vuln, (var, _) in self.vuln_vars.items() if var.get()]
        apply_vulnerabilities(selected_vulns)
        messagebox.showinfo("Vulnerability Configuration", "Vulnerabilities have been applied!")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = VulndowsPenGUI()
    app.run()
