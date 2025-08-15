#Features
#Real-time Analysis: Checks password strength as you type
#Visual Feedback:
#Color-coded progress bar (red to green)
#Strength label (Very Weak, Weak, Moderate, Strong)
#Checkmarks for met requirements
#Comprehensive Criteria Checking:
#Minimum length (8+ characters)
#Contains lowercase letters
#Contains uppercase letters
#Contains numbers
#Contains special characters
#Bonus points for longer passwords (12+, 16+ characters)
#Helpful Suggestions: Provides specific feedback on how to improve weak passwords
#User-Friendly Options:
#Show/hide password toggle
#Clean, modern interface




import tkinter as tk
from tkinter import ttk, messagebox
import re

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TLabel', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10), padding=5)
        self.style.configure('Red.TLabel', foreground='red')
        self.style.configure('Yellow.TLabel', foreground='orange')
        self.style.configure('Green.TLabel', foreground='green')
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create widgets
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        ttk.Label(self.main_frame, text="Password Strength Checker", 
                 font=('Arial', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Password entry
        ttk.Label(self.main_frame, text="Enter Password:").grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.password_entry = ttk.Entry(self.main_frame, width=30, show="•")
        self.password_entry.grid(row=2, column=0, sticky=tk.W, pady=(0, 15))
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Show password checkbox
        self.show_password = tk.BooleanVar()
        self.show_pass_check = ttk.Checkbutton(
            self.main_frame, 
            text="Show password", 
            variable=self.show_password,
            command=self.toggle_password_visibility
        )
        self.show_pass_check.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        # Strength meter
        ttk.Label(self.main_frame, text="Strength:").grid(row=3, column=0, sticky=tk.W, pady=(0, 5))
        self.strength_meter = ttk.Progressbar(
            self.main_frame, 
            orient='horizontal', 
            length=200, 
            mode='determinate'
        )
        self.strength_meter.grid(row=4, column=0, sticky=tk.W, pady=(0, 15))
        
        # Strength label
        self.strength_label = ttk.Label(self.main_frame, text="", font=('Arial', 10, 'bold'))
        self.strength_label.grid(row=4, column=1, sticky=tk.W, padx=(10, 0))
        
        # Criteria frame
        criteria_frame = ttk.LabelFrame(self.main_frame, text="Password Requirements", padding=10)
        criteria_frame.grid(row=5, column=0, columnspan=2, sticky=tk.W+tk.E, pady=(0, 20))
        
        # Criteria labels
        self.length_label = ttk.Label(criteria_frame, text="✓ At least 8 characters")
        self.length_label.grid(row=0, column=0, sticky=tk.W)
        
        self.lower_label = ttk.Label(criteria_frame, text="✓ Contains lowercase letters")
        self.lower_label.grid(row=1, column=0, sticky=tk.W)
        
        self.upper_label = ttk.Label(criteria_frame, text="✓ Contains uppercase letters")
        self.upper_label.grid(row=2, column=0, sticky=tk.W)
        
        self.number_label = ttk.Label(criteria_frame, text="✓ Contains numbers")
        self.number_label.grid(row=3, column=0, sticky=tk.W)
        
        self.special_label = ttk.Label(criteria_frame, text="✓ Contains special characters")
        self.special_label.grid(row=4, column=0, sticky=tk.W)
        
        # Feedback label
        self.feedback_label = ttk.Label(
            self.main_frame, 
            text="", 
            wraplength=400, 
            justify=tk.LEFT
        )
        self.feedback_label.grid(row=6, column=0, columnspan=2, sticky=tk.W)
        
        # Check button
        self.check_btn = ttk.Button(
            self.main_frame, 
            text="Check Password", 
            command=self.check_password_strength
        )
        self.check_btn.grid(row=7, column=0, columnspan=2, pady=(10, 0))
        
    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def check_password_strength(self, event=None):
        password = self.password_entry.get()
        strength = 0
        feedback = []
        
        # Reset criteria labels
        self.length_label.config(style='TLabel')
        self.lower_label.config(style='TLabel')
        self.upper_label.config(style='TLabel')
        self.number_label.config(style='TLabel')
        self.special_label.config(style='TLabel')
        
        # Check length
        if len(password) >= 8:
            strength += 1
            self.length_label.config(style='Green.TLabel')
        else:
            feedback.append("Password should be at least 8 characters long.")
            self.length_label.config(style='Red.TLabel')
        
        # Check lowercase letters
        if re.search(r'[a-z]', password):
            strength += 1
            self.lower_label.config(style='Green.TLabel')
        else:
            feedback.append("Add lowercase letters to strengthen your password.")
            self.lower_label.config(style='Red.TLabel')
        
        # Check uppercase letters
        if re.search(r'[A-Z]', password):
            strength += 1
            self.upper_label.config(style='Green.TLabel')
        else:
            feedback.append("Add uppercase letters to strengthen your password.")
            self.upper_label.config(style='Red.TLabel')
        
        # Check numbers
        if re.search(r'[0-9]', password):
            strength += 1
            self.number_label.config(style='Green.TLabel')
        else:
            feedback.append("Include numbers to strengthen your password.")
            self.number_label.config(style='Red.TLabel')
        
        # Check special characters
        if re.search(r'[^A-Za-z0-9]', password):
            strength += 1
            self.special_label.config(style='Green.TLabel')
        else:
            feedback.append("Add special characters (!@#$%^&*) to strengthen your password.")
            self.special_label.config(style='Red.TLabel')
        
        # Additional length bonus
        if len(password) >= 12:
            strength += 1
        if len(password) >= 16:
            strength += 1
        
        # Calculate strength percentage (max 7 points)
        strength_percent = (strength / 7) * 100
        
        # Update strength meter and label
        self.strength_meter['value'] = strength_percent
        
        if strength_percent < 40:
            strength_text = "Very Weak"
            self.strength_label.config(text=strength_text, style='Red.TLabel')
            self.strength_meter.config(style='red.Horizontal.TProgressbar')
        elif strength_percent < 60:
            strength_text = "Weak"
            self.strength_label.config(text=strength_text, style='Red.TLabel')
            self.strength_meter.config(style='red.Horizontal.TProgressbar')
        elif strength_percent < 80:
            strength_text = "Moderate"
            self.strength_label.config(text=strength_text, style='Yellow.TLabel')
            self.strength_meter.config(style='yellow.Horizontal.TProgressbar')
        else:
            strength_text = "Strong"
            self.strength_label.config(text=strength_text, style='Green.TLabel')
            self.strength_meter.config(style='green.Horizontal.TProgressbar')
        
        # Provide feedback
        if strength_percent >= 80:
            feedback.insert(0, "Great job! This is a strong password.")
        elif strength_percent >= 60:
            feedback.insert(0, "Your password is okay but could be stronger.")
        else:
            feedback.insert(0, "Your password is weak. Consider improving it.")
        
        self.feedback_label.config(text="\n".join(feedback))
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    app.run()