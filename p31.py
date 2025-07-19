import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import re
import random
import string

# ---------------- Password Strength Check ----------------

def assess_password_strength(password):
    score = 0
    feedback = []
    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("🔸 At least 8 characters long")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("🔸 Add lowercase letters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("🔸 Add uppercase letters")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("🔸 Add numbers")

    if re.search(rf"[{re.escape(special_chars)}]", password):
        score += 1
    else:
        feedback.append("🔸 Add special characters (e.g., !, @, #)")

    if score <= 2:
        strength = "Weak ❌"
    elif score == 3:
        strength = "Moderate ⚠️"
    elif score == 4:
        strength = "Strong ✅"
    else:
        strength = "Very Strong 💪"

    return strength, feedback, score

# ---------------- Password Generator ----------------

def generate_secure_password(length=16):
    if length < 12:
        raise ValueError("Password length must be at least 12")

    chars = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice("!@#$%^&*()-_=+[]{}|;:,.<>?")
    ]

    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    chars += random.choices(all_chars, k=length - len(chars))
    random.shuffle(chars)

    return ''.join(chars)

# ---------------- GUI Application ----------------

class PasswordToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Strength & Generator Tool")
        self.root.geometry("500x480")
        self.root.resizable(False, False)

        self.create_widgets()

    def create_widgets(self):
        # Password Strength Section
        tk.Label(self.root, text="🔍 Check Password Strength", font=("Arial", 14, "bold")).pack(pady=10)

        self.password_entry = tk.Entry(self.root, show="*", width=30, font=("Arial", 12))
        self.password_entry.pack(pady=5)

        # Show/Hide password checkbox
        self.show_password = tk.BooleanVar()
        tk.Checkbutton(self.root, text="Show Password", variable=self.show_password, command=self.toggle_password).pack()

        tk.Button(self.root, text="Check Strength", command=self.check_strength, bg="lightblue").pack(pady=5)

        self.strength_label = tk.Label(self.root, text="", font=("Arial", 12, "bold"))
        self.strength_label.pack(pady=5)

        # Progress bar for strength
        self.progress = ttk.Progressbar(self.root, length=200, maximum=5)
        self.progress.pack(pady=5)

        self.feedback_label = tk.Label(self.root, text="", font=("Arial", 10), fg="gray")
        self.feedback_label.pack()

        tk.Label(self.root, text="────────────────────────────────────", fg="gray").pack(pady=10)

        # Password Generator Section
        tk.Label(self.root, text="🔧 Generate Secure Password", font=("Arial", 14, "bold")).pack(pady=5)

        self.length_var = tk.IntVar(value=16)
        tk.Label(self.root, text="Length (min 12):").pack()
        tk.Entry(self.root, textvariable=self.length_var, width=5, justify="center").pack()

        tk.Button(self.root, text="Generate Password", command=self.generate_password, bg="lightgreen").pack(pady=5)

        self.generated_password = tk.Entry(self.root, width=30, font=("Arial", 12), justify="center")
        self.generated_password.pack(pady=5)

        tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=5)

        self.copy_label = tk.Label(self.root, text="", fg="green", font=("Arial", 10))
        self.copy_label.pack()

    def toggle_password(self):
        self.password_entry.config(show="" if self.show_password.get() else "*")

    def check_strength(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return

        strength, feedback, score = assess_password_strength(password)
        self.strength_label.config(text=f"Strength: {strength}")
        self.feedback_label.config(text="\n".join(feedback) if feedback else "✅ Very Strong!")
        self.progress["value"] = score

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 12:
                raise ValueError
            password = generate_secure_password(length)
            self.generated_password.delete(0, tk.END)
            self.generated_password.insert(0, password)
        except:
            messagebox.showerror("Invalid Input", "Please enter a valid number (min 12).")

    def copy_to_clipboard(self):
        password = self.generated_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.copy_label.config(text="✅ Copied to clipboard!")
            self.root.after(2000, lambda: self.copy_label.config(text=""))
        else:
            messagebox.showwarning("Nothing to Copy", "No password generated yet.")

# ---------------- Run the App ----------------

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordToolApp(root)
    root.mainloop()
