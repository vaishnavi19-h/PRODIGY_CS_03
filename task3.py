import tkinter as tk
from tkinter import messagebox
import re

def assess_password_strength(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    special_character_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    criteria_met = sum([
        length_criteria,
        uppercase_criteria,
        lowercase_criteria,
        number_criteria,
        special_character_criteria
    ])

    if criteria_met == 5:
        feedback = "Strong password! Your password meets all recommended criteria."
    elif criteria_met >= 3:
        feedback = "Moderate password. Consider adding more diversity (e.g., special characters, uppercase letters) to strengthen it."
    else:
        feedback = "Weak password. Try making it longer and including a mix of letters, numbers, and special characters."

    return {
        "Password Length": len(password),
        "Contains Uppercase": uppercase_criteria,
        "Contains Lowercase": lowercase_criteria,
        "Contains Numbers": number_criteria,
        "Contains Special Characters": special_character_criteria,
        "Strength Feedback": feedback
    }

def check_password():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    
    result = assess_password_strength(password)
    feedback = f"""
    Password Length: {result['Password Length']}
    Contains Uppercase: {'Yes' if result['Contains Uppercase'] else 'No'}
    Contains Lowercase: {'Yes' if result['Contains Lowercase'] else 'No'}
    Contains Numbers: {'Yes' if result['Contains Numbers'] else 'No'}
    Contains Special Characters: {'Yes' if result['Contains Special Characters'] else 'No'}
    \nStrength Feedback: {result['Strength Feedback']}
    """
    messagebox.showinfo("Password Strength", feedback)

app = tk.Tk()
app.title("Password Strength Checker")

tk.Label(app, text="Enter your password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(app, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10, pady=10)

check_button = tk.Button(app, text="Check Strength", command=check_password)
check_button.grid(row=1, column=0, columnspan=2, pady=10)

app.mainloop()
