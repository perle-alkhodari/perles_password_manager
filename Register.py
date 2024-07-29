import tkinter as tk
import ttkbootstrap as tb
from Verifier import Verifier
from tkinter import messagebox
from User import User
import time

FONT = ("Futura", 25)

class Register:

    def __init__(self, email, _password):
        # Functions
        self.code = Verifier().send_code(email)

        def verify():
            entry = code_entry.get()
            if entry == self.code:
                User().create_user(email, _password)
                code_label.config(text="Verification Complete!")
                feedback_label.config(text="user: " + email)
                code_entry.destroy()
                verify_button.destroy()
                resend_button.destroy()
                time.sleep(3)
                window.destroy()
            else:
                messagebox.showerror("Invalid", "You have entered the incorrect code.")

        def resend():
            self.code = Verifier().send_code(email)
            messagebox.showinfo("Resent", "Resent code to " + email + ".")

        # Window

        window = tb.Window(themename="superhero")
        window.geometry("450x300")
        window.title("Password Manager")

        my_style = tb.Style()
        my_style.configure('success.Outline.TButton', font=("Futura", 40), parent=window)

        # Frame

        register_frame = tk.Frame(

            window
        )
        register_frame.pack(pady=50)

        # User Input

        code_label = tb.Label(
            register_frame,
            text="Verification Code",
            font=FONT
        )
        code_label.grid(row=0, column=0, sticky="w", columnspan=2)

        feedback_label = tb.Label(
            register_frame,
            text="Enter the code sent to your email.",
            font=("Futura", 13)
        )
        feedback_label.grid(row=1, column=0, sticky="w", columnspan=2)

        code_entry = tb.Entry(
            register_frame,
            font=FONT,
        )
        code_entry.grid(row=2, column=0, columnspan=2)

        # Buttons

        verify_button = tb.Button(
            register_frame,
            text="Verify",
            style="success.Outline.TButton",
            width=10,
            command=verify
        )
        verify_button.grid(row=3, column=0, pady=20)

        resend_button = tb.Button(
            register_frame,
            text="Resend Code",
            style="success.Outline.TButton",
            width=10,
            command=resend
        )
        resend_button.grid(row=3, column=1, pady=20)

        window.mainloop()
