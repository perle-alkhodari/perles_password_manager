import tkinter as tk
import ttkbootstrap as tb
from tkinter import messagebox
from PIL import ImageTk, Image
from User import User
from Password import Password
import pyperclip
from DataManager import DataManager
import os.path
from EncryptDecrypt import EncryptDecrypt
from tkinter import messagebox
from Verifier import Verifier
import time
import ctypes

self_user = ""
self_password = ""
self_file = ""
self_register_code = ""
encrypt_decrypt = ""
view = False
LAST_SESSION_FILE = "last_session"
DELIMITER = "//~+~//"
NEW_LINER = "PERLES_FILE_MANAGER(SIGNATURE)"

class Home:

    def __init__(self):

        # ------------------------------- HOME FUNCTIONS --------------------------------------

        def register_window():
            global self_register_code

            email = email_entry.get().lower()
            _password = password_entry.get()
            if len(email) > 0:
                if not User().find_user(email):
                    if len(_password) > 6:
                        if '@' in email and len(email) > 5:
                            home_page.place_forget()
                            self_register_code = Verifier().send_code(email)
                            register_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
                        else:
                            messagebox.showerror("Invalid Address", "Please enter a valid email address.")
                    else:
                        messagebox.showinfo("Password", "Password too short.")
                else:
                    messagebox.showerror("Invalid email", "A user with this email is already registered.")
            else:
                messagebox.showerror("Invalid Credentials", "Enter an email and password to make a "
                                                            "new account")

        def login():
            global self_user
            global self_password
            global self_file
            global encrypt_decrypt
            global LAST_SESSION_FILE

            email = email_entry.get().lower()
            _password = password_entry.get()
            if len(email) > 0:
                if User().find_user(email):
                    if User().check_user(email, _password):
                        # login window
                        self_user = User().get_user(email)
                        self_password = _password
                        self_file = f"user_files/{User().get_user_file(email)}"
                        encrypt_decrypt = EncryptDecrypt(self_password, self_file)
                        password_entry.delete(0, tk.END)
                        DataManager().create_file(filename=LAST_SESSION_FILE, data=email)
                        if os.path.exists(self_file):
                            update_tree_view_hidden()

                        home_page.place_forget()
                        service_entry.focus_set()
                        account_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
                    else:
                        messagebox.showerror("Access Denied", "Invalid email/password combination.")
                else:
                    messagebox.showerror("Invalid email", "A user with this email does not exist.")
            else:
                messagebox.showerror("Empty Credentials", "Enter your email and password to log in.")

        def view_login_password():
            global view
            if not view:
                password_entry.config(show="")
                password_view_button.config(bg="red")
                view = True
            else:
                password_entry.config(show="*")
                password_view_button.config(bg="SystemButtonFace")
                view = False

        def on_enter(event, entry):
            if entry == service_entry:
                login()
            entry.focus()

        # ------------------------------- HOME FUNCTIONS --------------------------------------
        # ------------------------------- ACCOUNT FUNCTIONS -----------------------------------
        def check_strength():
            data = Password().strength_score_color_description_feedback(password_entry.get())
            if len(data) != 0:
                password_strength_label.config(foreground=data[1])
                password_strength_label.config(text=data[2])

        def is_duplicate(service, _email, _password):
            global DELIMITER
            global NEW_LINER

            li = [service, _email, _password]
            data = DataManager().deserialize(encrypt_decrypt.decrypt_from_file(), DELIMITER, NEW_LINER)
            return li in data

        # Functions
        def generate_password():
            try:
                length = int(length_entry.get())
                if length == 0:
                    length = 10
                if length <= 30:
                    new_password = Password.generate(has_lowercase.get(), has_uppercase.get(), has_numbers.get(),
                                                     has_symbols.get(), length)
                    account_password_entry.delete(0, len(account_password_entry.get()))
                    account_password_entry.insert(0, new_password)
                    # PASSWORD STRENGTH CHECK
                    if len(account_password_entry.get()) > 0:
                        check_strength()
                    else:
                        password_strength_label.config(foreground="")
                        password_strength_label.config(text="(strength)")
                    # PASSWORD STRENGTH CHECK
                else:
                    messagebox.showerror("Invalid", "Password too long.")
            except ValueError:
                messagebox.showerror("Invalid", "Invalid input. Please enter a valid number.")

        def check_strength_event(event):
            check_strength()

        def copy_password():
            pyperclip.copy(account_password_entry.get())

        def copy_password_tv():
            selected_group = info_tree.focus()
            if not show_all_button.cget('text') == "Show All":
                group_details = info_tree.item(selected_group)["values"]
                if len(group_details) == 3:
                    pyperclip.copy(group_details[2])
            else:
                data_shown = get_data_shown()
                data_hidden = get_data_hidden()
                details = info_tree.item(selected_group)["values"]
                index = data_hidden.index([details[0], details[1], details[2]])
                group_details = data_shown[index]
                pyperclip.copy(group_details[2])

        def sort_by_second(item):
            return item[0]

        def get_data_shown():
            global DELIMITER
            global NEW_LINER
            new_info = DataManager().li_of_li_to_li_to_tup(DataManager().deserialize(encrypt_decrypt.decrypt_from_file()
                                                                                     , DELIMITER, NEW_LINER))
            new_info.pop()
            new_info.sort(key=sort_by_second)
            return new_info

        def get_data_hidden():
            global DELIMITER
            global NEW_LINER
            data = DataManager().deserialize(encrypt_decrypt.decrypt_from_file(), DELIMITER, NEW_LINER)
            data.pop()
            replacement = ""
            for inf in data:
                for letter in inf[2]:
                    replacement += "*"
                inf[2] = replacement
                replacement = ""
            data.sort(key=sort_by_second)
            DataManager().li_of_li_to_li_to_tup(data)
            return data

        def update_tree_view_shown():
            data = get_data_shown()
            info_tree.delete(*info_tree.get_children())
            for inf in data:
                info_tree.insert('', tb.END, values=inf)

        def update_tree_view_hidden():
            data = get_data_hidden()
            info_tree.delete(*info_tree.get_children())
            for inf in data:
                info_tree.insert('', tb.END, values=inf)

        def update_tree_view():
            if show_all_button.cget('text') == "Show All":
                update_tree_view_hidden()
            else:
                update_tree_view_shown()

        def save_group():
            global DELIMITER
            global NEW_LINER

            service = service_entry.get()
            username = username_entry.get()
            password = account_password_entry.get()

            # Character limit check
            if len(service) > 30:
                messagebox.showinfo("Character Limit Exceeded", "The service name has exceeded the\n"
                                                                "character limit of 30.")
                return None
            if len(username) > 30:
                messagebox.showinfo("Character Limit Exceeded", "The username/email has exceeded the\n"
                                                                "character limit of 30.")
                return None
            if len(password) > 30:
                messagebox.showinfo("Character Limit Exceeded", "The password has exceeded the\n"
                                                                "character limit of 30.")
                return None

            if len(service) + len(username) + len(password) == 0:
                messagebox.askokcancel("Empty Fields", "There is no data to save.\nAll fields are empty.")
                return None

            if len(service) == 0:
                if messagebox.askyesno("Empty Field", "Proceed without service?"):
                    service = "-"
                else:
                    return None

            if len(username) == 0:
                if messagebox.askyesno("Empty Field", "Proceed without username/email?"):
                    username = "-"
                else:
                    return None

            if len(password) == 0:
                if messagebox.askyesno("Empty Field", "Proceed without password?"):
                    password = "-"
                else:
                    return None

            # Check for duplicates if file exists
            if os.path.exists(self_file):
                if is_duplicate(service, username, password):
                    if messagebox.askyesno("Duplicate", "This group is already saved. Save again?"):
                        pass
                    else:
                        return None

            data = DataManager().serialize(service, username, password, DELIMITER, NEW_LINER)
            encrypt_decrypt.encrypt_to_file(data)

            update_tree_view()

        def clear_entries():
            service_entry.delete(0, tk.END)
            username_entry.delete(0, tk.END)
            account_password_entry.delete(0, tk.END)

        def delete_group():
            global DELIMITER
            global NEW_LINER

            groups = []

            if messagebox.askyesno("Delete", "Are you sure you want to delete this group?"):

                if not show_all_button.cget('text') == "Show All":
                    selected_items = info_tree.selection()
                    for item in selected_items:
                        details = info_tree.item(item)["values"]
                        if len(details) == 3:
                            group = [details[0], details[1], details[2]]
                            groups.append(group)
                    for group in groups:
                        encrypt_decrypt.remove_from_file(f"{group[0]}{DELIMITER}{group[1]}{DELIMITER}{group[2]}{NEW_LINER}")
                        update_tree_view()
                else:
                    selected_items = info_tree.selection()
                    data_shown = get_data_shown()
                    data_hidden = get_data_hidden()
                    for item in selected_items:
                        details = info_tree.item(item)["values"]
                        index = data_hidden.index([details[0], details[1], details[2]])
                        data = data_shown[index]
                        encrypt_decrypt.remove_from_file(f"{data[0]}{DELIMITER}{data[1]}{DELIMITER}{data[2]}{NEW_LINER}")
                    update_tree_view()

        def check_all():
            if has_all.get():
                has_lowercase.set(1)
                has_uppercase.set(1)
                has_numbers.set(1)
                has_symbols.set(1)

        def uncheck_all_checkbutton():
            if has_lowercase.get() == 0 or has_uppercase.get() == 0 or has_numbers.get() == 0 or has_symbols.get() == 0:
                has_all.set(0)

        def show_all():
            if show_all_button.cget('text') == "Show All":
                show_all_button.config(text="Hide All")
                update_tree_view_shown()

            else:
                show_all_button.config(text="Show All")
                update_tree_view_hidden()

        def logout():
            wants_out = messagebox.askyesno("Logout", "Are you sure you want to logout?")
            if wants_out:
                username_entry.delete(0, tk.END)
                service_entry.delete(0, tk.END)
                account_password_entry.delete(0, tk.END)
                account_page.place_forget()
                password_entry.focus_set()
                home_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        # ------------------------------- ACCOUNT FUNCTIONS -----------------------------------
        # ------------------------------- REGISTER FUNCTIONS -----------------------------------
        def verify():
            global self_register_code
            email = email_entry.get()
            _password = password_entry.get()
            entry = code_entry.get()
            if entry == self_register_code:
                User().create_user(email, _password)
                code_label.config(text="Verification Complete!")
                feedback_label.config(text="user: " + email)
                time.sleep(3)
                code_entry.delete(0, tk.END)
                register_page.place_forget()
                home_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
            else:
                messagebox.showerror("Invalid", "You have entered the incorrect code.")

        def resend():
            global self_register_code
            email = email_entry.get()
            self_register_code = Verifier().send_code(email)
            messagebox.showinfo("Resent", "Resent code to " + email + ".")

        # ------------------------------- REGISTER FUNCTIONS -----------------------------------

        FONT = ("Segoe UI", 25)
        FONT_BOLD = ("Segoe UI", 25, 'bold')
        ENTRY_FONT_SMALL = ("Segoe UI", 15)
        ENTRY_FONT = ("Segoe UI", 20)
        ENTRY_FONT_LARGE = ("Segoe UI", 39)
        WINDOW_WIDTH = 750
        WINDOW_HEIGHT = 760

        # Window
        window = tb.Window(themename="superhero", title="Perles Password Manager", resizable=(False, False))

        # Center window
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = int((screen_width / 2) - (WINDOW_WIDTH / 2))
        y = int((screen_height / 2) - (WINDOW_HEIGHT / 2))
        window.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y-50}")

        myappid = u'perlescompany.perlesapplication.perlespasswordmanager.1'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        window.iconbitmap("Images/lock_icon.ico")

        img_eye_open = ImageTk.PhotoImage(Image.open("Images/eye_open.png").resize((50, 30)))
        lock_img = ImageTk.PhotoImage(Image.open("Images/Lock.png").resize((175, 175)))
        small_lock_img = ImageTk.PhotoImage(Image.open("Images/Lock.png").resize((70, 70)))

        success_style = tb.Style()
        success_style.configure('success.TButton', font=("Segoe UI", 10), parent=window)

        danger_style = tb.Style()
        danger_style.configure('danger.Outline.TButton', font=("Segoe UI", 10), parent=window)

        primary_style = tb.Style()
        primary_style.configure('primary.TButton', font=("Segoe UI", 10), parent=window)

        info_style = tb.Style()
        info_style.configure('info.TButton', font=("Segoe UI", 10), parent=window)

        warning_style = tb.Style()
        warning_style.configure('warning.TButton', font=("Segoe UI", 10), parent=window)

        # ---------------------------------- HOME PAGE ---------------------------------------
        home_page = tk.Frame(window, width=window.winfo_width()-20, height=window.winfo_height()-20)

        logo_frame = tk.Frame(home_page)
        logo_frame.pack(pady=(20, 20))
        lock_label = tk.Label(
            logo_frame,
            image=lock_img,
        )
        lock_label.grid(row=0, column=0)

        login_frame = tk.Frame(home_page)
        login_frame.pack(pady=20)

        # email label
        email_label = tb.Label(
            login_frame,
            text="Email",
            font=FONT_BOLD,

        )
        email_label.grid(row=0, column=0, pady=2, sticky="w")

        # email entry
        email_entry = tb.Entry(
            login_frame,
            font=ENTRY_FONT_SMALL,
            width=50
        )
        email_entry.grid(row=1, column=0, columnspan=2, sticky="ew")
        email_entry.bind("<Return>", lambda event: on_enter(event, entry=password_entry))
        if os.path.exists(LAST_SESSION_FILE):
            data = DataManager().extract_from_file(LAST_SESSION_FILE)
            email_entry.insert(0, data)

        password_label = tb.Label(
            login_frame,
            text="Password",
            font=FONT_BOLD
        )
        password_label.grid(row=4, column=0, pady=(20, 2), sticky="w")

        password_entry = tb.Entry(
            login_frame,
            font=ENTRY_FONT_SMALL,
            show="*",
            width=40
        )
        password_entry.bind("<Return>", lambda event: on_enter(event, entry=service_entry))
        password_entry.grid(row=5, column=0, sticky="ew", padx=5)
        password_entry.focus_set()

        password_view_button = tk.Button(
            login_frame,
            image=img_eye_open,
            compound=tk.CENTER,
            border=0,
            borderwidth=0,
            bg="SystemButtonFace",
            command=view_login_password,
        )
        password_view_button.grid(row=5, column=1, sticky="ens")

        home_buttons_frame = tk.Frame(home_page)
        home_buttons_frame.pack()

        login_button = tb.Button(
            home_buttons_frame,
            text="Login",
            style='primary.TButton',
            width=10,
            command=login
        )
        login_button.grid(row=6, column=0, pady=30, padx=10)

        register_button = tb.Button(
            home_buttons_frame,
            text="Register",
            style='primary.TButton',
            width=10,
            command=register_window
        )
        register_button.grid(row=6, column=1)

        home_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        # ---------------------------------- HOME PAGE ---------------------------------------
        # ---------------------------------- REGISTER PAGE ---------------------------------------
        register_page = tk.Frame(window)

        register_frame = tk.Frame(
            register_page
        )
        register_frame.pack(pady=50)

        # User Input

        code_label = tb.Label(
            register_frame,
            text="Verification Code",
            font=FONT_BOLD
        )
        code_label.grid(row=0, column=0, sticky="w", columnspan=2)

        feedback_label = tb.Label(
            register_frame,
            text="Enter the code sent to your email.",
            font=("Segoe UI", 13)
        )
        feedback_label.grid(row=1, column=0, sticky="w", columnspan=2)

        code_entry = tb.Entry(
            register_frame,
            font=ENTRY_FONT_SMALL,
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
            width=15,
            command=resend
        )
        resend_button.grid(row=3, column=1, pady=20)

        register_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        register_page.place_forget()
        # ---------------------------------- REGISTER PAGE ------------------------------------
        # ---------------------------------- ACCOUNT PAGE ------------------------------------
        account_page = tk.Frame(window)

        # Welcome
        welcome_label = tb.Label(
            account_page,
            image=small_lock_img,
        )
        welcome_label.pack(pady=(5, 0))

        # ENTRY FRAME

        # Frame
        entry_fields = tk.Frame(
            account_page
        )
        entry_fields.pack(pady=(25, 0))

        # Service Label
        service_label = tb.Label(
            entry_fields,
            text="Service",
            font=ENTRY_FONT_SMALL
        )
        service_label.grid(row=0, column=0, padx=10, pady=(0, 0), sticky="w")

        # Username Label
        username_label = tb.Label(
            entry_fields,
            text="Username/Email",
            font=ENTRY_FONT_SMALL
        )
        username_label.grid(row=0, column=1, padx=10, pady=(0, 0), sticky="w")

        # Password Label
        password_label = tb.Label(
            entry_fields,
            text="Password",
            font=FONT_BOLD,
        )
        password_label.grid(row=2, column=0, padx=10, pady=(15, 0), sticky="w")

        # Password Strength Label
        password_strength_label = tb.Label(
            entry_fields,
            text="(strength)",
            font=("Segoe UI", 10)
        )
        password_strength_label.grid(row=2, column=1, sticky="se", padx=(0, 15))

        # Service entry
        service_entry = tb.Entry(
            entry_fields,
            font=ENTRY_FONT_SMALL,
            width=21
        )
        service_entry.bind("<Return>", lambda event: on_enter(event, username_entry))
        service_entry.grid(row=1, column=0, padx=10, pady=0, sticky="ew")

        # Username entry
        username_entry = tb.Entry(
            entry_fields,
            font=ENTRY_FONT_SMALL,
            width=21
        )
        username_entry.bind("<Return>", lambda event: on_enter(event, account_password_entry))
        username_entry.grid(row=1, column=1, padx=10, pady=0, sticky="ew")

        # Password entry
        account_password_entry = tb.Entry(
            entry_fields,
            font=ENTRY_FONT_LARGE,
            width=23
        )
        account_password_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=0, sticky="w")
        account_password_entry.bind("<Key>", check_strength_event)

        # Menu options frame
        menu_options_frame = tk.Frame(
            account_page
        )
        menu_options_frame.pack(pady=(5, 0))

        # All checkbutton
        has_all = tk.IntVar(menu_options_frame)
        all_checkbutton = tb.Checkbutton(
            menu_options_frame,
            text="All",
            variable=has_all,
            onvalue=1,
            offvalue=0,
            command=check_all
        )
        all_checkbutton.grid(row=0, column=0, padx=10)

        # Lowercase checkbutton
        has_lowercase = tb.IntVar(menu_options_frame)
        lowercase_checkbutton = tb.Checkbutton(
            menu_options_frame,
            text="Lowercase",
            variable=has_lowercase,
            onvalue=1,
            offvalue=0,
            command=uncheck_all_checkbutton
        )
        lowercase_checkbutton.grid(row=0, column=1, padx=10)

        # uppercase checkbutton
        has_uppercase = tk.IntVar(menu_options_frame)
        uppercase_checkbutton = tb.Checkbutton(
            menu_options_frame,
            text="Uppercase",
            variable=has_uppercase,
            onvalue=1,
            offvalue=0,
            command=uncheck_all_checkbutton
        )
        uppercase_checkbutton.grid(row=0, column=2, padx=10)

        # Numbers checkbutton
        has_numbers = tk.IntVar(menu_options_frame)
        numbers_checkbutton = tb.Checkbutton(
            menu_options_frame,
            text="Numbers",
            variable=has_numbers,
            onvalue=1,
            offvalue=0,
            command=uncheck_all_checkbutton
        )
        numbers_checkbutton.grid(row=0, column=3, padx=10)

        # Symbols checkbutton
        has_symbols = tk.IntVar(menu_options_frame)
        symbols_checkbutton = tb.Checkbutton(
            menu_options_frame,
            text="Symbols",
            variable=has_symbols,
            onvalue=1,
            offvalue=0,
            command=uncheck_all_checkbutton
        )
        symbols_checkbutton.grid(row=0, column=4, padx=10)

        # Length entry
        length_entry = tb.Entry(
            menu_options_frame,
            font=("Segoe UI", 10),
            width=2,
        )
        length_entry.grid(row=0, column=5, padx=(10, 0))
        length_entry.insert(0, "10")

        # Length label
        length_label = tb.Label(
            menu_options_frame,
            text="length",
            font=("Segoe UI", 11),
        )
        length_label.grid(row=0, column=6, padx=(0, 10))

        has_all.set(1)
        check_all()

        # ACTION BUTTONS FRAME

        # Action buttons frame
        action_buttons_frame = tk.Frame(
            account_page
        )
        action_buttons_frame.pack(pady=5)

        # Generate button
        generate_button = tb.Button(
            action_buttons_frame,
            text="Generate Password",
            style="primary.TButton",
            command=generate_password
        )
        generate_button.grid(row=0, column=0)

        # Copy button
        copy_button = tb.Button(
            action_buttons_frame,
            text="Copy Password",
            style="primary.TButton",
            command=copy_password
        )
        copy_button.grid(row=0, column=1, padx=10)

        # Clear All button
        clear_entries_button = tb.Button(
            action_buttons_frame,
            text="Clear",
            style="warning.TButton",
            command=clear_entries
        )
        clear_entries_button.grid(row=0, column=2, padx=(0, 10))

        # Save Group button
        save_group_button = tb.Button(
            action_buttons_frame,
            text="Save Group",
            style="success.TButton",
            command=save_group
        )
        save_group_button.grid(row=0, column=3,)

        # INFO TREE VIEW
        info_frame = tb.Frame(
            account_page
        )
        info_frame.pack(pady=(25, 5))

        # Tree view
        tree_style = tb.Style()
        tree_style.configure("tree_style.Treeview", font=('Segoe UI', 11), rowheight=20)  # Set font size for body text
        tree_style.configure("tree_style.Treeview.Heading", font=('Segoe UI', 14, 'bold'))  # Set font size for headings

        scrollbar = tb.Scrollbar(info_frame, orient=tb.VERTICAL)
        scrollbar.pack(side=tb.RIGHT, fill=tb.Y)

        columns = ("service", "email", "password")
        info_tree = tb.Treeview(
            info_frame,
            columns=columns,
            show="headings",
            height=9,
            yscrollcommand=scrollbar.set,
        )
        scrollbar.config(command=info_tree.yview)
        info_tree.config(style="tree_style.Treeview")
        info_tree.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)

        info_tree.heading("service", text="Service")
        info_tree.heading("email", text="Email/Username")
        info_tree.heading("password", text="Password")

        # Get info if it exists
        if os.path.exists(self_file):
            update_tree_view_hidden()

        # T.V. BUTTONS
        tv_buttons_frame = tb.Frame(
            account_page
        )
        tv_buttons_frame.pack(pady=5)

        show_all_button = tb.Button(
            tv_buttons_frame,
            text="Show All",
            style="primary.TButton",
            command=show_all
        )
        show_all_button.grid(row=0, column=2, padx=10)

        copy_password_tv_button = tb.Button(
            tv_buttons_frame,
            text="Copy Password",
            style="primary.TButton",
            command=copy_password_tv
        )
        copy_password_tv_button.grid(row=0, column=4)

        delete_group_button = tb.Button(
            tv_buttons_frame,
            text="Delete Group",
            style="warning.TButton",
            command=delete_group
        )
        delete_group_button.grid(row=0, column=5, padx=10)

        logout_button = tb.Button(
            tv_buttons_frame,
            text="Logout",
            style="danger.Outline.TButton",
            command=logout,
        )
        logout_button.grid(row=0, column=6)

        account_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        account_page.place_forget()

        # ---------------------------------- ACCOUNT PAGE ------------------------------------

        # Loop
        window.mainloop()


Home()
