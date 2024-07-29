import os.path
import tkinter as tk
import ttkbootstrap as tb
from EncryptDecrypt import EncryptDecrypt
from tkinter import messagebox
from User import User
from Password import Password
import pyperclip
from DataManager import DataManager
from PIL import Image, ImageTk

FONT = ("Futura", 25)
ENTRY_FONT_SMALL = ("Futura", 13)
ENTRY_FONT = ("Futura", 20)
ENTRY_FONT_LARGE = ("Futura", 39)
DELIMITER = "//~+~//"
NEW_LINER = "PERLES_FILE_MANAGER(SIGNATURE)"
WINDOW_WIDTH = 750
WINDOW_HEIGHT = 710



class Account:

    def __init__(self, email, password):
        self.user = User().get_user(email)
        self.password = password
        self.file = f"user_files/{User().get_user_file(email)}"
        encrypt_decrypt = EncryptDecrypt(self.password, self.file)

        def check_strength():
            data = Password().strength_score_color_description_feedback(password_entry.get())
            if len(data) != 0:
                password_strength_label.config(foreground=data[1])
                password_strength_label.config(text=data[2])

        def is_duplicate(service, _email, _password):
            li = [service, _email, _password]
            data = DataManager().deserialize(encrypt_decrypt.decrypt_from_file(), DELIMITER, NEW_LINER)
            return li in data

        # Functions
        def generate_password():
            try:
                length = int(length_entry.get())
                if length == 0:
                    length = 10
                if length <= 24:
                    new_password = Password.generate(has_lowercase.get(), has_uppercase.get(), has_numbers.get(),
                                                     has_symbols.get(), length)
                    password_entry.delete(0, len(password_entry.get()))
                    password_entry.insert(0, new_password)
                    # PASSWORD STRENGTH CHECK
                    if len(password_entry.get()) > 0:
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
            pyperclip.copy(password_entry.get())

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
            new_info = DataManager().li_of_li_to_li_to_tup(DataManager().deserialize(encrypt_decrypt.decrypt_from_file()
                                                                                     , DELIMITER, NEW_LINER))
            new_info.pop()
            new_info.sort(key=sort_by_second)
            return new_info

        def get_data_hidden():
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
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()

            # Character limit check
            if len(service) > 24:
                messagebox.showinfo("Character Limit Exceeded", "The service name has exceeded the\n"
                                                                "character limit of 24.")
                return None
            if len(username) > 24:
                messagebox.showinfo("Character Limit Exceeded", "The username/email has exceeded the\n"
                                                                "character limit of 24.")
                return None
            if len(password) > 24:
                messagebox.showinfo("Character Limit Exceeded", "The password has exceeded the\n"
                                                                "character limit of 24.")
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
            if os.path.exists(self.file):
                if is_duplicate(service, username, password):
                    if messagebox.askyesno("Duplicate", "This group is already saved. Save again?"):
                        pass
                    else:
                        return None

            data = DataManager().serialize(service, username, password, DELIMITER, NEW_LINER)
            encrypt_decrypt.encrypt_to_file(data)

            update_tree_view()

        def delete_group():
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
                window.destroy()
                from Home import Home
                Home()

        # Window
        window = tb.Window(themename="superhero")

        success_style = tb.Style()
        success_style.configure('success.TButton', font=("Futura", 16), parent=window)

        danger_style = tb.Style()
        danger_style.configure('danger.Outline.TButton', font=("Futura", 16), parent=window)

        primary_style = tb.Style()
        primary_style.configure('primary.TButton', font=("Futura", 16), parent=window)

        info_style = tb.Style()
        info_style.configure('info.TButton', font=("Futura", 16), parent=window)

        warning_style = tb.Style()
        warning_style.configure('warning.TButton', font=("Futura", 16), parent=window)

        # Center window
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = int((screen_width / 2) - (WINDOW_WIDTH / 2))
        y = int((screen_height / 2) - (WINDOW_HEIGHT / 2))

        window.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")
        window.title("Password Manager")
        window.resizable(False, False)

        # Welcome
        welcome_label = tb.Label(
            window,
            text="My Password Manager",
            font=FONT
        )
        welcome_label.pack(pady=(30, 0))

        # ---------------------------------ENTRY FRAME-------------------------------

        # Frame
        entry_fields = tk.Frame(
            window
        )
        entry_fields.pack(pady=(50, 0), padx=50)

        # Service Label
        service_label = tb.Label(
            entry_fields,
            text="Service",
            font=("Futura", 13)
        )
        service_label.grid(row=0, column=0, padx=10, pady=(0, 0), sticky="w")

        # Username Label
        username_label = tb.Label(
            entry_fields,
            text="Username/Email",
            font=("Futura", 13)
        )
        username_label.grid(row=0, column=1, padx=10, pady=(0, 0), sticky="w")

        # Password Label
        password_label = tb.Label(
            entry_fields,
            text="Password",
            font=FONT,
        )
        password_label.grid(row=2, column=0, padx=10, pady=(15, 0), sticky="w")

        # Password Strength Label
        password_strength_label = tb.Label(
            entry_fields,
            text="(strength)",
            font=("Futura", 10)
        )
        password_strength_label.grid(row=2, column=1, sticky="se", padx=(0, 15))

        # Service entry
        service_entry = tb.Entry(
            entry_fields,
            font=ENTRY_FONT,
            width=21
        )
        service_entry.grid(row=1, column=0, padx=10, pady=0)

        # Username entry
        username_entry = tb.Entry(
            entry_fields,
            font=ENTRY_FONT,
            width=21
        )
        username_entry.grid(row=1, column=1, padx=10, pady=0)

        # Password entry
        password_entry = tb.Entry(
            entry_fields,
            font=ENTRY_FONT_LARGE,
            width=23
        )
        password_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=0, sticky="w")
        password_entry.bind("<Key>", check_strength_event)

        # ---------------------------------CHECK BUTTONS FRAME-------------------------------

        # Menu options frame
        menu_options_frame = tk.Frame(
            window
        )
        menu_options_frame.pack(pady=(5, 0), padx=50)

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
            font=ENTRY_FONT_SMALL,
            width=2,
        )
        length_entry.grid(row=0, column=5, padx=(10, 0))
        length_entry.insert(0, "10")

        # Length label
        length_label = tb.Label(
            menu_options_frame,
            text="length",
            font=ENTRY_FONT_SMALL,
        )
        length_label.grid(row=0, column=6, padx=(0, 10))

        has_all.set(1)
        check_all()

        # ---------------------------------ACTION BUTTONS FRAME-------------------------------

        # Action buttons frame
        action_buttons_frame = tk.Frame(
            window
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

        # Save Group button
        save_group_button = tb.Button(
            action_buttons_frame,
            text="Save Group",
            style="success.TButton",
            command=save_group
        )
        save_group_button.grid(row=0, column=2,)

        # ---------------------------------INFO TREE VIEW-------------------------------
        info_frame = tb.Frame(
            window
        )
        info_frame.pack(padx=50, pady=(50, 5))

        # Tree view
        columns = ("service", "email", "password")
        info_tree = tb.Treeview(
            info_frame,
            columns=columns,
            show="headings"
        )
        info_tree.grid(row=0, column=0)

        info_tree.heading("service", text="Service")
        info_tree.heading("email", text="Email/Username")
        info_tree.heading("password", text="Password")

        # Get info if it exists
        if os.path.exists(self.file):
            print(get_data_hidden())
            update_tree_view_hidden()

        # ---------------------------------T.V. BUTTONS-------------------------------
        tv_buttons_frame = tb.Frame(
            window
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

        window.mainloop()
