#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""@author: satsuma.blog ."""
##############
# To Do List #
##############
# TODO bind command+ș, e, d, v to sign encrypt decrypt and verify
# TODO put popup titles in the class
# TODO fix binds
# TODO close popup menu button
from rsa_backend import (Message, Private_Key, Public_Key,
                         import_key, password_key, Key_Store)
import tkinter as tk
from tkinter import ttk, messagebox
from os import remove

###############
# Main Window #
###############


class Main_Window(object):
    """Represents the main gui window."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title('RSA cryptosystem')
        width = 800
        height = 600
        position_right = int(self.root.winfo_screenwidth()/2 - width/2)
        position_down = int(self.root.winfo_screenheight()/2 - height/2) - 50
        self.root.geometry("{}x{}+{}+{}".format(width, height,
                                                position_right, position_down))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        self.style = ttk.Style()
        self.theme_var = tk.StringVar()

        # Key selection
        key_selection_frame = ttk.Frame(self.root)
        key_selection_frame.columnconfigure(1, weight=1)
        key_selection_frame.grid(
            row=0, column=0,
            sticky=tk.N+tk.E+tk.S+tk.W,
            padx=10, pady=4)

        class Key_selection(object):
            def __init__(self, label: str, row: int,):
                ttk.Label(key_selection_frame, text=label).grid(
                    row=row, column=0,
                    sticky=tk.W)
                self.key_var = tk.StringVar()
                self.options = ttk.OptionMenu(key_selection_frame,
                                              self.key_var,
                                              "No Keys (click 'Import')")
                self.options.grid(
                    row=row, column=1,
                    sticky=tk.W+tk.E,
                    padx=25)

        self.private_key_selection = Key_selection("Private Key:", 0)
        self.public_key_selection = Key_selection("Public Key:", 1)

        class import_export_btns(object):
            def __init__(self, label, row):
                self.btn = tk.Button(key_selection_frame, text=label, padx=2)
                self.btn.grid(row=row, column=2)

        self.import_btn = import_export_btns('Import', 0)
        self.export_btn = import_export_btns('Export', 1)

        # Message and Ciphertext boxes
        message_frame = ttk.Frame(self.root)
        message_frame.grid(row=1, sticky=tk.N+tk.E+tk.S+tk.W, ipadx=2, ipady=2)
        [message_frame.columnconfigure(i, weight=1) for i in range(2)]
        message_frame.rowconfigure(0, weight=1)

        class Message_box(object):
            def __init__(self, label, column):
                self.frame = ttk.LabelFrame(message_frame, text=label)
                [self.frame.columnconfigure(i, weight=1) for i in range(2)]
                self.frame.rowconfigure(0, weight=1)
                self.frame.grid(
                    row=0, column=column,
                    sticky=tk.N+tk.E+tk.W+tk.S,
                    padx=2, pady=4)

                self.text = tk.Text(self.frame)
                self.text.grid(
                    row=0, column=0,
                    sticky=tk.N+tk.E+tk.S+tk.W,
                    columnspan=2)

        self.message_input = Message_box("Message:", 0)
        self.ciphertext_input = Message_box("Ciphertext:", 1)

        # Buttons
        class Lower_btn(object):
            """Represents the lower buttons."""

            def __init__(self, master, label: str, column: int):
                self.btn = ttk.Button(master, text=label)
                self.btn.grid(
                    row=1, column=column,
                    sticky=tk.E+tk.W,
                    padx=2, ipady=2)

        self.sign_btn = Lower_btn(self.message_input.frame, 'Sign', 0)
        self.encrypt_btn = Lower_btn(self.message_input.frame, 'Encrypt', 1)
        self.decrypt_btn = Lower_btn(self.ciphertext_input.frame, 'Decrypt', 0)
        self.verify_btn = Lower_btn(self.ciphertext_input.frame, 'Verify', 1)

    def update_key_OptionMenu(self):
        for i in range(2):
            key_selection = [self.private_key_selection,
                             self.public_key_selection][i]
            key_store = [Key_Store.private_keys, Key_Store.public_keys][i]
            if list(key_store) != []:
                key_selection.key_var.set(list(key_store)[0])
                key_selection.options["menu"].delete(0, tk.END)
                for key in list(key_store):
                    key_selection.options["menu"].add_command(
                        label=key,
                        command=tk._setit(key_selection.key_var, key))
            else:
                key_selection.key_var.set("No Keys (click 'Import')")
                key_selection.options["menu"].delete(0, tk.END)


main_window = Main_Window()

#################
# Other Windows #
#################


class Popup(object):
    """A general class for all of the other windows."""

    screen_width = main_window.root.winfo_screenwidth()
    screen_height = main_window.root.winfo_screenheight()

    def close_popup(self, event=None):
        self.window.withdraw()

    def title():
        return "No Title"

    def other_setup(self):
        pass

    def __init__(self):
        self.window = tk.Toplevel(main_window.root)
        self.window.title(self.title())
        width, height = self.set_size()
        position_right = int(Popup.screen_width/2 - width/2)
        position_down = int(Popup.screen_height/2 - height/2) - 150
        self.window.geometry(
            "{}x{}+{}+{}".format(width, height,
                                 position_right, position_down))
        self.add_widgets()
        self.other_setup()
        self.window.bind('<Command-Key-w>', self.close_popup)
        self.window.protocol("WM_DELETE_WINDOW", self.close_popup)


class view_window(Popup):
    """Represesnts the export keys window and the view public key"""

    def set_size(self):
        return 500, 300

    def add_widgets(self):
        self.text = tk.Text(self.window, height=100)
        self.text.pack(fill=tk.BOTH)


class function_window(Popup):
    """Represents severel windows, e.g. 'Import Key' window."""

    width = 450

    def other_setup(self):
        self.window.resizable(False, False)


class import_Popup(function_window):
    """Represents the import popup or new key window."""

    def set_size(self):
        return import_Popup.width, 165

    def add_widgets(self):
        label_frame = ttk.LabelFrame(self.window, text='Label')
        label_frame.pack(fill=tk.BOTH, padx=4)
        self.label_var = tk.StringVar()
        self.label_entry = tk.Entry(label_frame, textvariable=self.label_var)
        self.label_entry.pack(fill=tk.BOTH)
        self.label_entry.focus_set()

        key_frame = ttk.LabelFrame(self.window, text='Key')
        key_frame.pack(fill=tk.BOTH, padx=4)
        self.key_txt = tk.Text(key_frame, height=3)
        self.key_txt.pack(fill=tk.BOTH)

        option_frame = ttk.Frame(self.window)
        option_frame.pack()
        ttk.Label(option_frame, text="Bit length:").grid(column=0, row=0)
        self.bit_length_choice = tk.IntVar()
        ttk.OptionMenu(option_frame, self.bit_length_choice, 512,
                       256,
                       512,
                       1024,
                       2048,
                       4096).grid(column=1, row=0, padx=2, pady=6)

        self.new_key_btn, self.save_btn = [
            ttk.Button(option_frame,
                       text=["New Private Key", "Save"][i]) for i in range(2)]
        [[self.new_key_btn, self.save_btn][i].grid(column=i+2, row=0, padx=4)
         for i in range(2)]

    def new(self):
        self.key_txt.delete('1.0', tk.END)
        self.key_txt.insert('1.0', str(Private_Key(
            Bit_Length=self.bit_length_choice.get())))

    def save(self, event=None):
        key = import_key(self.key_txt.get('1.0', tk.END))
        label = self.label_var.get()
        label = ''.join([label[i] for i in range(len(label))
                         if label[i] != ' '])

        if label == '':
            messagebox.showwarning("Error", "Key must have a label")
            return
        if label in list(Key_Store.public_keys):
            if label in list(Key_Store.private_keys):
                answer = messagebox.askokcancel(
                    "Warning", "Private Key with that label already exists.\
                    Continuing will overwrite the old key.")
                if answer:
                    pass
                else:
                    return
            else:
                answer = messagebox.askokcancel(
                    "Warning", "Public Key with that label already exists.\
                    Continuing will overwrite the old key.")
                if answer:
                    pass
                else:
                    return

        if type(key) == Private_Key:
            Key_Store.private_keys[label] = key
            Key_Store.public_keys[label] = key.pub_key
            main_window.update_key_OptionMenu()
            self.close_popup()
            messagebox.showinfo(
                message=("Corresponding Public Key:\n\n" + str(key.pub_key) +
                         "\n\nshare it with people you want to be able to" +
                         "receive encrypted messages from"))
            Key_Store.write_keys()
        elif type(key) == Public_Key:
            Key_Store.public_keys[label] = key
            main_window.update_key_OptionMenu()
            self.close_popup()
            Key_Store.write_keys()
        else:
            messagebox.showwarning("Error", "No valid key entered.")
            return

    def other_setup(self):
        self.window.resizable(False, False)
        self.new_key_btn.configure(command=lambda: import_Popup.new(self))
        self.save_btn.configure(command=lambda: import_Popup.save(self))
        self.window.bind('<Return>', lambda x: import_Popup.save(self))


class delete_key_Popup(function_window):
    """Represents the delete key popup."""

    def set_size(self):
        return delete_key_Popup.width, 180

    def add_widgets(self):
        [self.window.columnconfigure(i, weight=1) for i in range(2)]

        self.priv_or_pub_var = tk.StringVar()
        radiobtn_labels = ['Private Key', 'Public Key']
        [ttk.Radiobutton(self.window,
                         text=radiobtn_labels[i],
                         var=self.priv_or_pub_var,
                         value=radiobtn_labels[i]).grid(
                             row=i, column=0,
                             sticky=tk.W,
                             padx=4, pady=2) for i in range(2)]

        self.selected_key = tk.StringVar()
        self.key_options = ttk.OptionMenu(self.window,
                                          self.selected_key, "No Keys")
        self.key_options.grid(
            row=2, column=0,
            columnspan=2,
            sticky=tk.W+tk.E,
            padx=6, pady=4)

        self.key_txt = tk.Text(self.window, height=4, state=tk.DISABLED)
        self.key_txt.grid(
            row=3, column=0,
            columnspan=2,
            sticky=tk.W+tk.E,
            padx=4)

        self.delete_keys_btn = ttk.Button(self.window, text="Delete All Keys")
        self.delete_keys_btn.grid(row=4, column=0)

        self.delete_key_btn = ttk.Button(self.window, text="Delete Key")
        self.delete_key_btn.grid(row=4, column=1)
        self.delete_key_btn["state"] = tk.DISABLED

    def update_key_options(self, *args):
        key_list = []
        if self.priv_or_pub_var.get() == 'Private Key':
            key_list = list(Key_Store.private_keys)
        if self.priv_or_pub_var.get() == 'Public Key':
            key_list = list(Key_Store.public_keys)
            for key in list(Key_Store.private_keys):
                if key in key_list:
                    key_list.remove(key)
        if key_list != []:
            self.key_options["menu"].delete(0, tk.END)
            self.selected_key.set(key_list[0])
            for key in key_list:
                self.key_options["menu"].add_command(label=key,
                                                     command=tk._setit(
                                                         self.selected_key,
                                                         key))
        if key_list == []:
            self.key_options["menu"].delete(0, tk.END)
            self.selected_key.set("No Keys")

    def update_key_txt(self, *args):
        self.key_txt["state"] = tk.NORMAL
        self.key_txt.delete('1.0', tk.END)
        if self.priv_or_pub_var.get() == 'Private Key':
            if self.selected_key.get() == "No Keys":
                self.delete_key_btn["state"] = tk.DISABLED
            else:
                self.key_txt.insert('1.0', Key_Store.private_keys[
                    self.selected_key.get()])
                self.delete_key_btn["state"] = tk.NORMAL
        if self.priv_or_pub_var.get() == 'Public Key':
            if self.selected_key.get() == "No Keys":
                self.delete_key_btn["state"] = tk.DISABLED
            else:
                self.key_txt.insert('1.0', Key_Store.public_keys[
                    self.selected_key.get()])
                self.delete_key_btn["state"] = tk.NORMAL
        self.key_txt["state"] = tk.DISABLED

    def delete_all_keys(self):
        answer = messagebox.askokcancel(
            title="WARNING!",
            message="WARNING!\nThis will delete all keys, public and private")
        if answer:
            Key_Store.private_keys = {}
            Key_Store.public_keys = {}
            Key_Store.write_keys()
            self.update_key_options()
            main_window.update_key_OptionMenu()
            self.close_popup()

    def delete_key(self, event=None):
        key = self.selected_key.get()
        if key == "No Keys":
            return
        if self.priv_or_pub_var.get() == 'Private Key':
            answer = messagebox.askokcancel(
                title="WARNING!",
                message=("WARNING!\nThis will delete the private key:\n" +
                         str(key) +
                         "\nAND it's corresponding public key:\n" +
                         str(Key_Store.public_keys[key])))
            if answer:
                del Key_Store.public_keys[key]
                del Key_Store.private_keys[key]
        if self.priv_or_pub_var.get() == 'Public Key':
            answer = messagebox.askokcancel(
                title="WARNING!",
                message="WARNING!\nThis will delete the public key:\n" +
                str(key))
            if answer:
                del Key_Store.public_keys[key]
        Key_Store.write_keys()
        self.update_key_options()
        main_window.update_key_OptionMenu()

    def other_setup(self):
        self.window.resizable(False, False)
        self.priv_or_pub_var.trace_add('write', self.update_key_options)
        self.selected_key.trace_add('write', self.update_key_txt)
        self.delete_keys_btn.configure(command=self.delete_all_keys)
        self.delete_key_btn.configure(command=self.delete_key)
        self.window.bind('<Return>', self.delete_key)


class password_window(function_window):
    """Represents the different password windows."""

    width = 400


class password_message(object):
    length = Key_Store.min_password_len
    short_message = 'password must be at least '+str(length)+' characters'
    no_match_message = 'passwords do not match'
    ok_password_message = 'password: OK'

    def __init__(self, master, password_var, re_enter_var, save_btn):
        label = ttk.Label(master)
        label.config(text=password_message.short_message, foreground='red')
        label.pack()
        save_btn["state"] = tk.DISABLED

        def check_match(*args):
            if len(password_var.get()) < Key_Store.min_password_len:
                label.config(text=password_message.short_message,
                             foreground='red')
                save_btn["state"] = tk.DISABLED
            elif password_var.get() != re_enter_var.get():
                label.config(text=password_message.no_match_message,
                             foreground='red')
                save_btn["state"] = tk.DISABLED
            else:
                label.config(text=password_message.ok_password_message,
                             foreground='green')
                save_btn["state"] = tk.NORMAL

        password_var.trace_add('write', check_match)
        re_enter_var.trace_add('write', check_match)


class change_password_Popup(password_window):
    """Represents the change password window."""

    def set_size(self):
        return change_password_Popup.width, 210

    def add_widgets(self):
        old_password_frame = ttk.LabelFrame(self.window, text='Old password')
        old_password_frame.pack(fill=tk.BOTH, padx=4)
        self.old_password_var = tk.StringVar()
        self.old_password_entry = tk.Entry(old_password_frame,
                                           textvariable=self.old_password_var,
                                           show="*")
        self.old_password_entry.pack(fill=tk.BOTH)
        self.old_password_entry.focus_set()

        new_password_frame = ttk.LabelFrame(self.window, text='New password')
        new_password_frame.pack(fill=tk.BOTH, padx=4)
        self.new_password_var = tk.StringVar()
        tk.Entry(new_password_frame,
                 textvariable=self.new_password_var,
                 show="*").pack(fill=tk.BOTH)

        re_enter_frame = ttk.LabelFrame(self.window,
                                        text='Re-enter new password')
        re_enter_frame.pack(fill=tk.BOTH, padx=4)
        self.re_enter_var = tk.StringVar()
        tk.Entry(re_enter_frame,
                 textvariable=self.re_enter_var, show="*").pack(fill=tk.BOTH)

        self.save_btn = ttk.Button(self.window, text="Save")
        password_message(self.window,
                         self.new_password_var, self.re_enter_var,
                         self.save_btn)
        self.save_btn.pack()
        self.save_btn["state"] = tk.DISABLED

    def save(self, event=None):
        if len(self.new_password_var.get()) >= Key_Store.min_password_len \
            and self.new_password_var.get() == self.re_enter_var.get() \
                and self.old_password_var.get() == Key_Store.password:
            Key_Store.password = self.new_password_var.get()
            Key_Store.password_pub_key = password_key(
                self.new_password_var.get()).pub_key
            self.close_popup()
            Key_Store.write_keys()
            Key_Store.read_keys()
            main_window.update_key_OptionMenu()

        elif self.old_password_var.get() != Key_Store.password:
            messagebox.showwarning(message="Incorrect password")

        else:
            return

    def other_setup(self):
        self.window.resizable(False, False)
        self.save_btn.configure(command=self.save)
        self.window.bind('<Return>', self.save)


class login_window(password_window):
    def close_popup(self, event=None):
        self.window.withdraw()
        main_window.root.destroy()


class set_password_Popup(login_window):
    def set_size(self):
        return set_password_Popup.width, 160

    def add_widgets(self):
        password_frame = ttk.LabelFrame(self.window, text='Password')
        password_frame.pack(fill=tk.BOTH, padx=4)
        self.password_var = tk.StringVar()
        password_entry = tk.Entry(password_frame,
                                  textvariable=self.password_var, show="*")
        password_entry.pack(fill=tk.BOTH)
        password_entry.focus_set()

        re_enter_frame = ttk.LabelFrame(self.window, text='Re-enter Password')
        re_enter_frame.pack(fill=tk.BOTH, padx=4)
        self.re_enter_var = tk.StringVar()
        tk.Entry(re_enter_frame,
                 textvariable=self.re_enter_var, show="*").pack(fill=tk.BOTH)

        self.save_btn = ttk.Button(self.window, text="Save")
        password_message(self.window,
                         self.password_var, self.re_enter_var,
                         self.save_btn)
        self.save_btn.pack()

    def save(self, event=None):
        if len(self.password_var.get()) >= Key_Store.min_password_len \
                and self.password_var.get() == self.re_enter_var.get():
            Key_Store.password = self.password_var.get()
            Key_Store.password_pub_key = password_key(
                self.password_var.get()).pub_key
            self.window.destroy()
            Key_Store.write_keys()
            main_window.root.deiconify()

    def other_setup(self):
        self.window.resizable(False, False)
        self.save_btn.configure(command=self.save)
        self.window.bind('<Return>', self.save)


class enter_password_Popup(login_window):
    def set_size(self):
        return enter_password_Popup.width, 90

    def add_widgets(self):
        password_frame = ttk.LabelFrame(self.window, text='Password')
        password_frame.pack(fill=tk.BOTH, padx=4)
        self.password_var = tk.StringVar()
        password_entry = tk.Entry(password_frame,
                                  textvariable=self.password_var, show="*")
        password_entry.pack(fill=tk.BOTH)
        password_entry.focus_set()

        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.BOTH, pady=2)
        [button_frame.columnconfigure(i, weight=1) for i in range(2)]

        self.reset_btn = ttk.Button(button_frame, text="Forgot password")
        self.reset_btn.grid(row=0, column=0)

        self.unlock_btn = ttk.Button(button_frame,
                                     text="Unlock")
        self.unlock_btn.grid(row=0, column=1)

    def unlock(self, event=None):
        Key_Store.password = self.password_var.get()
        try:
            Key_Store.read_keys()
            main_window.update_key_OptionMenu()
            self.window.destroy()
            main_window.root.deiconify()
        except:
            messagebox.showwarning(message="Incorrect password!")
            Key_Store.password = None
            self.password_var.set('')

    def reset(self):
        messagebox.showwarning(
            message="There is no way to recover your password encrypted keys!")
        answer = messagebox.askokcancel(
            message="WARNING!\nReset password?\nall keys will be lost")
        if answer:
            self.close_popup()
            remove(Key_Store.key_file)
            Key_Store.public_keys = Key_Store.private_keys = {}
            Key_Store.password = Key_Store.password_pub_key = None
            main_window.update_key_OptionMenu()
            set_password()

    def other_setup(self):
        self.window.resizable(False, False)
        self.reset_btn.configure(command=self.reset)
        self.unlock_btn.configure(command=self.unlock)
        self.window.bind('<Return>', self.unlock)

#################################
# Main Window Callback Functions#
#################################


def Sign(event=None):
    if main_window.private_key_selection.key_var.get() \
            not in Key_Store.private_keys:
        messagebox.showwarning(
            title="No Private Key",
            message="Select a private key")
        return
    priv_key = Key_Store.private_keys[
        main_window.private_key_selection.key_var.get()]

    message = Message(main_window.message_input.text.get('1.0', tk.END))
    priv_key.sign(message)
    main_window.message_input.text.delete('1.0', tk.END)
    main_window.message_input.text.insert('1.0', str(message))


main_window.root.bind_all('<Control-Key-S>', Sign)
main_window.sign_btn.btn.configure(command=Sign)


def Encrypt(event=None):
    if main_window.public_key_selection.key_var.get() \
            not in Key_Store.public_keys:
        messagebox.showwarning(
            title="No Public Key",
            message="Select a public key")
        return
    pub_key = Key_Store.public_keys[
        main_window.public_key_selection.key_var.get()]
    message = Message(main_window.message_input.text.get('1.0', tk.END))
    unsupported_chars = [i for i in message.string
                         if i not in Message.allowed_characters]
    unsupported_chars = list(dict.fromkeys(unsupported_chars))
    if unsupported_chars != []:
        messagebox.showwarning(
            title="Unsupported Character",
            message="ERROR!\nMessage contains unsupported character(s):\n" +
            ', '.join(unsupported_chars))
        return
    ciphertext = pub_key.encrypt(message)
    main_window.message_input.text.delete('1.0', tk.END)
    main_window.message_input.text.insert('1.0', ciphertext)


main_window.root.bind('<Control-Key-E>', Encrypt)
main_window.encrypt_btn.btn.configure(command=Encrypt)


def Decrypt(event=None):
    if main_window.private_key_selection.key_var.get() \
            not in Key_Store.private_keys:
        messagebox.showwarning(
            title="No Private Key",
            message="Select a private key")
        return
    priv_key = Key_Store.private_keys[
        main_window.private_key_selection.key_var.get()]
    ciphertext = main_window.ciphertext_input.text.get('1.0', tk.END)
    try:
        message = priv_key.decrypt(ciphertext)
    except:
        messagebox.showwarning(
            title="Wrong private key",
            message="Wrong private key")
        return
    message = priv_key.decrypt(ciphertext)
    main_window.ciphertext_input.text.delete('1.0', tk.END)
    main_window.ciphertext_input.text.insert('1.0', str(message))


main_window.root.bind_all('<Control-Key-D>', Decrypt)
main_window.decrypt_btn.btn.configure(command=Decrypt)


def Verify(event=None):
    message = Message(main_window.ciphertext_input.text.get('1.0', tk.END))
    verify_txt = message.verify()

    messagebox.showinfo("Signature verification", verify_txt)


main_window.root.bind_all('<Control-Key-V>', Verify)
main_window.verify_btn.btn.configure(command=Verify)


def Import(event=None):
    import_popup = import_Popup("Import Key")
    if event:
        import_popup.new()
    else:
        import_popup.key_txt.delete('1.0', tk.END)


main_window.root.bind_all('<Control-Key-N>', Import)
main_window.import_btn.btn.configure(command=Import)


def Export():
    text = 'Public Key(s):\n'
    for key_label in Key_Store.public_keys:
        text += ('\n' + str(key_label) +
                 '\n' + str(Key_Store.public_keys[key_label]) +
                 '\n')
    text += '\nPrivate Key(s):\n'
    for key_label in Key_Store.private_keys:
        text += ('\n' + str(key_label) +
                 '\n' + str(Key_Store.private_keys[key_label]) +
                 '\n')

    export_popup = view_window("Keys")
    export_popup.text.insert('1.0', text)
    export_popup.text["state"] = tk.DISABLED


main_window.export_btn.btn.configure(command=Export)


def view_pub_keys():
    text = 'Your Public Key(s):\n'
    for key_label in Key_Store.private_keys:
        text += ('\n' + str(key_label) +
                 '\n' + str(Key_Store.private_keys[key_label].pub_key) +
                 '\n')

    pub_key_popup = view_window('Public Key(s)')
    pub_key_popup.text.insert('1.0', text)
    pub_key_popup.text["state"] = tk.DISABLED


def Delete_Key(event=None):
    if Key_Store.private_keys == {} or Key_Store.public_keys == {}:
        messagebox.showwarning(message="No keys to delete")
        return
    delete_key_Popup("Delete Key")


def set_password():
    set_password_Popup("Set Password")


def enter_password():
    enter_password_Popup("Enter Password")


def change_password():
    if Key_Store.password is None:
        messagebox.showwarning(message="Unlock app first")
        return
    change_password_Popup("Change Password")


def reset():
    messagebox.showwarning(
        message="This will delete all saved keys and reset your password")
    answer = messagebox.askokcancel(
        message="WARNING!\nReset password?\nall keys will be lost")
    if answer:
        main_window.root.withdraw()
        remove(Key_Store.key_file)
        Key_Store.public_keys = Key_Store.private_keys = {}
        Key_Store.password = Key_Store.password_pub_key = None
        main_window.update_key_OptionMenu()
        set_password()


def set_theme(*args):
    theme = main_window.theme_var.get()
    main_window.style.theme_use(theme)


main_window.theme_var.trace_add('write', set_theme)


def clear(text_input):
    text_input.text.delete('1.0', tk.END)


def clear_Message():
    clear(main_window.message_input)


def clear_Ciphertext():
    clear(main_window.ciphertext_input)


def clear_Both(event=None):
    clear_Message()
    clear_Ciphertext()


main_window.root.bind_all('<Command-Key-BackSpace>', clear_Both)

########
# Menu #
########


menu = tk.Menu(main_window.root, tearoff=0)
main_window.root.configure(menu=menu)

keys_menu = tk.Menu(menu, tearoff=0)
keys_menu.add_command(label='View public keys', command=view_pub_keys)
keys_menu.add_command(label='New key', command=lambda: Import('event'),
                      accelerator="Command+N")
keys_menu.add_command(label='Delete key', command=Delete_Key)
keys_menu.add_command(label='Save key(s)', command=Key_Store.write_keys)
menu.add_cascade(label='Keys', menu=keys_menu)

view_menu = tk.Menu(menu, tearoff=0)
theme_menu = tk.Menu(menu, tearoff=0)
for theme in main_window.style.theme_names():
    theme_menu.add_radiobutton(label=theme,
                               value=theme,
                               variable=main_window.theme_var)
view_menu.add_cascade(label='Theme', menu=theme_menu)
menu.add_cascade(label='View', menu=view_menu)

clear_menu = tk.Menu(menu, tearoff=0)
clear_menu.add_command(label="Clear Message", command=clear_Message)
clear_menu.add_command(label="Clear Ciphertext", command=clear_Ciphertext)
clear_menu.add_command(label="Clear All",
                       command=clear_Both,
                       accelerator="command+BackSpace")
menu.add_cascade(label='Clear', menu=clear_menu)

option_menu = tk.Menu(menu, tearoff=0)
option_menu.add_command(label="Change password", command=change_password)
option_menu.add_command(label="Reset", command=reset)
menu.add_cascade(label='Options', menu=option_menu)


#################
# Launching GUI #
#################


def launch_GUI():
    main_window.root.withdraw()
    try:
        with open(Key_Store.key_file, 'x') as f:
            f.close()
            pass
        set_password()
    except:
        with open(Key_Store.key_file, 'r') as f:
            if 'ciphertext' not in f.read():
                set_password()
            else:
                enter_password()
            f.close()
            pass
    main_window.update_key_OptionMenu()
    main_window.root.mainloop()
    # Exiting GUI
    Key_Store.write_keys()
    objects = list(globals())
    for obj in objects:
        if not obj.startswith("__"):
            del globals()[obj]
    del obj, objects


if __name__ == '__main__':
    launch_GUI()
