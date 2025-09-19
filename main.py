# -*- coding: utf-8 -*-
import socket
import time
import Tkinter as tk
import tkMessageBox
import tkSimpleDialog
import json
import os
import codecs
import webbrowser
import re
import struct
import os
from datetime import datetime
import hashlib
import hmac
import random
import base64

try:
    import pyaes
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False


class DMconnectClient:
    AES_KEY_SIZE = 32
    IV_SIZE = 16
    
    def __init__(self, master):
        self.master = master
        self.master.title("ExTO")
        
        try:
            self.master.iconbitmap("icon.ico")
        except:
            pass
        
        self.session_key = None
        self.mac_key = None
        self._enc_in_buf = ''
        menubar = tk.Menu(self.master)
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Connect", command=self.toggle_connection)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings", command=self.open_settings)
        tools_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        about_menu = tk.Menu(menubar, tearoff=0)
        about_menu.add_command(label="About ExTO", command=self.show_about_dialog)
        menubar.add_cascade(label="About", menu=about_menu)

        self.master.config(menu=menubar)

        main_frame = tk.Frame(self.master)
        main_frame.pack(fill="both", expand=True)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side="left", fill="y", padx=3, pady=3)

        self.nickname_label = tk.Label(left_frame, text="", anchor="w")
        self.nickname_label.pack(fill="x")

        self.search_entry = tk.Entry(left_frame)
        self.search_entry.pack(fill="x", pady=2)
        self.search_entry.bind("<KeyRelease>", self.filter_contacts)
        
        self.search_entry.insert(0, "Search contacts...")
        self.search_entry.config(fg="gray")
        
        self.search_entry.bind("<FocusIn>", self.on_search_focus_in)
        self.search_entry.bind("<FocusOut>", self.on_search_focus_out)
        self.search_entry.bind("<KeyPress>", self.on_search_key_press)

        self.friend_list = tk.Listbox(left_frame, width=25)
        self.friend_list.pack(fill="both", expand=True, pady=2)
        self.friend_list.insert("end", "Server")

        self.friend_list.bind("<<ListboxSelect>>", self.on_select_contact)
        
        self.contact_menu = tk.Menu(self.master, tearoff=0)
        
        add_icon = tk.PhotoImage(file="invite_friends.gif")
        remove_icon = tk.PhotoImage(file="remove_friend.gif")
        message_icon = tk.PhotoImage(file="chat.gif")
        
        self.contact_menu.add_command(label="Add Friend", image=add_icon, compound="left", command=self.add_friend_from_menu)
        self.contact_menu.add_command(label="Remove Friend", image=remove_icon, compound="left", command=self.remove_friend_from_menu)
        self.contact_menu.add_separator()
        self.contact_menu.add_command(label="Send Message", image=message_icon, compound="left", command=self.send_message_to_contact)
        
        self.menu_icons = [add_icon, remove_icon, message_icon]
        
        self.friend_list.bind("<Button-3>", self.show_contact_menu)

        icon_photo = tk.PhotoImage(file="invite_friends.gif")
        add_btn = tk.Button(left_frame, text="  Add Friend", image=icon_photo, compound="left", width=20, height=15, command=self.add_friend_from_menu)
        add_btn.image = icon_photo

        add_btn.pack(fill="x", padx=5, pady=2)


        right_frame = tk.Frame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=3, pady=3)

        self.contact_label = tk.Label(right_frame, text="Server", anchor="w")
        self.contact_label.pack(fill="x")

        self.chat_area = tk.Text(right_frame, state="disabled", wrap="word", cursor="xterm")
        self.chat_area.pack(fill="both", expand=True, pady=2)
        
        self.chat_area.tag_configure("timestamp", foreground="gray")
        self.chat_area.tag_configure("my_name", foreground="blue")
        self.chat_area.tag_configure("their_name", foreground="red")
        self.chat_area.tag_configure("message_text", foreground="black")
        self.chat_area.tag_configure("server_special", foreground="#009900")
        self.chat_area.tag_configure("error_message", foreground="red")
        self.chat_area.tag_configure("retry_link", foreground="blue", underline=True)
        self.chat_area.tag_configure("clickable_name", foreground="red")
        
        


        bottom_frame = tk.Frame(right_frame)
        bottom_frame.pack(fill="x")

        self.entry = tk.Text(bottom_frame, height=2, wrap="word")
        self.entry.pack(fill="x", padx=2, pady=2, side="left", expand=True)
        self.entry.bind("<Return>", self.handle_enter)
        self.entry.bind("<Shift-Return>", self.insert_newline)
        
        self.entry.insert("1.0", "Type a message...")
        self.entry.config(fg="gray")
        
        self.entry.bind("<FocusIn>", self.on_message_focus_in)
        self.entry.bind("<FocusOut>", self.on_message_focus_out)
        self.entry.bind("<KeyPress>", self.on_message_key_press)

        try:
            chat_icon = tk.PhotoImage(file="chat2.gif")
            send_btn = tk.Button(bottom_frame, image=chat_icon, command=self.send_message, width=32, height=32)
            send_btn.image = chat_icon
        except:
            send_btn = tk.Button(bottom_frame, text="Send", width=32, height=32, command=self.send_message)
        send_btn.pack(side="right", padx=2, pady=2)

        self.entry_menu = tk.Menu(self.master, tearoff=0)
        self.entry_menu.add_command(label="Cut", command=self.cut_text)
        self.entry_menu.add_command(label="Copy", command=self.copy_text)
        self.entry_menu.add_command(label="Paste", command=self.paste_text)
        self.entry_menu.add_separator()
        self.entry_menu.add_command(label="Select All", command=self.select_all_text)
        
        self.chat_menu = tk.Menu(self.master, tearoff=0)
        self.chat_menu.add_command(label="Copy", command=self.copy_text)
        self.chat_menu.add_separator()
        self.chat_menu.add_command(label="Select All", command=self.select_all_text)
        
        self.entry.bind("<Button-3>", self.show_entry_context_menu)
        self.chat_area.bind("<Button-3>", self.show_chat_context_menu)

        self.client_socket = None
        self.is_connected = False
        self.last_ping = time.time()
        self.current_username = ""
        self.message_count = 0
        self.reconnect_attempts = 0
        self.menubar = menubar
        self.tools_menu = tools_menu
        
        self.encryption_key = None
        self.is_encrypted = False
        
        self.current_contact = "Server"
        self.histories = {"Server": []}
        
        self.original_contacts = ["Server"]
        
        self.last_messages = {}
        self.settings_file = "settings.json"
        self.contacts_file = "contacts.json"
        self.history_file = "history.json"
        self.settings = self.load_settings()
        self.load_contacts()
        self.load_history()
        
        self.update_nickname_display()
        
        self.load_server_history()
        
        if self.settings.get("connection", {}).get("connect_when_possible", False):
            self.connect_to_server()

        self.poll_server()

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_entry_context_menu(self, event):
        try:
            self.entry_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.entry_menu.grab_release()

    def show_chat_context_menu(self, event):
        try:
            self.chat_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.chat_menu.grab_release()

    def copy_text(self):
        try:
            text = self.master.clipboard_get()
        except:
            text = ""
        
        if self.entry.focus_get() == self.entry:
            try:
                selected = self.entry.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.master.clipboard_clear()
                self.master.clipboard_append(selected)
            except:
                pass
        elif self.chat_area.focus_get() == self.chat_area:
            try:
                selected = self.chat_area.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.master.clipboard_clear()
                self.master.clipboard_append(selected)
            except:
                pass

    def paste_text(self):
        try:
            text = self.master.clipboard_get()
        except:
            return
        
        if self.entry.focus_get() == self.entry:
            try:
                self.entry.insert(tk.INSERT, text)
            except:
                pass

    def cut_text(self):
        if self.entry.focus_get() == self.entry:
            try:
                selected = self.entry.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.master.clipboard_clear()
                self.master.clipboard_append(selected)
                self.entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
            except:
                pass

    def select_all_text(self):
        if self.entry.focus_get() == self.entry:
            self.entry.tag_add(tk.SEL, "1.0", tk.END)
            self.entry.mark_set(tk.INSERT, "1.0")
            self.entry.see(tk.INSERT)
        elif self.chat_area.focus_get() == self.chat_area:
            self.chat_area.tag_add(tk.SEL, "1.0", tk.END)
            self.chat_area.mark_set(tk.INSERT, "1.0")
            self.chat_area.see(tk.INSERT)

    def on_search_focus_in(self, event):
        if self.search_entry.get() == "Search contacts...":
            self.search_entry.delete(0, tk.END)
            self.search_entry.config(fg="black")

    def on_search_focus_out(self, event):
        if self.search_entry.get() == "":
            self.search_entry.insert(0, "Search contacts...")
            self.search_entry.config(fg="gray")

    def on_search_key_press(self, event):
        if self.search_entry.get() == "Search contacts...":
            self.search_entry.delete(0, tk.END)
            self.search_entry.config(fg="black")

    def on_message_focus_in(self, event):
        if self.entry.get("1.0", "end-1c") == "Type a message...":
            self.entry.delete("1.0", tk.END)
            self.entry.config(fg="black")

    def on_message_focus_out(self, event):
        if self.entry.get("1.0", "end-1c") == "":
            self.entry.insert("1.0", "Type a message...")
            self.entry.config(fg="gray")

    def on_message_key_press(self, event):
        if self.entry.get("1.0", "end-1c") == "Type a message...":
            self.entry.delete("1.0", tk.END)
            self.entry.config(fg="black")

    def connect_to_server(self):
        try:
            if self.client_socket:
                self.client_socket.close()
            
            server_host = self.settings.get("connection", {}).get("address", "dmconnect.hoho.ws")
            server_port = int(self.settings.get("connection", {}).get("port", "42439"))
            
            enable_encryption = self.settings.get("connection", {}).get("enable_encryption", False)
            
            if enable_encryption and ENCRYPTION_AVAILABLE:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((server_host, server_port))
                d = self.client_socket.recv(2)
                if len(d) != 2:
                    raise Exception("Handshake failed: no A length")
                alen = struct.unpack('>H', d)[0]
                Ab = ''
                while len(Ab) < alen:
                    c = self.client_socket.recv(alen - len(Ab))
                    if not c:
                        raise Exception("Handshake failed: A read error")
                    Ab += c
                P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
                        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
                G = 2
                A = int(Ab.encode('hex'), 16)
                b = random.getrandbits(256)
                B = pow(G, b, P)
                Bh = hex(B)[2:].rstrip('L')
                if len(Bh) % 2:
                    Bh = '0' + Bh
                Bb = Bh.decode('hex')
                self.client_socket.send(struct.pack('>H', len(Bb)) + Bb)
                S = pow(A, b, P)
                Sh = hex(S)[2:].rstrip('L')
                if len(Sh) % 2:
                    Sh = '0' + Sh
                Sb = Sh.decode('hex')
                self.session_key = hashlib.sha256(Sb + "|KEY").digest()
                self.mac_key = hashlib.sha256(Sb + "|MAC").digest()
                self.encryption_key = self.session_key
                self.is_encrypted = True
            else:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((server_host, server_port))
                self.is_encrypted = False
                self.encryption_key = None
                if enable_encryption and not ENCRYPTION_AVAILABLE:
                    print "Encryption requested but pyaes library not available"
            self.client_socket.setblocking(0) 
            self.is_connected = True
            self.last_ping = time.time()
            self.reconnect_attempts = 0
            
            self.tools_menu.entryconfig(0, label="Disconnect")
            
            self.auto_login()
            
            
        except Exception as e:
            self.is_connected = False
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            error_msg = "Error: connection failed - %s" % str(e)
            if isinstance(error_msg, str):
                try:
                    error_msg = error_msg.decode('utf-8')
                except Exception:
                    try:
                        error_msg = error_msg.decode('cp1251')
                    except Exception:
                        error_msg = "Error: connection failed"
            self.show_error_message(error_msg, "Server")
            self.tools_menu.entryconfig(0, label="Connect")

    def disconnect_from_server(self, show_message=False):
        try:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            self.is_connected = False
            
            self.tools_menu.entryconfig(0, label="Connect")
            
            if show_message and self.settings.get("connection", {}).get("show_disconnect_msg", False):
                self.show_error_message("Error: connection lost", "Server")
            
            if show_message and self.settings.get("connection", {}).get("auto_reconnect", True):
                self.reconnect_attempts += 1
                if self.reconnect_attempts <= 10:
                    self.master.after(3000, self.connect_to_server)
                else:
                    self.reconnect_attempts = 0
            
        except Exception as e:
            print("Error during disconnect: %s" % str(e))

    def auto_login(self):
        login = self.settings.get("account", {}).get("login", "").strip()
        password = self.settings.get("account", {}).get("password", "").strip()
        
        if login and password:
            if " " in login or " " in password:
                self.show_error_message("Error: login and password cannot contain spaces", "Server")
                return
            
            def send_login():
                try:
                    enc_enabled = self.settings.get("connection", {}).get("password_encryption_enabled", False)
                    mode = self.settings.get("connection", {}).get("password_encryption", u"SHA-256").lower()
                    pw_to_send = password
                    if enc_enabled:
                        try:
                            if mode == u"base64":
                                pw_to_send = base64.b64encode(password.encode('utf-8'))
                            elif mode == u"md5":
                                pw_to_send = hashlib.md5(password.encode('utf-8')).hexdigest()
                            elif mode == u"sha-256":
                                pw_to_send = hashlib.sha256(password.encode('utf-8')).hexdigest()
                            elif mode == u"sha-512":
                                pw_to_send = hashlib.sha512(password.encode('utf-8')).hexdigest()
                        except Exception:
                            pw_to_send = password
                    if isinstance(pw_to_send, bytes):
                        try:
                            pw_to_send = pw_to_send.decode('utf-8')
                        except Exception:
                            pass
                    cmd = u"/login {0} {1}".format(login, pw_to_send)
                    self.send_data(cmd)
                except Exception as e:
                    self.show_error_message("Error: failed to send login command", "Server")
            
            self.master.after(200, send_login)

    def update_nickname_display(self):
        login = self.settings.get("account", {}).get("login", "").strip()
        if login:
            self.nickname_label.config(text=login)
            self.current_username = login
        else:
            self.nickname_label.config(text=u"Your nickname will be here!")
            self.current_username = ""

    def toggle_connection(self):
        if self.is_connected:
            self.disconnect_from_server()
        else:
            self.connect_to_server()

    def load_settings(self):
        default_settings = {
            "connection": {
                "address": u"dmconnect.hoho.ws",
                "port": u"42439",
                "protocol": u"8",
                "password": u"",
                "password_encryption_enabled": False,
                "password_encryption": u"MD5",
                "auto_reconnect": True,
                "connect_when_possible": False,
                "keepalive": True,
                "keepalive_interval": u"5",
                "show_disconnect_msg": True,
                "enable_encryption": False,
            },
            "account": {
                "login": u"",
                "password": u"",
                "disconnect_if_invalid": False
            },
            "interface": {
                "show_graphical_smilies": True
            }
        }
        
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    for key in default_settings:
                        if key not in loaded_settings:
                            loaded_settings[key] = default_settings[key]
                        else:
                            for subkey in default_settings[key]:
                                if subkey not in loaded_settings[key]:
                                    loaded_settings[key][subkey] = default_settings[key][subkey]
                    return loaded_settings
            else:
                return default_settings
        except Exception as e:
            print("Error loading settings: %s" % str(e))
            return default_settings

    def save_settings(self):
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print("Error saving settings: %s" % str(e))

    def load_contacts(self):
        try:
            if os.path.exists(self.contacts_file):
                with codecs.open(self.contacts_file, 'r', encoding='utf-8') as f:
                    contacts = json.load(f)
                    self.original_contacts = ["Server"] + [c for c in contacts if c != "Server"]
                    self.friend_list.delete(0, "end")
                    for contact in self.original_contacts:
                        self.friend_list.insert("end", contact)
        except Exception as e:
            print("Error loading contacts: %s" % str(e))

    def save_contacts(self):
        try:
            contacts = [c for c in self.original_contacts if c != "Server"]
            with codecs.open(self.contacts_file, 'w', encoding='utf-8') as f:
                json.dump(contacts, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("Error saving contacts: %s" % str(e))

    def open_contact_dialog(self, contact_name):
        if contact_name not in self.original_contacts:
            self.original_contacts.append(contact_name)
            self.save_contacts()
            try:
                self.filter_contacts()
            except Exception:
                self.friend_list.insert("end", contact_name)
        
        self.current_contact = contact_name
        self.contact_label.config(text=contact_name)
        
        for i in range(self.friend_list.size()):
            item = self.friend_list.get(i)
            if item == contact_name:
                self.friend_list.selection_clear(0, "end")
                self.friend_list.selection_set(i)
                self.friend_list.activate(i)
                break
        
        self.chat_area.config(state="normal")
        self.chat_area.delete("1.0", "end")
        
        for line in self.histories.get(self.current_contact, []):
            if self.current_contact != "Server":
                self.show_formatted_private_message(line, self.current_contact)
            else:
                self.show_formatted_server_message(line)
        
        self.chat_area.config(state="disabled")

    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with codecs.open(self.history_file, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
                    for contact, messages in history_data.items():
                        if contact not in self.histories:
                            self.histories[contact] = []
                        self.histories[contact] = messages[-5:]
        except Exception as e:
            print("Error loading history: %s" % str(e))

    def save_history(self):
        try:
            history_data = {}
            for contact, messages in self.histories.items():
                history_data[contact] = messages[-5:] 
            
            with codecs.open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("Error saving history: %s" % str(e))

    def load_server_history(self):
        if "Server" in self.histories and self.histories["Server"]:
            self.chat_area.config(state="normal")
            self.chat_area.delete("1.0", "end")
            
            for line in self.histories["Server"]:
                self.show_formatted_server_message(line)
            
            self.chat_area.config(state="disabled")


    def filter_contacts(self, event=None):
        search_text = self.search_entry.get().lower().strip()
        
        if search_text == "search contacts...":
            search_text = ""
        
        self.friend_list.delete(0, "end")
        
        if not search_text:
            for contact in self.original_contacts:
                self.friend_list.insert("end", contact)
        else:
            for contact in self.original_contacts:
                if search_text in contact.lower():
                    self.friend_list.insert("end", contact)

    def add_friend(self):
        name = self.search_entry.get().strip()
        if isinstance(name, str):
            try:
                name = name.decode('utf-8')
            except Exception:
                pass
        if name and name != "Server":
            if name not in self.original_contacts:
                self.original_contacts.append(name)
                self.friend_list.insert("end", name)
                self.save_contacts()
        self.search_entry.delete(0, "end")

    def add_friend_from_menu(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("Add to contacts")
        dialog.resizable(False, False)
        dialog.transient(self.master)
        dialog.grab_set()

        name_var = tk.StringVar()

        frame = tk.Frame(dialog, padx=10, pady=10)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame,
            text="Enter friend's name, which you want to add",
            anchor="w"
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        tk.Label(frame, text="Name").grid(row=1, column=0, sticky="w", padx=(0, 5))
        entry = tk.Entry(frame, textvariable=name_var, width=20)
        entry.grid(row=1, column=1, sticky="ew")
        entry.focus()

        def on_ok():
            name = name_var.get().strip()
            if name and name != "Server":
                if isinstance(name, str):
                    try:
                        name = name.decode("utf-8")
                    except Exception:
                        pass
                if name not in self.original_contacts:
                    self.original_contacts.append(name)
                    self.friend_list.insert("end", name)
                    self.save_contacts()
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        tk.Button(frame, text="Add", width=8, command=on_ok).grid(row=1, column=2, padx=(8, 0))

        frame.columnconfigure(1, weight=1)

        dialog.bind("<Return>", lambda e: on_ok())
        dialog.bind("<Escape>", lambda e: on_cancel())

        dialog.update_idletasks()
        w, h = dialog.winfo_width(), dialog.winfo_height()
        x = self.master.winfo_rootx() + (self.master.winfo_width() - w) // 2
        y = self.master.winfo_rooty() + (self.master.winfo_height() - h) // 2
        dialog.geometry("{}x{}+{}+{}".format(w, h + 5, x, y))

        self.master.wait_window(dialog)



    def remove_friend_from_menu(self):
        selection = self.friend_list.curselection()
        if selection:
            idx = selection[0]
            selected = self.friend_list.get(idx)
            if selected != "Server":
                if tkMessageBox.askyesno("Remove Friend", u"Are you sure you want to remove '{0}'?".format(selected)):
                    self.friend_list.delete(idx)
                    if selected in self.original_contacts:
                        self.original_contacts.remove(selected)
                        self.save_contacts()
                    
                    if self.current_contact == selected:
                        for i in range(self.friend_list.size()):
                            item = self.friend_list.get(i)
                            if item == "Server":
                                self.friend_list.selection_clear(0, "end")
                                self.friend_list.selection_set(i)
                                self.on_select_contact()
                                break

    def copy_username(self):
        selection = self.friend_list.curselection()
        if selection:
            idx = selection[0]
            name = self.friend_list.get(idx)
            self.master.clipboard_clear()
            self.master.clipboard_append(name)
            tkMessageBox.showinfo("Copied", "Username copied to clipboard!")

    def send_message_to_contact(self):
        selection = self.friend_list.curselection()
        if selection:
            idx = selection[0]
            selected = self.friend_list.get(idx)
            self.current_contact = selected
            self.contact_label.config(text=selected)
            
            
            self.chat_area.config(state="normal")
            self.chat_area.delete("1.0", "end")
            
            for line in self.histories.get(self.current_contact, []):
                if self.current_contact != "Server":
                    self.show_formatted_private_message(line, self.current_contact)
                else:
                    self.show_formatted_server_message(line)
            
            self.chat_area.config(state="disabled")
            self.chat_area.see("end")
            
            self.entry.focus_set()

    def show_contact_menu(self, event):
        index = self.friend_list.nearest(event.y)
        if index >= 0:
            self.friend_list.selection_clear(0, tk.END)
            self.friend_list.selection_set(index)
            self.friend_list.activate(index)

            contact_name = self.friend_list.get(index)
            self.current_contact = contact_name
        
        try:
            self.contact_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.contact_menu.grab_release()

    def retry_last_message(self, event=None):
        if self.current_contact != "Server" and self.current_contact in self.last_messages:
            last_msg = self.last_messages[self.current_contact]
            try:
                pm = u"/pm {0} {1}".format(self.current_contact, last_msg)
                self.send_data(pm)
                
                display_name = self.current_username if self.current_username else "Me"
                self.show_message(u"{0} → {1}: {2}".format(display_name, self.current_contact, last_msg),
                                  self.current_contact)
                
                self.remove_error_message()
                
            except Exception as e:
                tkMessageBox.showerror("Error", "Failed to retry message: %s" % str(e))

    def remove_error_message(self):
        try:
            last_line = self.chat_area.get("end-2c linestart", "end-1c")
            if "Error: can't send message" in last_line:
                self.chat_area.delete("end-2c linestart", "end-1c")
        except Exception:
            pass

    def remove_friend(self):
        selection = self.friend_list.curselection()
        if selection:
            idx = selection[0]
            selected = self.friend_list.get(idx)
            if selected != "Server": 
                self.friend_list.delete(idx)
                if selected in self.original_contacts:
                    self.original_contacts.remove(selected)
                    self.save_contacts()
                
                if self.current_contact == selected:
                    for i in range(self.friend_list.size()):
                        item = self.friend_list.get(i)
                        if item == "Server":
                            self.friend_list.selection_clear(0, "end")
                            self.friend_list.selection_set(i)
                            self.on_select_contact()
                            break

    def on_select_contact(self, event=None):
        selection = self.friend_list.curselection()
        if selection:
            idx = selection[0]
            selected = self.friend_list.get(idx)
            if isinstance(selected, str):
                try:
                    selected = selected.decode('utf-8')
                except Exception:
                    pass
            
            self.current_contact = selected
            self.contact_label.config(text=self.current_contact)

            self.chat_area.config(state="normal")
            self.chat_area.delete("1.0", "end")
            
            for line in self.histories.get(self.current_contact, []):
                if self.current_contact != "Server":
                    self.show_formatted_private_message(line, self.current_contact)
                else:
                    self.show_formatted_server_message(line)
            
            self.chat_area.config(state="disabled")
            self.chat_area.see("end")

    def format_private_message(self, msg, is_my_message=False, contact_name=None):
        current_time = datetime.now().strftime("%H:%M")
        
        if is_my_message:
            display_name = self.current_username if self.current_username else "Me"
            formatted = u"[{0}] <{1}> {2}".format(current_time, display_name, msg)
        else:
            formatted = u"[{0}] <{1}> {2}".format(current_time, contact_name, msg)
        
        return formatted

    def show_connection_error_message(self):
        contact = self.current_contact
        try:
            if isinstance(contact, str):
                try:
                    contact = contact.decode('utf-8')
                except Exception:
                    pass
        except Exception:
            pass

        if contact not in self.histories:
            self.histories[contact] = []
        
        current_time = datetime.now().strftime("%H:%M")
        error_text = "Error: not connected to server"
        connect_text = " [Connect]"
        full_message = error_text + connect_text
        self.histories[contact].append(full_message)

        if contact == self.current_contact:
            self.chat_area.config(state="normal")
            
            formatted = u"[{0}] {1}".format(current_time, error_text)
            
            start_pos = self.chat_area.index("end-1c")
            self.chat_area.insert("end", formatted)
            end_pos = self.chat_area.index("end-1c")
            
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            self.chat_area.tag_add("timestamp",
                                "{0}+{1}c".format(start_pos, time_start),
                                "{0}+{1}c".format(start_pos, time_end))
            
            error_start = time_end
            error_end = error_start + len(error_text)
            self.chat_area.tag_add("error_message",
                                "{0}+{1}c".format(start_pos, error_start),
                                "{0}+{1}c".format(start_pos, error_end))
            
            self.chat_area.insert("end", connect_text)
            connect_start = self.chat_area.index("end-{0}c".format(len(connect_text)))
            connect_end = self.chat_area.index("end-1c") 
            
            self.chat_area.tag_add("retry_link", connect_start, connect_end)
            
            self.chat_area.tag_bind("retry_link", "<Button-1>", lambda e: self.connect_to_server())
            self.chat_area.tag_bind("retry_link", "<Enter>", lambda e: self.chat_area.config(cursor="hand2"))
            self.chat_area.tag_bind("retry_link", "<Leave>", lambda e: self.chat_area.config(cursor="xterm"))
            
            self.chat_area.insert("end", u"\n")
            
            self.chat_area.see("end")
            self.chat_area.config(state="disabled")

    def show_error_message(self, msg, contact=None):
        if contact is None:
            contact = self.current_contact
        try:
            if isinstance(contact, str):
                try:
                    contact = contact.decode('utf-8')
                except Exception:
                    pass
        except Exception:
            pass

        if contact not in self.histories:
            self.histories[contact] = []
        self.histories[contact].append(msg)
        
        self.message_count += 1
        if self.message_count % 5 == 0:
            self.save_history()

        if contact == self.current_contact:
            self.chat_area.config(state="normal")
            
            current_time = datetime.now().strftime("%H:%M")
            formatted = u"[{0}] {1}".format(current_time, msg)
            
            start_pos = self.chat_area.index("end-1c")
            self.chat_area.insert("end", formatted + u"\n")
            end_pos = self.chat_area.index("end-1c")
            
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            self.chat_area.tag_add("timestamp",
                                "{0}+{1}c".format(start_pos, time_start),
                                "{0}+{1}c".format(start_pos, time_end))
            
            text_start = time_end
            self.chat_area.tag_add("error_message",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)
            
            self.chat_area.see("end")
            self.chat_area.config(state="disabled")

    def show_message(self, msg, contact=None):
        if contact is None:
            contact = self.current_contact
        try:
            if isinstance(contact, str):
                try:
                    contact = contact.decode('utf-8')
                except Exception:
                    pass
        except Exception:
            pass

        if contact not in self.histories:
            self.histories[contact] = []
        self.histories[contact].append(msg)
        
        self.message_count += 1
        if self.message_count % 5 == 0:
            self.save_history()

        if contact == self.current_contact:
            self.chat_area.config(state="normal")
            
            if contact != "Server":
                self.show_formatted_private_message(msg, contact)
            else:
                self.show_formatted_server_message(msg)
            
            self.chat_area.see("end")
            self.chat_area.config(state="disabled")

    def show_formatted_private_message(self, msg, contact):
        is_my_message = u" → " in msg and u": " in msg
        is_error = msg.startswith(u"Error:") or msg.startswith(u"Erorr:")
        
        if is_my_message:
            parts = msg.split(u" → ", 1)
            if len(parts) == 2:
                sender_name = parts[0]
                text_with_recipient = parts[1]
                if u": " in text_with_recipient:
                    text_part = text_with_recipient.split(u": ", 1)[1]
                else:
                    text_part = text_with_recipient
                
                current_time = datetime.now().strftime("%H:%M")
                formatted = u"[{0}] <{1}> {2}".format(current_time, sender_name, text_part)
            else:
                text_part = msg.split(u": ", 1)[1] if u": " in msg else msg
                formatted = self.format_private_message(text_part, True)
        elif is_error:
            current_time = datetime.now().strftime("%H:%M")
            formatted = u"[{0}] {1}".format(current_time, msg)
        else:
            if msg.startswith(u"[PM от "):
                parts = msg.split(u"] ", 1)
                if len(parts) == 2:
                    name_part = parts[0].replace(u"[PM от ", u"")
                    text_part = parts[1]
                    formatted = self.format_private_message(text_part, False, name_part)
                else:
                    formatted = msg
            else:
                formatted = msg

        if isinstance(formatted, str):
            try:
                formatted = formatted.decode("utf-8")
            except Exception:
                pass

        start_pos = self.chat_area.index("end-1c")
        
        if is_my_message:
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            name_start = formatted.find(u"<")
            name_end = formatted.find(u">") + 1
            text_start = name_end
            
            self.chat_area.insert("end", formatted[:text_start])
            time_name_end = self.chat_area.index("end-1c")
            
            message_text = formatted[text_start:]
            self.insert_text_with_smilies(message_text)
            end_pos = self.chat_area.index("end-1c")
            
        elif is_error:
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            text_start = time_end
            
            self.chat_area.insert("end", formatted[:text_start])
            time_end_pos = self.chat_area.index("end-1c")
            
            message_text = formatted[text_start:]
            self.insert_text_with_smilies(message_text)
            end_pos = self.chat_area.index("end-1c")
            
        else:
            self.insert_text_with_smilies(formatted)
            end_pos = self.chat_area.index("end-1c")

        if is_my_message:
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            name_start = formatted.find(u"<")
            name_end = formatted.find(u">") + 1
            
            self.chat_area.tag_add("timestamp",
                                "{0}+{1}c".format(start_pos, time_start),
                                "{0}+{1}c".format(start_pos, time_end))

            self.chat_area.tag_add("my_name",
                                "{0}+{1}c".format(start_pos, name_start),
                                "{0}+{1}c".format(start_pos, name_end))

            text_start = name_end
            self.chat_area.tag_add("message_text",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)
            
            self.chat_area.insert("end", u"\n")
        elif is_error:
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            self.chat_area.tag_add("timestamp",
                                "{0}+{1}c".format(start_pos, time_start),
                                "{0}+{1}c".format(start_pos, time_end))
            
            text_start = time_end
            self.chat_area.tag_add("error_message",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)
            
            self.chat_area.insert("end", u" [Retry]")
            retry_start = self.chat_area.index("end-8c") 
            retry_end = self.chat_area.index("end-1c")
            
            self.chat_area.tag_bind("retry_link", "<Button-1>", self.retry_last_message)
            self.chat_area.tag_bind("retry_link", "<Enter>", lambda e: self.chat_area.config(cursor="hand2"))
            self.chat_area.tag_bind("retry_link", "<Leave>", lambda e: self.chat_area.config(cursor="xterm"))
            
            self.chat_area.tag_add("retry_link", retry_start, retry_end)
            
            self.chat_area.insert("end", u"\n")
        else:
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            self.chat_area.tag_add("timestamp",
                                "{0}+{1}c".format(start_pos, time_start),
                                "{0}+{1}c".format(start_pos, time_end))

            name_start = formatted.find(u"<")
            name_end = formatted.find(u">") + 1
            self.chat_area.tag_add("their_name",
                                "{0}+{1}c".format(start_pos, name_start),
                                "{0}+{1}c".format(start_pos, name_end))

            text_start = name_end
            self.chat_area.tag_add("message_text",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)
            
            self.chat_area.insert("end", u"\n")

    def show_formatted_server_message(self, msg):
        if isinstance(msg, str):
            try:
                msg = msg.decode('utf-8')
            except Exception:
                pass
        current_time = datetime.now().strftime("%H:%M")

        is_special = msg.startswith(u"***")
        is_error = msg.startswith(u"Error:") or msg.startswith(u"Erorr:")
        is_usage = msg.startswith(u"Usage:")

        name = None
        text_part = None
        if not is_special and not is_error and not is_usage: 
            try:
                if u":" in msg:
                    possible_name, rest = msg.split(u":", 1)
                    possible_name = possible_name.strip()
                    if possible_name and (u" " not in possible_name):
                        name = possible_name
                        text_part = rest[2:] if rest.startswith(u": ") else rest[1:] if rest.startswith(u":") else rest
            except Exception:
                pass

        if name is not None:
            formatted = u"[{0}] <{1}>{2}".format(current_time, name, text_part)
        else:
            formatted = u"[{0}] {1}".format(current_time, msg)

        start_pos = self.chat_area.index("end-1c")
        
        if name is not None:
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            name_start = formatted.find(u"<")
            name_end = formatted.find(u">") + 1
            text_start = name_end
            
            self.chat_area.insert("end", formatted[:text_start])
            time_name_end = self.chat_area.index("end-1c")
            
            message_text = formatted[text_start:]
            self.insert_text_with_smilies(message_text)
            end_pos = self.chat_area.index("end-1c")
            
        else:
            time_start = formatted.find(u"[")
            time_end = formatted.find(u"]") + 1
            text_start = time_end
            
            self.chat_area.insert("end", formatted[:text_start])
            time_end_pos = self.chat_area.index("end-1c")
            
            message_text = formatted[text_start:]
            self.insert_text_with_smilies(message_text)
            end_pos = self.chat_area.index("end-1c")
        
        self.chat_area.insert("end", u"\n")

        time_start = formatted.find(u"[")
        time_end = formatted.find(u"]") + 1
        self.chat_area.tag_add("timestamp",
                            "{0}+{1}c".format(start_pos, time_start),
                            "{0}+{1}c".format(start_pos, time_end))

        if is_special:
            text_start = time_end
            self.chat_area.tag_add("server_special",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)
        elif is_error:
            text_start = time_end
            self.chat_area.tag_add("error_message",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)
        elif name is not None:
            name_start = formatted.find(u"<")
            name_end = formatted.find(u">") + 1
            if name == self.current_username:
                self.chat_area.tag_add("my_name",
                                    "{0}+{1}c".format(start_pos, name_start),
                                    "{0}+{1}c".format(start_pos, name_end))
            else:
                self.chat_area.tag_add("their_name",
                                    "{0}+{1}c".format(start_pos, name_start),
                                    "{0}+{1}c".format(start_pos, name_end))
                                    
                unique_tag = "clickable_name_" + str(id(name))
                self.chat_area.tag_add(unique_tag,
                                    "{0}+{1}c".format(start_pos, name_start),
                                    "{0}+{1}c".format(start_pos, name_end))
                self.chat_area.tag_bind(unique_tag, "<Button-1>", 
                                      lambda e, contact_name=name: self.open_contact_dialog(contact_name))
                self.chat_area.tag_bind(unique_tag, "<Enter>", 
                                      lambda e: self.chat_area.config(cursor="hand2"))
                self.chat_area.tag_bind(unique_tag, "<Leave>", 
                                      lambda e: self.chat_area.config(cursor="xterm"))
            text_start = name_end
            self.chat_area.tag_add("message_text",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)
        else:
            text_start = time_end
            self.chat_area.tag_add("message_text",
                                "{0}+{1}c".format(start_pos, text_start),
                                end_pos)

    def handle_enter(self, event=None):
        self.send_message()
        self.entry.mark_set(tk.INSERT, "1.0")
        return "break" 

    def insert_newline(self, event=None):
        self.entry.insert(tk.INSERT, "\n")
        return "break" 

    def replace_smilies(self, text):
        smilies_dict = {
            "smilies/smile.gif": [":-)", ":)"],
            "smilies/sad.gif": [":-(", ":("],
            "smilies/grin.gif": [":-D", ":D"],
            "smilies/tongue.gif": [":-P", ":P"],
            "smilies/blink.gif": [";-)", ";)"],
            "smilies/ass.gif": [":-*", ":*"],
            "smilies/beaver.gif": [":-B", ":B"],
            "smilies/dubious.gif": [":-\\", ":\\"],
            "smilies/eek.gif": [":-O", ":O"],
            "smilies/finger.gif": [":-|", ":|"],
            "smilies/gigi.gif": [":-X", ":X"],
            "smilies/glasses.gif": ["8-)", "8)"],
            "smilies/kiss.gif": [":-*", ":*"],
            "smilies/mad.gif": [":-@", ":@"],
            "smilies/noem.gif": [":-|", ":|"],
            "smilies/o-smile.gif": [":-o", ":o"],
            "smilies/sad.gif": [":-(", ":("],
            "smilies/smokie.gif": [":-S", ":S"],
            "smilies/what.gif": [":-?", ":?"]
        }
        
        smilies = {}
        for image_path, variants in smilies_dict.items():
            for variant in variants:
                smilies[variant] = image_path
        
        result = []
        current_pos = 0
        
        for smiley, image_path in smilies.items():
            while True:
                pos = text.find(smiley, current_pos)
                if pos == -1:
                    break
                    
                if pos > current_pos:
                    result.append(("text", text[current_pos:pos]))
                
                result.append(("smiley", image_path))
                
                current_pos = pos + len(smiley)
        
        if current_pos < len(text):
            result.append(("text", text[current_pos:]))
            
        return result

    def insert_text_with_smilies(self, text):
        show_graphical = self.settings.get("interface", {}).get("show_graphical_smilies", True)
        
        if not show_graphical:
            self.insert_text_with_links(text)
            return
        
        parts = self.replace_smilies(text)
        
        for part_type, content in parts:
            if part_type == "text":
                self.insert_text_with_links(content)
            elif part_type == "smiley":
                try:
                    smiley_image = tk.PhotoImage(file=content)
                    
                    image_name = "smiley_" + str(id(smiley_image))
                    self.chat_area.image_create("end", image=smiley_image, name=image_name)
                    setattr(self, image_name, smiley_image)
                except Exception:
                    self.chat_area.insert("end", content)

    def insert_text_with_links(self, text):
        url_pattern = r'(https?://[^\s]+)'
        
        parts = re.split(url_pattern, text)
        
        for part in parts:
            if re.match(url_pattern, part):
                start_pos = self.chat_area.index("end-1c")
                self.chat_area.insert("end", part)
                end_pos = self.chat_area.index("end-1c")
                
                self.chat_area.tag_add("link", start_pos, end_pos)
                self.chat_area.tag_configure("link", foreground="blue", underline=True)
                
                self.chat_area.tag_bind("link", "<Button-1>", lambda e, url=part: webbrowser.open(url))
                self.chat_area.tag_bind("link", "<Enter>", lambda e: self.chat_area.config(cursor="hand2"))
                self.chat_area.tag_bind("link", "<Leave>", lambda e: self.chat_area.config(cursor="xterm"))
            else:
                self.chat_area.insert("end", part)

    def send_message(self, event=None):
        msg = self.entry.get("1.0", "end-1c").strip()
        if isinstance(msg, str):
            try:
                msg = msg.decode('utf-8')
            except Exception:
                pass

        if msg == "Type a message...":
            msg = ""

        if msg:
            if not self.is_connected or not self.client_socket:
                self.show_connection_error_message()
                self.entry.delete("1.0", "end")
                return
                
            try:
                if self.current_contact == "Server":
                    if msg.startswith("/login "):
                        parts = msg.split(" ", 2)
                        if len(parts) >= 3:
                            login_arg = parts[1]
                            pwd_arg = parts[2]
                            enc_enabled = self.settings.get("connection", {}).get("password_encryption_enabled", False)
                            mode = self.settings.get("connection", {}).get("password_encryption", u"MD5").lower()
                            if enc_enabled:
                                try:
                                    if mode == u"base64":
                                        pwd_tx = base64.b64encode(pwd_arg.encode('utf-8'))
                                        try: pwd_tx = pwd_tx.decode('utf-8')
                                        except Exception: pass
                                    elif mode == u"md5":
                                        pwd_tx = hashlib.md5(pwd_arg.encode('utf-8')).hexdigest()
                                    elif mode == u"sha-256":
                                        pwd_tx = hashlib.sha256(pwd_arg.encode('utf-8')).hexdigest()
                                    elif mode == u"sha-512":
                                        pwd_tx = hashlib.sha512(pwd_arg.encode('utf-8')).hexdigest()
                                    else:
                                        pwd_tx = pwd_arg
                                except Exception:
                                    pwd_tx = pwd_arg
                                msg = u"/login {0} {1}".format(login_arg, pwd_tx)
                    if msg.startswith("/pm "):
                        parts = msg.split(" ", 2) 
                        if len(parts) >= 3:
                            target_name = parts[1]
                            message_text = parts[2]
                            
                            if isinstance(target_name, str):
                                try:
                                    target_name = target_name.decode('utf-8')
                                except Exception:
                                    pass
                            
                            if target_name not in self.original_contacts:
                                self.original_contacts.append(target_name)
                                if not self.search_entry.get().strip():
                                    self.friend_list.insert("end", target_name)
                                self.save_contacts()
                            
                            self.current_contact = target_name
                            self.contact_label.config(text=target_name)
                            
                            for i in range(self.friend_list.size()):
                                item = self.friend_list.get(i)
                                if item == target_name:
                                    self.friend_list.selection_clear(0, "end")
                                    self.friend_list.selection_set(i)
                                    break
                            
                            self.chat_area.config(state="normal")
                            self.chat_area.delete("1.0", "end")
                            
                            for line in self.histories.get(self.current_contact, []):
                                if self.current_contact != "Server":
                                    self.show_formatted_private_message(line, self.current_contact)
                                else:
                                    self.show_formatted_server_message(line)
                            
                            self.chat_area.config(state="disabled")
                            
                            pm = u"/pm {0} {1}".format(target_name, message_text)
                            self.send_data(pm)
                            
                            self.last_messages[target_name] = message_text
                            
                            display_name = self.current_username if self.current_username else "Me"
                            self.show_message(u"{0} → {1}: {2}".format(display_name, target_name, message_text),
                                              target_name)
                            
                            self.entry.focus_set()
                        else:
                            self.send_data(msg)
                    else:
                        self.send_data(msg)
                else:
                    contact = self.current_contact
                    if isinstance(contact, str):
                        try:
                            contact = contact.decode('utf-8')
                        except Exception:
                            pass
                    pm = u"/pm {0} {1}".format(contact, msg)
                    self.send_data(pm)
                    
                    self.last_messages[contact] = msg
                    
                    display_name = self.current_username if self.current_username else "Me"
                    self.show_message(u"{0} → {1}: {2}".format(display_name, contact, msg),
                                      contact)
            except Exception as e:
                try:
                    print(unicode(e))
                except Exception:
                    try:
                        print(str(e))
                    except Exception:
                        print(repr(e))
                self.disconnect_from_server(show_message=True)
        self.entry.delete("1.0", "end")

    def poll_server(self):
        if self.is_connected and self.client_socket:
            try:
                if self.is_encrypted and self.encryption_key:
                    try:
                        while True:
                            try:
                                chunk = self.client_socket.recv(4096)
                            except socket.error:
                                break
                            if not chunk:
                                break
                            self._enc_in_buf += chunk
                            while True:
                                if len(self._enc_in_buf) < 4:
                                    break
                                ln = struct.unpack('>I', self._enc_in_buf[:4])[0]
                                if len(self._enc_in_buf) < 4 + ln:
                                    break
                                frame = self._enc_in_buf[4:4+ln]
                                self._enc_in_buf = self._enc_in_buf[4+ln:]
                                if self.mac_key and ln >= 32:
                                    data_part, mac_part = frame[:-32], frame[-32:]
                                    exp = hmac.new(self.mac_key, data_part, hashlib.sha256).digest()
                                    if exp != mac_part:
                                        continue
                                    payload = data_part
                                else:
                                    payload = frame
                                msg = self.decrypt_message(payload, self.encryption_key)
                                if msg and msg.strip():
                                    clean = msg.replace("*Ping!*", "").strip()
                                    if clean:
                                        self.parse_message(clean)
                    except Exception:
                        pass
                else:
                    try:
                        while True:
                            try:
                                data = self.client_socket.recv(1024)
                            except socket.error:
                                break
                            if not data:
                                break
                            message = data.decode("utf-8").strip()
                            if message.replace("*Ping!*", "").strip():
                                clean = message.replace("*Ping!*", "")
                                self.parse_message(clean)
                    except Exception:
                        pass
            except socket.error as e:
                if e.errno == 10054 or e.errno == 10053:
                    self.disconnect_from_server(show_message=True)
                    return
                pass

            if self.settings.get("connection", {}).get("keepalive", True):
                keepalive_interval = int(self.settings.get("connection", {}).get("keepalive_interval", "5"))
                if time.time() - self.last_ping >= keepalive_interval:
                    try:
                        self.send_data(b"/")
                    except socket.error as e:
                        if e.errno == 10054 or e.errno == 10053:  
                            self.disconnect_from_server(show_message=True)
                            return
                    self.last_ping = time.time()

        self.master.after(100, self.poll_server)

    def parse_message(self, msg):
        try:
            lines = msg.splitlines()
        except Exception:
            lines = [msg]

        i = 0
        while i < len(lines):
            line = lines[i]
            if isinstance(line, str):
                try:
                    line = line.decode("utf-8")
                except Exception:
                    pass
            line = line.replace("*Ping!*", "").strip()
            if not line:
                i += 1
                continue

            if line.startswith("(Private)"):
                try:
                    prefix, text = line.split(":", 1)
                    name = prefix.replace("(Private)", "").strip()
                    if isinstance(name, str):
                        try:
                            name = name.decode('utf-8')
                        except Exception:
                            pass
                    text = text.strip()

                    j = i + 1
                    while j < len(lines):
                        cont = lines[j]
                        if isinstance(cont, str):
                            try:
                                cont = cont.decode('utf-8')
                            except Exception:
                                pass
                        if cont.startswith("(Private)"):
                            break
                        text += u"\n" + cont
                        j += 1

                    i = j

                    display = u"[PM от {0}] {1}".format(name, text)

                    names_u = []
                    for c in self.original_contacts:
                        if isinstance(c, str):
                            try:
                                cu = c.decode('utf-8')
                            except Exception:
                                cu = c
                        else:
                            cu = c
                        names_u.append(cu)

                    if name not in names_u:
                        self.original_contacts.append(name)
                        try:
                            self.filter_contacts()
                        except Exception:
                            self.friend_list.insert("end", name)
                        self.save_contacts()

                    self.current_contact = name
                    self.contact_label.config(text=name)
                    
                    for i in range(self.friend_list.size()):
                        item = self.friend_list.get(i)
                        if item == name:
                            self.friend_list.selection_clear(0, "end")
                            self.friend_list.selection_set(i)
                            break
                    
                    self.chat_area.config(state="normal")
                    self.chat_area.delete("1.0", "end")
                    
                    for line in self.histories.get(self.current_contact, []):
                        if self.current_contact != "Server":
                            self.show_formatted_private_message(line, self.current_contact)
                        else:
                            self.show_formatted_server_message(line)
                    
                    self.chat_area.config(state="disabled")
                    self.chat_area.see("end")
                    
                    self.show_message(display, name)
                    continue
                except Exception:
                    self.show_message(line, "Server")
                    i += 1
                    continue
            elif line.startswith("Private message sent to ") and line.endswith("."):
                i += 1
                continue
            elif line.startswith("Failed to send private message to ") and line.endswith("."):
                try:
                    target_name = line.replace("Failed to send private message to ", "").replace(".", "").strip()
                    if isinstance(target_name, str):
                        try:
                            target_name = target_name.decode('utf-8')
                        except Exception:
                            pass
                    
                    error_msg = u"Error: can't send message"
                    self.show_message(error_msg, target_name)
                except Exception:
                    self.show_message(line, "Server")
                i += 1
                continue
            elif line == "User does not exist.":
                error_msg = u"Error: user does not exist"
                self.show_message(error_msg, self.current_contact)
                i += 1
                continue
            elif line == "You cannot send private messages to yourself.":
                error_msg = u"Error: cannot send private messages to yourself"
                self.show_message(error_msg, self.current_contact)
                i += 1
                continue
            elif line == "This username is already in use.":
                self.show_error_message("Error: username already in use", "Server")
                if self.settings.get("account", {}).get("disconnect_if_invalid", False):
                    self.disconnect_from_server(show_message=False)
                i += 1
                continue
            elif line == "Invalid username or password.":
                self.show_error_message("Error: invalid username or password", "Server")
                if self.settings.get("account", {}).get("disconnect_if_invalid", False):
                    self.disconnect_from_server(show_message=False)
                i += 1
                continue
            elif line == "Login successful.":
                self.show_message("Login successful", "Server")
                login = self.settings.get("account", {}).get("login", "").strip()
                if login:
                    self.current_username = login
                self.update_nickname_display()
                i += 1
                continue
            elif line.startswith("Enter command (/login /register): "):
                response = line.replace("Enter command (/login /register): ", "").strip()
                if response == "This username is already in use.":
                    self.show_error_message("Error: username already in use", "Server")
                    if self.settings.get("account", {}).get("disconnect_if_invalid", False):
                        self.disconnect_from_server(show_message=False)
                elif response == "Invalid username or password.":
                    self.show_error_message("Error: invalid username or password", "Server")
                    if self.settings.get("account", {}).get("disconnect_if_invalid", False):
                        self.disconnect_from_server(show_message=False)
                elif response == "Login successful.":
                    self.show_message("Login successful", "Server")
                    login = self.settings.get("account", {}).get("login", "").strip()
                    if login:
                        self.current_username = login
                    self.update_nickname_display()
                elif response == "Registration successful. Please log in.":
                    self.show_message("Registration successful. Please log in.", "Server")
                elif response == "Username already taken. Try another.":
                    self.show_error_message("Error: username already taken", "Server")
                elif response.startswith("Usage:"):
                    self.show_error_message("Error: invalid command format", "Server")
                else:
                    self.show_message(response, "Server")
                i += 1
                continue
            else:
                self.show_message(line, "Server")
                i += 1
                continue

    def on_close(self):
        try:
            self.save_settings()
            self.save_history()
            if self.client_socket:
                self.client_socket.close()
        except:
            pass
        self.master.destroy()

    def open_settings(self):
        root = self.master
        dlg = tk.Toplevel(root)
        dlg.title(u"Settings")
        dlg.resizable(False, False)
        dlg.transient(root)
        dlg.grab_set()
        
        try:
            dlg.iconbitmap("settings.ico")
        except:
            pass

        if "connection" not in self.settings:
            self.settings["connection"] = {}
        if "account" not in self.settings:
            self.settings["account"] = {"login": u"", "password": u"", "disconnect_if_invalid": False}
        if "interface" not in self.settings:
            self.settings["interface"] = {"show_graphical_smilies": True}

        container = tk.Frame(dlg, padx=6, pady=6)
        container.pack(fill="both", expand=True)

        left = tk.Frame(container)
        left.pack(side="left", fill="y")
        cats = tk.Listbox(left, height=22, width=24, exportselection=False)
        cats.pack(side="top", fill="y")
        for name in [u"Connection", u"Account", u"Interface"]:
            cats.insert("end", name)
        cats.selection_set(0)

        btn_grid = tk.Frame(left, pady=6)
        btn_grid.pack(side="top")
        btn_ok = tk.Button(btn_grid, text=u"OK", width=10)
        btn_apply = tk.Button(btn_grid, text=u"Apply", width=10)
        btn_reset = tk.Button(btn_grid, text=u"Reset", width=10)
        btn_close = tk.Button(btn_grid, text=u"Close", width=10, command=dlg.destroy)
        btn_ok.grid(row=0, column=0, padx=(0, 6), pady=(0, 6))
        btn_apply.grid(row=0, column=1, pady=(0, 6))
        btn_reset.grid(row=1, column=0, padx=(0, 6))
        btn_close.grid(row=1, column=1)

        right = tk.Frame(container)
        right.pack(side="right", fill="both", expand=True, padx=(10, 0))

        pages = {}

        conn = tk.Frame(right)
        pages[u"Connection"] = conn
        conn.pack(fill="both", expand=True)

        content = tk.Frame(conn)
        content.pack(anchor="nw", padx=10, pady=10)

        conn_group = tk.LabelFrame(content, text=u"Parameters")
        conn_group.pack(fill="x", padx=0, pady=(0, 8))
        conn_group.grid_columnconfigure(1, minsize=160)
        tk.Label(conn_group, text=u"Host", anchor="w", width=10).grid(row=0, column=0, sticky="w")
        addr_var = tk.StringVar(value=self.settings.get("connection", {}).get("address", u"dmconnect.hoho.ws"))
        addr_entry = tk.Entry(conn_group, textvariable=addr_var, width=22)
        addr_entry.grid(row=0, column=1, sticky="w")
        tk.Label(conn_group, text=u"Port", anchor="w", width=10).grid(row=1, column=0, sticky="w", pady=(6, 0))
        port_var = tk.StringVar(value=self.settings.get("connection", {}).get("port", u"42439"))
        port_entry = tk.Entry(conn_group, textvariable=port_var, width=8)
        port_entry.grid(row=1, column=1, sticky="w", pady=(6, 5))

        opt_conn = tk.LabelFrame(content, text=u"Options")
        opt_conn.pack(fill="x", padx=0, pady=(0, 0))

        auto_rec_var = tk.IntVar(value=1 if self.settings["connection"].get("auto_reconnect", True) else 0)
        conn_poss_var = tk.IntVar(value=1 if self.settings["connection"].get("connect_when_possible", False) else 0)
        keepalive_var = tk.IntVar(value=1 if self.settings["connection"].get("keepalive", True) else 0)
        ka_int_var = tk.StringVar(value=self.settings["connection"].get("keepalive_interval", u"60"))
        show_drop_var = tk.IntVar(value=1 if self.settings["connection"].get("show_disconnect_msg", False) else 0)
        encryption_var = tk.IntVar(value=1 if self.settings["connection"].get("enable_encryption", False) else 0)
        if encryption_var.get():
            port_var.set("42440")
        else:
            port_var.set("42439")

        tk.Checkbutton(opt_conn, text=u"Auto-reconnect on disconnect", variable=auto_rec_var).pack(anchor="w", pady=(2, 2))
        tk.Checkbutton(opt_conn, text=u"Connect when possible", variable=conn_poss_var).pack(anchor="w", pady=(0, 2))
        
        ka_frame = tk.Frame(opt_conn)
        ka_frame.pack(anchor="w", pady=(0, 2))
        
        ka_row_lbl = tk.Checkbutton(ka_frame, text=u"Test packets every", variable=keepalive_var)
        ka_row_lbl.pack(side="left")
        ka_entry = tk.Entry(ka_frame, textvariable=ka_int_var, width=4)
        ka_entry.pack(side="left", padx=(3, 0))
        tk.Label(ka_frame, text=u"seconds").pack(side="left")
        
        tk.Checkbutton(opt_conn, text=u"Show disconnect message", variable=show_drop_var).pack(anchor="w", pady=(0, 2))

        def on_encryption_toggle():
            if encryption_var.get():
                port_var.set("42440")
            else:
                port_var.set("42439")
        
        encryption_checkbox = tk.Checkbutton(opt_conn, text=u"Enable encryption (AES-256-CBC)", variable=encryption_var, command=on_encryption_toggle)
        encryption_checkbox.pack(anchor="w", pady=(0, 2))

        enc_frame = tk.Frame(opt_conn)
        enc_frame.pack(anchor="w", pady=(0, 2))
        enc_enabled_var = tk.IntVar(value=1 if self.settings["connection"].get("password_encryption_enabled", False) else 0)
        enc_cb = tk.Checkbutton(enc_frame, text=u"Password encryption", variable=enc_enabled_var)
        enc_cb.pack(side="left")
        pwdenc_var = tk.StringVar(value=self.settings["connection"].get("password_encryption", u"MD5"))
        pwdenc_menu = tk.OptionMenu(enc_frame, pwdenc_var, u"Base64", u"MD5", u"SHA-256", u"SHA-512")
        pwdenc_menu.config(width=6, height=1)
        pwdenc_menu.pack(side="left", padx=(0, 0))
        def toggle_pwdenc_state():
            state = "normal" if enc_enabled_var.get() else "disabled"
            try:
                pwdenc_menu.config(state=state)
            except Exception:
                pass
        toggle_pwdenc_state()
        enc_cb.config(command=toggle_pwdenc_state)

        account = tk.Frame(right)
        pages[u"Account"] = account
        acc_wrap = tk.Frame(account)
        acc_wrap.pack(anchor="nw", padx=10, pady=10)

        cred_group = tk.LabelFrame(acc_wrap, text=u"Account")
        cred_group.pack(fill="x", padx=0, pady=(0, 8))

        cred_group.grid_columnconfigure(1, minsize=160)
        tk.Label(cred_group, text=u"Login", anchor="w", width=10).grid(row=0, column=0, sticky="w")
        login_var = tk.StringVar(value=self.settings["account"].get("login", u""))
        login_entry = tk.Entry(cred_group, textvariable=login_var, width=22)
        login_entry.grid(row=0, column=1, sticky="w")

        tk.Label(cred_group, text=u"Password", anchor="w", width=10).grid(row=1, column=0, sticky="w", pady=(6, 0))
        pass_var = tk.StringVar(value=self.settings["account"].get("password", u""))
        pass_entry = tk.Entry(cred_group, textvariable=pass_var, show="*", width=22)
        pass_entry.grid(row=1, column=1, sticky="w", pady=(6, 0))

        reg_btn = tk.Button(cred_group, text=u"Registration", width=14)
        reg_btn.grid(row=2, column=0, columnspan=2, sticky="w", padx=4, pady=(3, 5))

        opt_group = tk.LabelFrame(acc_wrap, text=u"Options")
        opt_group.pack(fill="x", padx=0, pady=(0, 0))
        disco_var = tk.IntVar(value=1 if self.settings["account"].get("disconnect_if_invalid", False) else 0)
        acc_cb = tk.Checkbutton(opt_group, text=u"Disconnect if login details are invalid", variable=disco_var)
        acc_cb.pack(anchor="w", pady=(4, 4))

        interface = tk.Frame(right)
        pages[u"Interface"] = interface

        interface_wrap = tk.Frame(interface)
        interface_wrap.pack(anchor="nw", padx=10, pady=10)

        display_group = tk.LabelFrame(interface_wrap, text=u"Display")
        display_group.pack(fill="x", padx=0, pady=(0, 8))

        smiley_var = tk.IntVar(value=1 if self.settings["interface"].get("show_graphical_smilies", True) else 0)
        tk.Checkbutton(display_group, text=u"Show graphical smilies", variable=smiley_var).pack(anchor="w", pady=(4, 4))

        def on_select(evt=None):
            for p in right.pack_slaves():
                p.pack_forget()
            name = cats.get(cats.curselection())
            pages.get(name, conn).pack(fill="both", expand=True)
        cats.bind("<<ListboxSelect>>", on_select)

        original_conn = dict(self.settings["connection"])
        original_acc = dict(self.settings["account"])
        original_interface = dict(self.settings["interface"]) 

        def apply_settings():
            c = self.settings["connection"]
            c["address"] = addr_var.get().strip()
            c["port"] = port_var.get().strip()
            c["keepalive"] = bool(keepalive_var.get())
            c["keepalive_interval"] = ka_int_var.get().strip()
            c["auto_reconnect"] = bool(auto_rec_var.get())
            c["connect_when_possible"] = bool(conn_poss_var.get())
            c["show_disconnect_msg"] = bool(show_drop_var.get())
            c["enable_encryption"] = bool(encryption_var.get())
            c["password_encryption_enabled"] = bool(enc_enabled_var.get())
            c["password_encryption"] = pwdenc_var.get()
            a = self.settings["account"]
            a["login"] = login_var.get().strip()
            a["password"] = pass_var.get()
            a["disconnect_if_invalid"] = bool(disco_var.get())
            i = self.settings["interface"]
            i["show_graphical_smilies"] = bool(smiley_var.get())
            self.save_settings()
            self.update_nickname_display()

        def on_ok():
            apply_settings()
            dlg.destroy()

        def on_reset():
            addr_var.set(original_conn.get("address", u""))
            port_var.set(original_conn.get("port", u"42439"))
            keepalive_var.set(1 if original_conn.get("keepalive", True) else 0)
            ka_int_var.set(original_conn.get("keepalive_interval", u"5"))
            auto_rec_var.set(1 if original_conn.get("auto_reconnect", True) else 0)
            conn_poss_var.set(1 if original_conn.get("connect_when_possible", False) else 0)
            show_drop_var.set(1 if original_conn.get("show_disconnect_msg", False) else 0)
            encryption_var.set(1 if original_conn.get("enable_encryption", False) else 0)
            enc_enabled_var.set(1 if original_conn.get("password_encryption_enabled", False) else 0)
            pwdenc_var.set(original_conn.get("password_encryption", u"MD5"))
            toggle_pwdenc_state()
            if encryption_var.get():
                port_var.set("42440")
            else:
                port_var.set("42439")
            login_var.set(original_acc.get("login", u""))
            pass_var.set(original_acc.get("password", u""))
            disco_var.set(1 if original_acc.get("disconnect_if_invalid", False) else 0)
            smiley_var.set(1 if original_interface.get("show_graphical_smilies", True) else 0)

        btn_ok.config(command=on_ok)
        btn_apply.config(command=apply_settings)
        btn_reset.config(command=on_reset)
        dlg.bind("<Return>", lambda e: on_ok())
        dlg.bind("<Escape>", lambda e: dlg.destroy())

        def do_register():
            login = login_var.get().strip()
            pwd = pass_var.get()
            if not login or not pwd:
                tkMessageBox.showwarning(u"Registration", u"Enter login and password")
                return
            
            if " " in login or " " in pwd:
                tkMessageBox.showwarning(u"Registration", u"Username and password cannot contain spaces")
                return
            
            try:
                reg_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_host = self.settings.get("connection", {}).get("address", "dmconnect.hoho.ws")
                server_port = 42439
                reg_socket.connect((server_host, server_port))
                
                def handle_registration():
                    try:
                        reg_socket.settimeout(5.0)
                        
                        initial_msg = reg_socket.recv(1024).decode("utf-8").strip()
                        
                        cmd = u"/register {0} {1}".format(login, pwd)
                        reg_socket.send(cmd.encode("utf-8"))
                        
                        response = reg_socket.recv(1024).decode("utf-8").strip()
                        
                        if "Registration successful" in response:
                            tkMessageBox.showinfo(u"Registration", u"Registration successful! Please log in.")
                        elif "Username already taken" in response:
                            tkMessageBox.showwarning(u"Registration", u"Username already taken. Try another.")
                        elif "Usage:" in response:
                            tkMessageBox.showwarning(u"Registration", u"Invalid command format")
                        else:
                            tkMessageBox.showinfo(u"Registration", u"Server response: " + response)
                            
                    except socket.timeout:
                        tkMessageBox.showerror(u"Registration", u"Registration timeout")
                    except Exception as e:
                        tkMessageBox.showerror(u"Registration", u"Registration error: %s" % str(e))
                    finally:
                        try:
                            reg_socket.close()
                        except:
                            pass
                
                handle_registration()
                
            except Exception as e:
                tkMessageBox.showerror(u"Registration", u"Connection error: %s" % str(e))
        reg_btn.config(command=do_register)

        w, h = 560, 385
        dlg.update_idletasks()
        try:
            px, py = self.master.winfo_rootx(), self.master.winfo_rooty()
            pw, ph = self.master.winfo_width(), self.master.winfo_height()
            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
            dlg.geometry("%dx%d+%d+%d" % (w, h, max(0, x), max(0, y)))
        except Exception:
            dlg.geometry("%dx%d" % (w, h))

        dlg.wait_window()

    def show_about_dialog(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("About ExTO")
        dialog.iconbitmap("icon.ico")
        dialog.geometry("250x185")
        dialog.resizable(False, False)
        dialog.transient(self.master)
        dialog.grab_set()

        header_frame = tk.Frame(dialog)
        header_frame.pack(fill="x", padx=10, pady=(8, 0))

        title_label = tk.Label(header_frame, text="ExTO 0.0.1a",
                            font=("MS Sans Serif", 10, "bold"))
        title_label.pack(side="left")

        main_frame = tk.Frame(dialog)
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)

        copyright_label = tk.Label(main_frame,
                                text="© guester (AKA Archie-Boop)",
                                font=("MS Sans Serif", 9))
        copyright_label.pack(anchor="w", pady=(0, 5))

        def make_link(parent, text, url):
            lbl = tk.Label(parent, text=text, fg="blue", cursor="hand2",
                        font=("MS Sans Serif", 9, "underline"))
            lbl.pack(anchor="w")
            lbl.bind("<Button-1>", lambda e: webbrowser.open(url))
            return lbl

        make_link(main_frame, "DMconnect", "http://dmconnect.w10.site")
        make_link(main_frame, "Source Code", "https://github.com/Archie-Boop/ExTO")
        make_link(main_frame, "Protocol Documentation", "http://dmconnectspec.w10.site/")

        lic_label = tk.Label(main_frame, text="\nThanks to BitByByte for creating DMconnect!",
                            font=("MS Sans Serif", 9))
        lic_label.pack(anchor="w")


        bottom_frame = tk.Frame(dialog)
        bottom_frame.pack(fill="x", side="bottom", pady=5, padx=5)

        close_button = tk.Button(bottom_frame, text="OK", width=10, command=dialog.destroy, pady=0)
        close_button.pack(side="right")

        dialog.bind("<Return>", lambda e: dialog.destroy())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

        close_button.focus()

        dialog.update_idletasks()
        w, h = dialog.winfo_width(), dialog.winfo_height()
        x = self.master.winfo_rootx() + (self.master.winfo_width() - w) // 2
        y = self.master.winfo_rooty() + (self.master.winfo_height() - h) // 2
        dialog.geometry("{}x{}+{}+{}".format(w, h, x, y))

        dialog.wait_window()

    
    def send_data(self, data):
        try:
            if self.is_encrypted and self.encryption_key:
                if isinstance(data, bytes):
                    data = data.decode('utf-8')
                if not data.endswith('\n'):
                    data += '\n'
                payload = self.encrypt_message(data, self.encryption_key)
                if payload is None:
                    return False
                if self.mac_key:
                    mac = hmac.new(self.mac_key, payload, hashlib.sha256).digest()
                    payload += mac
                frame = struct.pack('>I', len(payload)) + payload
                self.client_socket.send(frame)
                return True
            else:
                if isinstance(data, unicode):
                    data = data.encode('utf-8')
                if not data.endswith('\n'):
                    data += '\n'
                self.client_socket.send(data)
                return True
        except Exception as e:
            print "Error sending data: %s" % str(e)
            return False
    
    def generate_aes_key(self):
        return os.urandom(self.AES_KEY_SIZE)

    def encrypt_message(self, message, encryption_key):
        if not ENCRYPTION_AVAILABLE:
            return None
        try:
            if isinstance(message, unicode):
                b = message.encode('utf-8')
            elif isinstance(message, bytes):
                b = message
            else:
                b = str(message)
                try:
                    b = b.encode('utf-8')
                except Exception:
                    pass
            iv = os.urandom(16)
            pad = 16 - (len(b) % 16)
            b += chr(pad) * pad
            a = pyaes.AESModeOfOperationCBC(encryption_key, iv=iv)
            out = ''
            for i in range(0, len(b), 16):
                out += a.encrypt(b[i:i+16])
            return iv + out
        except Exception as e:
            print "Encryption error: %s" % str(e)
            return None

    def decrypt_message(self, data, k):
        if not ENCRYPTION_AVAILABLE:
            return None
        try:
            if len(data) < 16:
                return None
            iv, enc = data[:16], data[16:]
            if len(enc) % 16 != 0:
                return None
            a = pyaes.AESModeOfOperationCBC(k, iv=iv)
            out = ''
            for i in range(0, len(enc), 16):
                out += a.decrypt(enc[i:i+16])
            pad = ord(out[-1])
            if pad == 0 or pad > 16:
                return None
            return out[:-pad].decode('utf-8')
        except Exception as e:
            print "Decryption error: %s" % str(e)
            return None

    def create_encrypted_packet(self, message, encryption_key):
        payload = self.encrypt_message(message, encryption_key)
        if payload is None:
            return None
        if self.mac_key:
            mac = hmac.new(self.mac_key, payload, hashlib.sha256).digest()
            payload += mac
        return struct.pack('>I', len(payload)) + payload

    def parse_encrypted_packet(self, packet_data, encryption_key):
        try:
            if len(packet_data) < 4:
                return None
                
            length = struct.unpack('>I', packet_data[:4])[0]
            
            if len(packet_data) < 4 + length:
                return None
                
            encrypted_data = packet_data[4:4+length]
            
            return self.decrypt_message(encrypted_data, encryption_key)
        except Exception as e:
            print "Packet parsing error: %s" % str(e)
            return None

    def get_encryption_key_from_server(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            
            key = sock.recv(self.AES_KEY_SIZE)
            
            sock.close()
            
            if len(key) == self.AES_KEY_SIZE:
                return key
            else:
                print "Failed to receive encryption key: got %d bytes, expected %d" % (len(key), self.AES_KEY_SIZE)
                return None
                
        except Exception as e:
            print "Error getting encryption key: %s" % str(e)
            return None


if __name__ == "__main__":
    root = tk.Tk()
    app = DMconnectClient(root)
    root.mainloop()
