import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from PIL import ImageTk
import pyotp
import qrcode

from api_client import IMClientAPI
from crypto_manager import CryptoManager


class SecureIMApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IM App")
        self.geometry("900x600")

        self.api = IMClientAPI()
        self.crypto = CryptoManager()

        self.temp_username = None
        self.temp_password = None

        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for frame_cls in (LoginPage, RegistrationPage, LoginOTPPage, RegisterOTPPage, HomePage):
            page_name = frame_cls.__name__
            frame = frame_cls(self.container, self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_page("LoginPage")

    def show_page(self, page_name):
        frame = self.frames[page_name]
        if hasattr(frame, "clear"):
            frame.clear()
        frame.tkraise()

    def start_login(self, username, password):
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return False

        success, result = self.api.verify_login_password(username, password)
        if not success:
            messagebox.showerror("Error", result)
            return False

        self.temp_username = username
        self.temp_password = password
        self.show_page("LoginOTPPage")
        return True

    def verify_otp(self, otp):
        if not otp:
            messagebox.showerror("Error", "OTP code required")
            return False
        success, result = self.api.login_with_otp(self.temp_username, self.temp_password, otp)
        if success:
            self.api.set_public_key(self.crypto.get_public_key_pem())
            home = self.frames["HomePage"]
            home.set_user(self.temp_username)
            self.show_page("HomePage")
            return True

        messagebox.showerror("Error", result)
        return False

    def register_user(self, username, password, confirm):
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return False
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return False

        success, result = self.api.register(username, password)
        if success:
            self.show_page("RegisterOTPPage")
            otp_page = self.frames["RegisterOTPPage"]
            otp_page.show_qr(
                username,
                result["otp_secret"],
                result.get("contact_code") or "",
            )
            return True

        messagebox.showerror("Error", result)
        return False


class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="Login", font=("Arial", 20)).pack(pady=20)

        form_frame = ttk.Frame(self)
        form_frame.pack(pady=10)

        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = ttk.Entry(form_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Login", command=self.on_login).pack(side="left", padx=10)
        ttk.Button(
            btn_frame,
            text="Register",
            command=lambda: controller.show_page("RegistrationPage"),
        ).pack(side="left", padx=10)

    def on_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.controller.start_login(username, password)

    def clear(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)


class RegistrationPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="Register", font=("Arial", 20)).pack(pady=20)

        form_frame = ttk.Frame(self)
        form_frame.pack(pady=10)

        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = ttk.Entry(form_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="Confirm:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.confirm_entry = ttk.Entry(form_frame, width=25, show="*")
        self.confirm_entry.grid(row=2, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Register", command=self.on_register).pack(side="left", padx=10)
        ttk.Button(
            btn_frame,
            text="Back to Login",
            command=lambda: controller.show_page("LoginPage"),
        ).pack(side="left", padx=10)

    def on_register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        self.controller.register_user(username, password, confirm)

    def clear(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_entry.delete(0, tk.END)


class LoginOTPPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="Enter OTP Code", font=("Arial", 20)).pack(pady=20)

        form_frame = ttk.Frame(self)
        form_frame.pack(pady=10)

        ttk.Label(form_frame, text="OTP:").grid(row=0, column=0, padx=5, pady=5)
        self.otp_entry = ttk.Entry(form_frame, width=20)
        self.otp_entry.grid(row=0, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Confirm", command=self.on_confirm).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Cancel", command=lambda: controller.show_page("LoginPage")).pack(
            side="left", padx=10
        )

    def on_confirm(self):
        otp = self.otp_entry.get()
        self.controller.verify_otp(otp)

    def clear(self):
        self.otp_entry.delete(0, tk.END)


class RegisterOTPPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="OTP Setup", font=("Arial", 20)).pack(pady=10)

        secret_frame = ttk.Frame(self)
        secret_frame.pack(pady=10, fill="x", padx=20)
        ttk.Label(secret_frame, text="Secret Key:").pack(anchor="w")
        self.secret_entry = ttk.Entry(secret_frame, width=40)
        self.secret_entry.pack(fill="x", pady=5)
        self.contact_code_label = ttk.Label(secret_frame, text="")
        self.contact_code_label.pack(anchor="w", pady=(6, 0))

        qr_container = ttk.LabelFrame(self, text="Scan QR Code with Authenticator App", padding=10)
        qr_container.pack(pady=10, fill="both", expand=True, padx=20)

        self.qr_label = ttk.Label(qr_container)
        self.qr_label.pack(expand=True)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Go to Login", command=lambda: controller.show_page("LoginPage")).pack()

    def show_qr(self, username, secret, contact_code=""):
        self.secret_entry.delete(0, tk.END)
        self.secret_entry.insert(0, secret)
        if contact_code:
            self.contact_code_label.config(text=f"Your contact code: {contact_code}")
        else:
            self.contact_code_label.config(text="")

        totp_uri = pyotp.TOTP(secret).provisioning_uri(username, issuer_name="SecureIM")
        qr = qrcode.make(totp_uri)
        img = qr.resize((200, 200))
        photo = ImageTk.PhotoImage(img)
        self.qr_label.config(image=photo)
        self.qr_label.image = photo

    def clear(self):
        pass


class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.current_user = None
        self._incoming_request_ids = []
        self._outgoing_request_ids = []

        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)

        top_bar = ttk.Frame(root)
        top_bar.pack(fill="x", pady=(0, 8))

        title_col = ttk.Frame(top_bar)
        title_col.pack(side="left", fill="x", expand=True)
        self.user_label = ttk.Label(title_col, text="", font=("Arial", 12))
        self.user_label.pack(anchor="w")
        self.contact_code_label = ttk.Label(title_col, text="", font=("Arial", 10))
        self.contact_code_label.pack(anchor="w")
        ttk.Button(top_bar, text="Refresh", command=self.refresh_social).pack(side="right", padx=(0, 8))
        ttk.Button(top_bar, text="Logout", command=self.logout).pack(side="right")

        body = ttk.Panedwindow(root, orient="horizontal")
        body.pack(fill="both", expand=True)

        left_panel = ttk.Frame(body, padding=(0, 0, 10, 0))
        right_panel = ttk.Frame(body)
        body.add(left_panel, weight=1)
        body.add(right_panel, weight=3)

        ttk.Label(left_panel, text="Friend List", font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 6))
        self.friend_listbox = tk.Listbox(left_panel, height=8)
        self.friend_listbox.pack(fill="x", pady=(0, 8))

        ttk.Label(left_panel, text="Sent requests (pending)", font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self.outgoing_listbox = tk.Listbox(left_panel, height=3)
        self.outgoing_listbox.pack(fill="x", pady=(0, 4))
        ttk.Button(left_panel, text="Cancel selected sent request", command=self.cancel_outgoing_request).pack(
            anchor="w", pady=(0, 10)
        )

        friend_action_row = ttk.Frame(left_panel)
        friend_action_row.pack(fill="x", pady=(0, 12))
        ttk.Button(friend_action_row, text="Add Friend", command=self.add_friend).pack(side="left", padx=(0, 6))
        ttk.Button(friend_action_row, text="Remove Friend", command=self.remove_friend).pack(side="left", padx=(0, 6))
        ttk.Button(friend_action_row, text="Block", command=self.block_friend).pack(side="left")

        ttk.Label(left_panel, text="Incoming requests", font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 6))
        self.request_listbox = tk.Listbox(left_panel, height=6)
        self.request_listbox.pack(fill="x", pady=(0, 8))

        request_action_row = ttk.Frame(left_panel)
        request_action_row.pack(fill="x")
        ttk.Button(request_action_row, text="Accept", command=self.accept_request).pack(side="left", padx=(0, 6))
        ttk.Button(request_action_row, text="Decline", command=self.decline_request).pack(side="left", padx=(0, 6))
        ttk.Button(request_action_row, text="Block", command=self.block_request).pack(side="left")

        ttk.Label(right_panel, text="Chat", font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 6))
        self.chat_text = tk.Text(right_panel, state="disabled", wrap="word")
        self.chat_text.pack(fill="both", expand=True)

        chat_input_row = ttk.Frame(right_panel)
        chat_input_row.pack(fill="x", pady=(8, 0))
        self.chat_input = ttk.Entry(chat_input_row)
        self.chat_input.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(chat_input_row, text="Send", command=self.send_message).pack(side="right")

    def set_user(self, username):
        self.current_user = username
        self.user_label.config(text=f"Logged in as: {username}")
        self.refresh_social()

    def refresh_social(self):
        api = self.controller.api
        ok, me = api.get_me()
        if ok:
            code = me.get("contact_code") or ""
            self.contact_code_label.config(
                text=f"Contact code: {code}" if code else "Contact code: —",
            )

        self.friend_listbox.delete(0, tk.END)
        ok_f, friends = api.list_friends()
        if ok_f:
            for f in friends:
                self.friend_listbox.insert(tk.END, f.get("username", ""))

        self.outgoing_listbox.delete(0, tk.END)
        self._outgoing_request_ids.clear()
        ok_o, outgoing = api.list_outgoing_friend_requests()
        if ok_o:
            for r in outgoing:
                self._outgoing_request_ids.append(r.get("id"))
                self.outgoing_listbox.insert(tk.END, r.get("counterparty_username", ""))

        self.request_listbox.delete(0, tk.END)
        self._incoming_request_ids.clear()
        ok_i, incoming = api.list_incoming_friend_requests()
        if ok_i:
            for r in incoming:
                self._incoming_request_ids.append(r.get("id"))
                self.request_listbox.insert(tk.END, r.get("counterparty_username", ""))

    def logout(self):
        self.controller.api.token = None
        self.controller.show_page("LoginPage")

    def add_friend(self):
        ident = simpledialog.askstring(
            "Add contact",
            "Enter username or contact code:",
            parent=self,
        )
        if not ident or not ident.strip():
            return
        ok, res = self.controller.api.send_friend_request(ident.strip())
        if ok:
            messagebox.showinfo("Sent", f"Friend request sent to {res.get('to_username', '')}.")
            self.refresh_social()
        else:
            messagebox.showerror("Error", str(res))

    def _selected_friend_username(self):
        sel = self.friend_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select friend", "Choose someone in the friend list first.")
            return None
        idx = int(sel[0])
        return self.friend_listbox.get(idx).strip() or None

    def remove_friend(self):
        peer = self._selected_friend_username()
        if not peer:
            return
        ok, res = self.controller.api.remove_friend(peer)
        if ok:
            messagebox.showinfo("Removed", f"No longer friends with {res.get('username', peer)}.")
            self.refresh_social()
        else:
            messagebox.showerror("Error", str(res))

    def block_friend(self):
        peer = None
        sel = self.friend_listbox.curselection()
        if sel:
            peer = self.friend_listbox.get(int(sel[0])).strip() or None
        if not peer:
            entered = simpledialog.askstring(
                "Block user",
                "Enter username or contact code:",
                parent=self,
            )
            if not entered or not entered.strip():
                return
            peer = entered.strip()
        if not messagebox.askyesno("Block user", f"Block {peer}? They will not be able to send requests or messages to you."):
            return
        ok, res = self.controller.api.block_user(peer)
        if ok:
            messagebox.showinfo("Blocked", f"Blocked {res.get('blocked_username', peer)}.")
            self.refresh_social()
        else:
            messagebox.showerror("Error", str(res))

    def _selected_incoming_request_id(self):
        sel = self.request_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select request", "Choose an incoming request first.")
            return None
        idx = int(sel[0])
        if idx < 0 or idx >= len(self._incoming_request_ids):
            messagebox.showerror("Error", "Invalid selection.")
            return None
        return self._incoming_request_ids[idx]

    def accept_request(self):
        rid = self._selected_incoming_request_id()
        if rid is None:
            return
        ok, err = self.controller.api.accept_friend_request(rid)
        if ok:
            self.refresh_social()
        else:
            messagebox.showerror("Error", str(err))

    def decline_request(self):
        rid = self._selected_incoming_request_id()
        if rid is None:
            return
        ok, err = self.controller.api.decline_friend_request(rid)
        if ok:
            self.refresh_social()
        else:
            messagebox.showerror("Error", str(err))

    def _selected_outgoing_request_id(self):
        sel = self.outgoing_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select request", "Choose a sent request to cancel.")
            return None
        idx = int(sel[0])
        if idx < 0 or idx >= len(self._outgoing_request_ids):
            messagebox.showerror("Error", "Invalid selection.")
            return None
        return self._outgoing_request_ids[idx]

    def cancel_outgoing_request(self):
        rid = self._selected_outgoing_request_id()
        if rid is None:
            return
        ok, err = self.controller.api.cancel_friend_request(rid)
        if ok:
            self.refresh_social()
        else:
            messagebox.showerror("Error", str(err))

    def block_request(self):
        rid = self._selected_incoming_request_id()
        if rid is None:
            return
        if not messagebox.askyesno("Block user", "Block this person? The request will be removed."):
            return
        ok, res = self.controller.api.block_friend_request(rid)
        if ok:
            messagebox.showinfo("Blocked", f"Blocked {res.get('blocked_username', '')}.")
            self.refresh_social()
        else:
            messagebox.showerror("Error", str(res))

    def send_message(self):
        text = self.chat_input.get().strip()
        if not text:
            return
        self.chat_text.configure(state="normal")
        self.chat_text.insert(tk.END, f"Me: {text}\n")
        self.chat_text.see(tk.END)
        self.chat_text.configure(state="disabled")
        self.chat_input.delete(0, tk.END)

    def clear(self):
        self.chat_input.delete(0, tk.END)
