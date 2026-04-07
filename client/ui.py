"""Tkinter UI pages."""

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from datetime import datetime, timedelta, timezone
import time
import base64
import json

from PIL import ImageTk
import pyotp
import qrcode

from api_client import IMClientAPI
from config import CHAT_PAGE_SIZE
from crypto_manager import CryptoManager


class SecureIMApp(tk.Tk):
    def __init__(self, profile_name="default"):
        super().__init__()
        self.profile_name = str(profile_name or "default")
        self.title(f"IM App ({self.profile_name})")
        self.geometry("1280x840")
        self.resizable(True, True)

        style = ttk.Style(self)
        style.configure("TLabel", font=("Arial", 12))

        self.api = IMClientAPI(profile_name=self.profile_name)
        self.crypto = CryptoManager(profile_name=self.profile_name)

        self.temp_username = None
        self.temp_password = None

        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

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
            prekeys = self.crypto.generate_prekeys_upload_batch(self.temp_username, self.api.device_id, count=20)
            if prekeys:
                self.api.upload_prekeys(prekeys)
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

        try:
            success, result = self.api.register(username, password)
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error during registration: {e}")
            return False
        if success and isinstance(result, dict) and "otp_secret" in result:
            try:
                self.show_page("RegisterOTPPage")
                otp_page = self.frames["RegisterOTPPage"]
                otp_page.show_qr(
                    username,
                    result.get("otp_secret", ""),
                    result.get("contact_code") or "",
                )
                return True
            except Exception as e:
                messagebox.showerror("Error", f"Failed to prepare OTP setup: {e}")
                return False

        messagebox.showerror("Error", result)
        return False


class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        center = ttk.Frame(self)
        center.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(center, text="Login").pack(pady=20)

        form_frame = ttk.Frame(center)
        form_frame.pack(pady=10)

        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = ttk.Entry(form_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry.bind("<Return>", lambda _event: self.on_login())

        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        self.password_entry.bind("<Return>", lambda _event: self.on_login())

        btn_frame = ttk.Frame(center)
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

        center = ttk.Frame(self)
        center.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(center, text="Register").pack(pady=20)

        form_frame = ttk.Frame(center)
        form_frame.pack(pady=10)

        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = ttk.Entry(form_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry.bind("<Return>", lambda _event: self.on_register())

        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        self.password_entry.bind("<Return>", lambda _event: self.on_register())

        ttk.Label(form_frame, text="Confirm:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.confirm_entry = ttk.Entry(form_frame, width=25, show="*")
        self.confirm_entry.grid(row=2, column=1, padx=5, pady=5)
        self.confirm_entry.bind("<Return>", lambda _event: self.on_register())

        btn_frame = ttk.Frame(center)
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

        center = ttk.Frame(self)
        center.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(center, text="Enter OTP Code").pack(pady=20)

        form_frame = ttk.Frame(center)
        form_frame.pack(pady=10)

        ttk.Label(form_frame, text="OTP:").grid(row=0, column=0, padx=5, pady=5)
        self.otp_entry = ttk.Entry(form_frame, width=20)
        self.otp_entry.grid(row=0, column=1, padx=5, pady=5)
        self.otp_entry.bind("<Return>", lambda _event: self.on_confirm())

        btn_frame = ttk.Frame(center)
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

        center = ttk.Frame(self)
        center.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(center, text="OTP Setup").pack(pady=10)

        secret_frame = ttk.Frame(center)
        secret_frame.pack(pady=10, fill="x", padx=20)
        ttk.Label(secret_frame, text="Secret Key:").pack(anchor="w")
        self.secret_entry = ttk.Entry(secret_frame, width=40)
        self.secret_entry.pack(fill="x", pady=5)
        self.contact_code_label = ttk.Label(secret_frame, text="")
        self.contact_code_label.pack(anchor="w", pady=(6, 0))

        qr_container = ttk.LabelFrame(center, text="Scan QR Code with Authenticator App", padding=10)
        qr_container.pack(pady=10, fill="both", expand=True, padx=20)

        self.qr_label = ttk.Label(qr_container)
        self.qr_label.pack(expand=True)

        btn_frame = ttk.Frame(center)
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
        # Runtime chat cache is profile-scoped and persisted through api_client helpers.
        self.current_user = None
        self._incoming_request_ids = []
        self._outgoing_request_ids = []
        self._seen_message_ids = set()
        self._chat_records_by_friend = {}
        self._unread_counts = {}
        self._last_activity_ts = {}
        self._visible_message_counts = {}
        self._chat_page_size = max(1, int(CHAT_PAGE_SIZE))
        self._friend_list_usernames = []
        self._active_chat_friend = None
        self._handshake_retry_peers = set()
        self._suspend_friend_select_event = False
        self._polling_active = False
        self._social_refresh_interval_ms = 3000
        self._ttl_units = [
            ("Second", 1),
            ("Minute", 60),
            ("Hour", 3600),
            ("Day", 86400),
        ]

        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)

        top_bar = ttk.Frame(root)
        top_bar.pack(fill="x", pady=(0, 8))

        title_col = ttk.Frame(top_bar)
        title_col.pack(side="left", fill="x", expand=True)
        self.user_label = ttk.Label(title_col, text="")
        self.user_label.pack(anchor="w")
        self.contact_code_label = ttk.Label(title_col, text="")
        self.contact_code_label.pack(anchor="w")
        ttk.Button(top_bar, text="Logout", command=self.logout).pack(side="right")

        body = ttk.Panedwindow(root, orient="horizontal")
        body.pack(fill="both", expand=True)

        left_panel = ttk.Frame(body, padding=(0, 0, 10, 0))
        right_panel = ttk.Frame(body)
        body.add(left_panel, weight=1)
        body.add(right_panel, weight=3)

        ttk.Label(left_panel, text="Friend List").pack(anchor="w", pady=(0, 6))
        self.friend_listbox = tk.Listbox(left_panel, height=12, exportselection=False)
        self.friend_listbox.pack(fill="x", pady=(0, 8))
        self.friend_listbox.bind("<<ListboxSelect>>", self.on_friend_selected)

        friend_action_row = ttk.Frame(left_panel)
        friend_action_row.pack(fill="x", pady=(0, 12))
        ttk.Button(friend_action_row, text="Add Friend", command=self.add_friend).pack(side="left", padx=(0, 6))
        ttk.Button(friend_action_row, text="Remove Friend", command=self.remove_friend).pack(side="left", padx=(0, 6))
        ttk.Button(friend_action_row, text="Keys / Fingerprint", command=self.show_contact_fingerprints).pack(
            side="left", padx=(0, 6)
        )

        ttk.Label(left_panel, text="Pending Requests").pack(anchor="w", pady=(0, 4))
        self.outgoing_listbox = tk.Listbox(left_panel, height=6)
        self.outgoing_listbox.pack(fill="x", pady=(0, 4))
        ttk.Button(left_panel, text="Cancel", command=self.cancel_outgoing_request).pack(
            anchor="w", pady=(0, 10)
        )

        ttk.Label(left_panel, text="Incoming Requests").pack(anchor="w", pady=(0, 6))
        self.request_listbox = tk.Listbox(left_panel, height=6)
        self.request_listbox.pack(fill="x", pady=(0, 8))

        request_action_row = ttk.Frame(left_panel)
        request_action_row.pack(fill="x")
        ttk.Button(request_action_row, text="Accept", command=self.accept_request).pack(side="left", padx=(0, 6))
        ttk.Button(request_action_row, text="Decline", command=self.decline_request).pack(side="left", padx=(0, 6))

        ttk.Label(left_panel, text="Blocked Users").pack(anchor="w", pady=(12, 4))
        self.blocked_listbox = tk.Listbox(left_panel, height=5)
        self.blocked_listbox.pack(fill="x", pady=(0, 8))
        blocked_action_row = ttk.Frame(left_panel)
        blocked_action_row.pack(anchor="w", pady=(0, 10))
        ttk.Button(blocked_action_row, text="Block", command=self.block_friend).pack(side="left", padx=(0, 6))
        ttk.Button(blocked_action_row, text="Unblock", command=self.unblock_user).pack(side="left")

        chat_header_row = ttk.Frame(right_panel)
        chat_header_row.pack(fill="x", pady=(0, 6))
        self.chat_title_label = ttk.Label(chat_header_row, text="Select A Friend To Chat")
        self.chat_title_label.pack(side="left")
        self.load_older_info_label = ttk.Label(chat_header_row, text="")
        self.load_older_info_label.pack(side="right")
        self.load_older_button = ttk.Button(
            chat_header_row,
            text="Load Older Messages",
            command=self.load_older_messages,
        )
        self.load_older_button.pack(side="right", padx=(0, 10))

        self.chat_content = ttk.Frame(right_panel)
        self.chat_text = tk.Text(self.chat_content, state="disabled", wrap="word")
        self.chat_text.pack(fill="both", expand=True)

        chat_input_row = ttk.Frame(self.chat_content)
        chat_input_row.pack(fill="x", pady=(8, 0))
        self.chat_input = ttk.Entry(chat_input_row)
        self.chat_input.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttl_label = ttk.Label(chat_input_row, text="Destruct after")
        ttl_label.pack(side="left", padx=(0, 8))
        self.ttl_value_var = tk.StringVar(value="0")
        self.ttl_value_entry = ttk.Entry(chat_input_row, textvariable=self.ttl_value_var, width=8)
        self.ttl_value_entry.pack(side="left", padx=(0, 8))
        self.ttl_unit_var = tk.StringVar(value=self._ttl_units[0][0])
        self.ttl_unit_selector = ttk.Combobox(
            chat_input_row,
            textvariable=self.ttl_unit_var,
            values=[label for label, _ in self._ttl_units],
            state="readonly",
            width=10,
        )
        self.ttl_unit_selector.pack(side="left", padx=(0, 8))
        self.ttl_unit_selector.current(0)
        ttk.Button(chat_input_row, text="Send", command=self.send_message).pack(side="right")

        self.chat_content.pack_forget()

    def set_user(self, username):
        self.current_user = username
        self._active_chat_friend = None
        self._chat_records_by_friend, self._unread_counts, self._last_activity_ts = self._load_chat_history_for_user(
            username
        )
        self.user_label.config(text=f"Username: {username}")
        self.chat_title_label.config(text="Select A Friend To Chat")
        self.chat_content.pack_forget()
        self._prune_expired_chat_records()
        self._render_chat_records()
        self.refresh_social()
        if not self._polling_active:
            self._polling_active = True
            self.after(800, self._poll_messages_loop)
            self.after(1200, self._social_refresh_loop)

    def refresh_social(self):
        api = self.controller.api
        selected_outgoing_id = None
        outgoing_sel = self.outgoing_listbox.curselection()
        if outgoing_sel:
            idx = int(outgoing_sel[0])
            if 0 <= idx < len(self._outgoing_request_ids):
                selected_outgoing_id = self._outgoing_request_ids[idx]

        selected_incoming_id = None
        incoming_sel = self.request_listbox.curselection()
        if incoming_sel:
            idx = int(incoming_sel[0])
            if 0 <= idx < len(self._incoming_request_ids):
                selected_incoming_id = self._incoming_request_ids[idx]

        selected_blocked_user = None
        blocked_sel = self.blocked_listbox.curselection()
        if blocked_sel:
            selected_blocked_user = str(self.blocked_listbox.get(int(blocked_sel[0]))).strip()

        ok, me = api.get_me()
        if ok:
            code = me.get("contact_code") or ""
            self.contact_code_label.config(
                text=f"Contact Code: {code}" if code else "Contact Code: —",
            )

        self._suspend_friend_select_event = True
        try:
            self.friend_listbox.delete(0, tk.END)
            ok_f, friends = api.list_friends()
            friends_usernames = []
            if ok_f:
                for f in friends:
                    friend_name = f.get("username", "")
                    friends_usernames.append(friend_name)

            sorted_usernames = sorted(
                friends_usernames,
                key=lambda name: (-self._conversation_last_activity_ts(name), name),
            )
            self._friend_list_usernames = sorted_usernames
            for friend_name in sorted_usernames:
                trust_state = self._refresh_contact_key_trust(friend_name, prompt=False)
                unread = int(self._unread_counts.get(friend_name, 0) or 0)
                last_ts = self._conversation_last_activity_ts(friend_name)
                if last_ts > 0:
                    last_text = datetime.fromtimestamp(last_ts).strftime("%m-%d %H:%M")
                    label = f"{friend_name} [{last_text}]"
                else:
                    label = friend_name
                if unread > 0:
                    label = f"{label} ({unread})"
                if trust_state.get("changed"):
                    label = f"{label} [Key changed]"
                self.friend_listbox.insert(tk.END, label)

            if self._active_chat_friend and self._active_chat_friend in sorted_usernames:
                idx = sorted_usernames.index(self._active_chat_friend)
                self.friend_listbox.selection_clear(0, tk.END)
                self.friend_listbox.selection_set(idx)
                self.friend_listbox.activate(idx)
                self.friend_listbox.see(idx)
            elif self._active_chat_friend and self._active_chat_friend not in friends_usernames:
                self._set_active_chat_friend(None)
        finally:
            self._suspend_friend_select_event = False

        self.outgoing_listbox.delete(0, tk.END)
        self._outgoing_request_ids.clear()
        ok_o, outgoing = api.list_outgoing_friend_requests()
        if ok_o:
            for r in outgoing:
                self._outgoing_request_ids.append(r.get("id"))
                self.outgoing_listbox.insert(tk.END, r.get("counterparty_username", ""))
        if selected_outgoing_id is not None and selected_outgoing_id in self._outgoing_request_ids:
            idx = self._outgoing_request_ids.index(selected_outgoing_id)
            self.outgoing_listbox.selection_set(idx)
            self.outgoing_listbox.activate(idx)
            self.outgoing_listbox.see(idx)

        self.request_listbox.delete(0, tk.END)
        self._incoming_request_ids.clear()
        ok_i, incoming = api.list_incoming_friend_requests()
        if ok_i:
            for r in incoming:
                self._incoming_request_ids.append(r.get("id"))
                self.request_listbox.insert(tk.END, r.get("counterparty_username", ""))
        if selected_incoming_id is not None and selected_incoming_id in self._incoming_request_ids:
            idx = self._incoming_request_ids.index(selected_incoming_id)
            self.request_listbox.selection_set(idx)
            self.request_listbox.activate(idx)
            self.request_listbox.see(idx)

        self.blocked_listbox.delete(0, tk.END)
        ok_b, blocked_users = api.list_blocked_users()
        if ok_b:
            for blocked_user in blocked_users:
                self.blocked_listbox.insert(tk.END, blocked_user)
        if selected_blocked_user:
            try:
                items = self.blocked_listbox.get(0, tk.END)
                if selected_blocked_user in items:
                    idx = items.index(selected_blocked_user)
                    self.blocked_listbox.selection_set(idx)
                    self.blocked_listbox.activate(idx)
                    self.blocked_listbox.see(idx)
            except Exception:
                pass

    def logout(self):
        self._polling_active = False
        self._active_chat_friend = None
        # Avoid persisting an empty history snapshot during logout.
        self.current_user = None
        self._chat_records_by_friend = {}
        self._unread_counts = {}
        self._last_activity_ts = {}
        self._visible_message_counts = {}
        self._friend_list_usernames = []
        self.chat_title_label.config(text="Select A Friend To Chat")
        self.chat_content.pack_forget()
        self._render_chat_records()
        self.controller.api.token = None
        self.controller.show_page("LoginPage")

    def _selected_ttl_seconds(self):
        raw_value = self.ttl_value_var.get().strip()
        if not raw_value:
            return 0
        try:
            amount = int(raw_value)
        except ValueError:
            return None
        if amount < 0:
            return None
        if amount == 0:
            return 0
        selected_label = self.ttl_unit_var.get()
        for label, seconds in self._ttl_units:
            if label == selected_label:
                return amount * seconds
        return None

    def _fingerprints_from_keys(self, keys):
        fingerprints = []
        seen = set()
        if not isinstance(keys, list):
            return fingerprints
        for entry in keys:
            fingerprint = ""
            if isinstance(entry, dict):
                fingerprint = str(entry.get("fingerprint", "")).strip()
            else:
                fingerprint = str(entry).strip()
            if not fingerprint or fingerprint in seen:
                continue
            seen.add(fingerprint)
            fingerprints.append(fingerprint)
        return sorted(fingerprints)

    def _refresh_contact_key_trust(self, peer, prompt=False):
        api = self.controller.api
        result = {"changed": False, "fingerprints": [], "verified": False}
        if not peer:
            return result

        keys = api.get_public_key(peer)
        if not keys:
            return result

        current_fps = self._fingerprints_from_keys(keys)
        result["fingerprints"] = current_fps
        verified = api.get_verified_fingerprints(peer)
        result["verified"] = bool(current_fps) and (set(verified) == set(current_fps))
        changed = api.detect_key_change(peer, keys)
        if changed:
            api.mark_key_change_blocked(peer)

        if api.is_key_change_blocked(peer):
            if set(verified) == set(current_fps) and current_fps:
                api.clear_key_change_block(peer)
                result["verified"] = True
            else:
                result["changed"] = True
                return result

        result["changed"] = False

        return result

    def _ensure_peer_trusted(self, peer, prompt=True, confirm_send_on_key_change=False):
        trust_state = self._refresh_contact_key_trust(peer, prompt=prompt)
        if not trust_state.get("fingerprints"):
            if prompt:
                messagebox.showinfo("No keys", f"{peer} has no published identity keys yet.")
            return False
        if trust_state.get("changed") and prompt and confirm_send_on_key_change:
            return messagebox.askyesno(
                "Key Changed",
                (
                    f"{peer}'s identity key has changed and is not re-verified yet.\n"
                    "Do you still want to send this message?"
                ),
                parent=self,
            )
        if (not trust_state.get("changed")) and (not trust_state.get("verified")) and prompt and confirm_send_on_key_change:
            return messagebox.askyesno(
                "Contact Not Verified",
                (
                    f"{peer}'s identity key has not been verified yet.\n"
                    "Do you still want to send this message?"
                ),
                parent=self,
            )
        return True

    def _prune_expired_chat_records(self):
        now_ts = time.time()
        for friend, records in list(self._chat_records_by_friend.items()):
            kept_records = []
            for record in records:
                expires_at_ts = record.get("expires_at_ts") if isinstance(record, dict) else None
                if expires_at_ts and expires_at_ts <= now_ts:
                    continue
                kept_records.append(record)
            if kept_records:
                self._chat_records_by_friend[friend] = kept_records
                visible = int(self._visible_message_counts.get(friend, self._chat_page_size) or self._chat_page_size)
                self._visible_message_counts[friend] = min(max(visible, self._chat_page_size), len(kept_records))
            else:
                self._chat_records_by_friend.pop(friend, None)
                self._visible_message_counts.pop(friend, None)
        self._save_chat_history()

    def _load_chat_history_for_user(self, username):
        data = self.controller.api.load_chat_history(username)
        friends = data.get("friends", {}) if isinstance(data, dict) else {}
        unread_raw = data.get("unread_counts", {}) if isinstance(data, dict) else {}
        last_activity_raw = data.get("last_activity_ts", {}) if isinstance(data, dict) else {}
        loaded = {}
        unread_counts = {}
        last_activity_ts = {}
        if not isinstance(friends, dict):
            friends = {}
        for friend, records in friends.items():
            if not isinstance(friend, str) or not isinstance(records, list):
                continue
            cleaned_records = []
            for record in records:
                if not isinstance(record, dict):
                    continue
                text = str(record.get("text", "")).strip()
                if not text:
                    continue
                expires_at_ts = record.get("expires_at_ts")
                try:
                    expires_at_ts = float(expires_at_ts) if expires_at_ts is not None else None
                except Exception:
                    expires_at_ts = None
                outgoing = bool(record.get("outgoing", False))
                message_id = record.get("message_id")
                try:
                    message_id = int(message_id) if message_id is not None else None
                except Exception:
                    message_id = None
                created_at_ts = record.get("created_at_ts")
                try:
                    created_at_ts = float(created_at_ts) if created_at_ts is not None else None
                except Exception:
                    created_at_ts = None
                delivery_status = str(record.get("delivery_status", "")).strip().lower() if outgoing else ""
                if outgoing and delivery_status not in ("sent", "delivered"):
                    delivery_status = "sent"
                cleaned_records.append(
                    {
                        "text": text,
                        "expires_at_ts": expires_at_ts,
                        "created_at_ts": created_at_ts,
                        "outgoing": outgoing,
                        "message_id": message_id,
                        "delivery_status": delivery_status,
                    }
                )
            if cleaned_records:
                loaded[friend] = cleaned_records
                last_seen = 0.0
                for record in cleaned_records:
                    created = record.get("created_at_ts")
                    if isinstance(created, (int, float)) and float(created) > last_seen:
                        last_seen = float(created)
                if last_seen > 0:
                    last_activity_ts[friend] = last_seen
        if isinstance(unread_raw, dict):
            for friend, value in unread_raw.items():
                if not isinstance(friend, str):
                    continue
                try:
                    number = int(value)
                except Exception:
                    number = 0
                unread_counts[friend] = max(0, number)
        if isinstance(last_activity_raw, dict):
            for friend, value in last_activity_raw.items():
                if not isinstance(friend, str):
                    continue
                try:
                    ts = float(value)
                except Exception:
                    ts = 0.0
                if ts > 0:
                    last_activity_ts[friend] = ts
        return loaded, unread_counts, last_activity_ts

    def _save_chat_history(self):
        if not self.current_user:
            return
        self.controller.api.save_chat_history(
            self.current_user,
            {
                "friends": self._chat_records_by_friend,
                "unread_counts": self._unread_counts,
                "last_activity_ts": self._last_activity_ts,
            },
        )

    def _conversation_last_activity_ts(self, friend):
        saved_ts = self._last_activity_ts.get(friend)
        if isinstance(saved_ts, (int, float)) and float(saved_ts) > 0:
            return float(saved_ts)
        records = self._chat_records_by_friend.get(friend, [])
        last_ts = 0.0
        for record in records:
            if not isinstance(record, dict):
                continue
            created_at_ts = record.get("created_at_ts")
            if isinstance(created_at_ts, (int, float)):
                if float(created_at_ts) > last_ts:
                    last_ts = float(created_at_ts)
        return last_ts

    def _mark_conversation_activity(self, friend, activity_ts=None):
        if not friend:
            return
        ts = activity_ts if isinstance(activity_ts, (int, float)) else time.time()
        ts = float(ts)
        if ts <= 0:
            return
        current = self._last_activity_ts.get(friend)
        current_ts = float(current) if isinstance(current, (int, float)) else 0.0
        if ts > current_ts:
            self._last_activity_ts[friend] = ts

    def _to_expiry_timestamp(self, expires_at):
        if not expires_at:
            return None
        if isinstance(expires_at, (int, float)):
            return float(expires_at)
        if isinstance(expires_at, datetime):
            dt = expires_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return float(dt.timestamp())
        try:
            dt = datetime.fromisoformat(str(expires_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return float(dt.timestamp())
        except Exception:
            return None

    def _append_chat_line(self, friend, text, expires_at=None, outgoing=False, message_id=None, delivery_status=""):
        if not friend:
            return
        normalized_status = str(delivery_status or "").strip().lower() if outgoing else ""
        if outgoing and normalized_status not in ("sent", "delivered"):
            normalized_status = "sent"
        try:
            normalized_message_id = int(message_id) if message_id is not None else None
        except Exception:
            normalized_message_id = None
        created_at_ts = time.time()
        self._chat_records_by_friend.setdefault(friend, []).append(
            {
                "text": text,
                "expires_at_ts": self._to_expiry_timestamp(expires_at),
                "created_at_ts": created_at_ts,
                "outgoing": bool(outgoing),
                "message_id": normalized_message_id,
                "delivery_status": normalized_status,
            }
        )
        self._mark_conversation_activity(friend, created_at_ts)
        self._save_chat_history()
        self.refresh_social()
        self._render_chat_records()

    def _render_record_text(self, record):
        text = str(record.get("text", ""))
        if not bool(record.get("outgoing", False)):
            return text
        status = str(record.get("delivery_status", "")).strip().lower()
        if status == "delivered":
            return f"{text} [Delivered]"
        return f"{text} [Sent]"

    def _refresh_outgoing_delivery_statuses(self):
        pending_message_ids = []
        id_to_records = {}
        for records in self._chat_records_by_friend.values():
            for record in records:
                if not isinstance(record, dict):
                    continue
                if not bool(record.get("outgoing", False)):
                    continue
                if str(record.get("delivery_status", "")).strip().lower() == "delivered":
                    continue
                message_id = record.get("message_id")
                if not isinstance(message_id, int) or message_id <= 0:
                    continue
                pending_message_ids.append(message_id)
                id_to_records.setdefault(message_id, []).append(record)

        if not pending_message_ids:
            return

        ok, statuses = self.controller.api.get_message_statuses(pending_message_ids)
        if not ok:
            return

        changed = False
        for item in statuses:
            try:
                message_id = int(item.get("message_id", 0))
            except Exception:
                continue
            status = str(item.get("status", "")).strip().lower()
            if status not in ("sent", "delivered"):
                continue
            for record in id_to_records.get(message_id, []):
                old_status = str(record.get("delivery_status", "")).strip().lower()
                if old_status != status:
                    record["delivery_status"] = status
                    changed = True

        if changed:
            self._save_chat_history()
            self._render_chat_records()

    def _render_chat_records(self):
        self._prune_expired_chat_records()
        self.chat_text.configure(state="normal")
        self.chat_text.delete("1.0", tk.END)
        if not self._active_chat_friend:
            self.load_older_button.configure(state="disabled")
            self.load_older_info_label.config(text="")
            self.chat_text.configure(state="disabled")
            return
        records = self._chat_records_by_friend.get(self._active_chat_friend, [])
        total = len(records)
        visible = int(self._visible_message_counts.get(self._active_chat_friend, self._chat_page_size) or self._chat_page_size)
        if total > 0:
            visible = min(max(visible, self._chat_page_size), total)
            self._visible_message_counts[self._active_chat_friend] = visible
        else:
            visible = 0
        start_idx = max(0, total - visible)
        hidden = start_idx

        for line in records[start_idx:]:
            if isinstance(line, dict):
                self.chat_text.insert(tk.END, f"{self._render_record_text(line)}\n")
            else:
                self.chat_text.insert(tk.END, f"{line}\n")

        if hidden > 0:
            self.load_older_button.configure(state="normal")
            self.load_older_info_label.config(text=f"Showing {visible}/{total} messages")
        else:
            self.load_older_button.configure(state="disabled")
            if total > 0:
                self.load_older_info_label.config(text=f"Showing all {total} messages")
            else:
                self.load_older_info_label.config(text="")
        self.chat_text.see(tk.END)
        self.chat_text.configure(state="disabled")

    def _set_active_chat_friend(self, friend):
        self._active_chat_friend = friend
        if friend:
            total = len(self._chat_records_by_friend.get(friend, []))
            default_visible = self._chat_page_size if total > self._chat_page_size else total
            self._visible_message_counts[friend] = max(default_visible, 0)
            self.chat_title_label.config(text=f"Chatting with {friend}")
            if not self.chat_content.winfo_ismapped():
                self.chat_content.pack(fill="both", expand=True)
        else:
            self.chat_title_label.config(text="Select A Friend To Chat")
            if self.chat_content.winfo_ismapped():
                self.chat_content.pack_forget()
        self._render_chat_records()

    def load_older_messages(self):
        friend = self._active_chat_friend
        if not friend:
            return
        total = len(self._chat_records_by_friend.get(friend, []))
        if total <= 0:
            return
        current_visible = int(self._visible_message_counts.get(friend, self._chat_page_size) or self._chat_page_size)
        self._visible_message_counts[friend] = min(total, current_visible + self._chat_page_size)
        self._render_chat_records()

    def on_friend_selected(self, _event=None):
        if self._suspend_friend_select_event:
            return
        sel = self.friend_listbox.curselection()
        if not sel:
            self._set_active_chat_friend(None)
            return
        idx = int(sel[0])
        friend = None
        if 0 <= idx < len(self._friend_list_usernames):
            friend = self._friend_list_usernames[idx]
        if not friend:
            return
        if int(self._unread_counts.get(friend, 0) or 0) > 0:
            self._unread_counts[friend] = 0
            self._save_chat_history()
            self.refresh_social()
        self._set_active_chat_friend(friend)

    def _social_refresh_loop(self):
        if not self._polling_active:
            return
        self.refresh_social()
        self.after(self._social_refresh_interval_ms, self._social_refresh_loop)

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
        if idx < 0 or idx >= len(self._friend_list_usernames):
            messagebox.showerror("Error", "Invalid selection.")
            return None
        return self._friend_list_usernames[idx]

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

    def show_contact_fingerprints(self):
        """
        Show a dialog with the identity key fingerprints for the selected friend,
        and allow the user to locally mark the current keys as 'verified'.
        """
        peer = self._selected_friend_username()
        if not peer:
            return

        api = self.controller.api
        keys = api.get_public_key(peer)
        if not keys:
            messagebox.showinfo("No keys", f"{peer} has no published identity keys yet.")
            return

        verified = api.get_verified_fingerprints(peer)
        trust_state = self._refresh_contact_key_trust(peer, prompt=False)

        dialog = tk.Toplevel(self)
        dialog.title(f"Security for {peer}")
        dialog.transient(self)
        dialog.grab_set()

        outer = ttk.Frame(dialog, padding=10)
        outer.pack(fill="both", expand=True)

        if trust_state.get("changed"):
            ttk.Label(
                outer,
                text=(
                    "Warning: this contact's identity key changed.\n"
                    "Messaging is still allowed, but verify the new fingerprint if you want to trust it."
                ),
                foreground="red",
                justify="left",
            ).pack(anchor="w", pady=(0, 8))
        elif verified:
            ttk.Label(
                outer,
                text="This contact has locally verified fingerprints saved on this profile.",
                justify="left",
            ).pack(anchor="w", pady=(0, 8))

        ttk.Label(
            outer,
            text=(
                "Compare these fingerprints with your contact over a trusted channel.\n"
                "When you have verified them, you can mark the current keys as verified."
            ),
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        text = tk.Text(outer, width=80, height=12, wrap="none")
        text.pack(fill="both", expand=True)
        text.configure(state="normal")

        current_fps = []
        for entry in keys:
            device_id = str(entry.get("device_id", ""))
            fingerprint = str(entry.get("fingerprint", ""))
            if not fingerprint:
                continue
            current_fps.append(fingerprint)
            is_verified = "YES" if fingerprint in verified else "NO"
            text.insert(
                tk.END,
                f"Device: {device_id or '-'}\n"
                f"Fingerprint: {fingerprint}\n"
                f"Locally marked verified: {is_verified}\n"
                "----------------------------------------\n",
            )

        text.configure(state="disabled")

        btn_row = ttk.Frame(outer)
        btn_row.pack(fill="x", pady=(8, 0))

        def on_mark_verified():
            if not current_fps:
                return
            if not messagebox.askyesno(
                "Mark verified",
                "Mark all of the currently displayed fingerprints as VERIFIED for this contact?",
                parent=dialog,
            ):
                return
            api.set_verified_fingerprints(peer, current_fps)
            messagebox.showinfo("Saved", "Verification state saved locally for this contact.", parent=dialog)
            dialog.destroy()

        ttk.Button(btn_row, text="Mark current keys as verified", command=on_mark_verified).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(btn_row, text="Close", command=dialog.destroy).pack(side="right")

    def block_friend(self):
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

    def unblock_user(self):
        sel = self.blocked_listbox.curselection()
        if not sel:
            entered = simpledialog.askstring("Unblock user", "Enter username or contact code:", parent=self)
            if not entered or not entered.strip():
                return
            target = entered.strip()
        else:
            target = self.blocked_listbox.get(int(sel[0])).strip()

        ok, res = self.controller.api.unblock_user(target)
        if ok:
            messagebox.showinfo("Unblocked", f"Unblocked {res.get('unblocked_username', target)}.")
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

    def _append_system_message(self, text):
        if self._active_chat_friend:
            self._append_chat_line(self._active_chat_friend, f"[System] {text}")

    def _find_identity_key_for_device(self, username, device_id):
        keys = self.controller.api.get_public_key(username)
        for key_entry in keys:
            if key_entry.get("device_id") == device_id:
                return key_entry.get("public_key_pem", "")
        return ""

    def _decode_aad_obj(self, aad_b64):
        try:
            raw = base64.b64decode(str(aad_b64).encode("utf-8"))
            obj = json.loads(raw.decode("utf-8"))
            if isinstance(obj, dict):
                return obj
        except Exception:
            return {}
        return {}

    def _record_received_message(self, sender, sender_device, sender_counter):
        self.controller.api.is_replay_message(sender, sender_device, sender_counter)

    def _initiate_session_with_peer(self, peer):
        if not self._ensure_peer_trusted(peer):
            return False
        if self.controller.crypto.has_session_with(peer):
            return True
        keys = self.controller.api.get_public_key(peer)
        if not keys:
            self._append_system_message(f"Cannot start session with {peer}: peer has no published identity key/device.")
            return False

        target_device_id = keys[0].get("device_id", "")
        if not target_device_id:
            self._append_system_message(f"Cannot start session with {peer}: cannot determine target device.")
            return False

        try:
            eph_pub, init_sig, eph_priv = self.controller.crypto.create_initiator_handshake(
                initiator_username=self.current_user,
                initiator_device_id=self.controller.api.device_id,
                recipient_username=peer,
                recipient_device_id=target_device_id,
            )
        except Exception as e:
            self._append_system_message(f"Failed to build handshake with {peer}: {e}")
            return False

        ok, result = self.controller.api.init_session_handshake(peer, target_device_id, eph_pub, init_sig)
        if not ok:
            self._append_system_message(f"Failed to send handshake to {peer}: {result}")
            return False

        handshake_id = result.get("handshake_id")
        if handshake_id is None:
            self._append_system_message(f"Failed to send handshake to {peer}: missing handshake id.")
            return False

        self.controller.crypto.remember_initiator_private_key(
            int(handshake_id),
            peer,
            target_device_id,
            eph_priv,
        )
        self._append_system_message(f"Session handshake sent to {peer} ({target_device_id}).")
        return True

    def sync_sessions(self):
        api = self.controller.api
        crypto = self.controller.crypto

        ok_pending, pending_result = api.list_pending_session_handshakes()
        if ok_pending:
            for handshake in pending_result:
                initiator = handshake.get("initiator_username", "")
                initiator_device = handshake.get("initiator_device_id", "")
                initiator_pem = self._find_identity_key_for_device(initiator, initiator_device)
                if not initiator_pem:
                    continue
                if not self._ensure_peer_trusted(initiator, prompt=False):
                    continue
                try:
                    responder_pub, responder_sig, _ = crypto.handle_incoming_handshake(
                        handshake=handshake,
                        my_username=self.current_user,
                        my_device_id=api.device_id,
                        initiator_identity_key_pem=initiator_pem,
                    )
                except Exception as e:
                    self._append_system_message(f"Ignored invalid incoming handshake from {initiator}: {e}")
                    continue

                ok_resp, resp_result = api.respond_session_handshake(
                    handshake.get("id"),
                    responder_pub,
                    responder_sig,
                )
                if ok_resp:
                    self._append_system_message(f"Session established with {initiator}.")
                else:
                    self._append_system_message(f"Failed to respond handshake for {initiator}: {resp_result}")

        ok_resp_list, responded_result = api.list_responded_session_handshakes()
        if ok_resp_list:
            for handshake in responded_result:
                recipient = handshake.get("recipient_username", "")
                recipient_device = handshake.get("recipient_device_id", "")
                recipient_pem = self._find_identity_key_for_device(recipient, recipient_device)
                if not recipient_pem:
                    continue
                if not self._ensure_peer_trusted(recipient, prompt=False):
                    continue
                try:
                    shared_key = crypto.finalize_initiator_handshake(
                        handshake=handshake,
                        my_username=self.current_user,
                        my_device_id=api.device_id,
                        recipient_identity_key_pem=recipient_pem,
                    )
                except Exception as e:
                    self._append_system_message(f"Failed to finalize handshake with {recipient}: {e}")
                    continue
                if shared_key:
                    self._append_system_message(f"Session established with {recipient}.")

    def send_message(self):
        text = self.chat_input.get().strip()
        if not text:
            return

        peer = self._active_chat_friend
        if not peer:
            messagebox.showwarning("Select friend", "Choose someone in the friend list first.")
            return
        if not self._ensure_peer_trusted(peer, confirm_send_on_key_change=True):
            messagebox.showinfo(
                "Key Changed",
                (
                    f"{peer}'s identity key changed.\n"
                    "Open 'Keys / Fingerprint', compare fingerprints via a trusted channel, "
                    "mark current keys as verified, then resend."
                ),
                parent=self,
            )
            return
        counter = int(self.controller.api.next_sender_counter())
        ttl_seconds = self._selected_ttl_seconds() 
        if ttl_seconds is None:
            messagebox.showerror("Invalid TTL", "Use a non-negative integer. Leave empty or use 0 for permanent storage.")
            return
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds) if ttl_seconds > 0 else None
        aad = {
            "sender": self.current_user,
            "recipient": peer,
            "sender_counter": counter,
            "ts": int(time.time()),
            "ttl_seconds": ttl_seconds,
        }
        encrypted = None

        if self.controller.crypto.has_session_with(peer):
            try:
                encrypted = self.controller.crypto.encrypt_message(peer, text, aad)
            except Exception as e:
                messagebox.showerror("Encrypt error", str(e))
                return
        else:
            preferred_device_id = ""
            try:
                keys = self.controller.api.get_public_key(peer)
                if isinstance(keys, list) and keys:
                    preferred_device_id = str(keys[0].get("device_id", "") or "")
            except Exception:
                preferred_device_id = ""
            ok_bundle, bundle = self.controller.api.claim_prekey_bundle(peer, device_id=preferred_device_id)
            if ok_bundle:
                try:
                    encrypted = self.controller.crypto.encrypt_message_with_prekey_bundle(
                        peer_username=peer,
                        peer_device_id=str(bundle.get("device_id", "")),
                        my_username=self.current_user,
                        my_device_id=self.controller.api.device_id,
                        peer_identity_key_pem=str(bundle.get("identity_key_pem", "")),
                        prekey_id=str(bundle.get("prekey_id", "")),
                        prekey_public=str(bundle.get("prekey_public", "")),
                        prekey_signature=str(bundle.get("prekey_signature", "")),
                        message=text,
                        aad_obj=aad,
                    )
                except Exception as e:
                    messagebox.showerror("Encrypt error", f"Failed prekey encryption: {e}")
                    return
            else:
                started = self._initiate_session_with_peer(peer)
                if not started:
                    messagebox.showwarning("No secure session", "Unable to start secure session automatically.")
                    return
                self.sync_sessions()
                if not self.controller.crypto.has_session_with(peer):
                    messagebox.showinfo(
                        "Session pending",
                        "Secure session is being established. Ask your friend to stay online; message can be sent shortly.",
                    )
                    return
                try:
                    encrypted = self.controller.crypto.encrypt_message(peer, text, aad)
                except Exception as e:
                    messagebox.showerror("Encrypt error", str(e))
                    return

        recipient_device_id = encrypted.get("recipient_device_id") if isinstance(encrypted, dict) else None
        if not recipient_device_id:
            recipient_device_id = self.controller.crypto.session_peer_device_id(peer)

        ok, result = self.controller.api.send_message(
            recipient=peer,
            recipient_device_id=recipient_device_id,
            ciphertext=encrypted["ciphertext"],
            nonce=encrypted["nonce"],
            aad=encrypted["aad"],
            sender_counter=counter,
            expires_in_seconds=ttl_seconds,
        )
        if not ok:
            messagebox.showerror("Send failed", str(result))
            return

        sent_message_id = result.get("message_id") if isinstance(result, dict) else None
        self._append_chat_line(
            peer,
            f"{self.current_user}(You): {text}",
            expires_at=expires_at,
            outgoing=True,
            message_id=sent_message_id,
            delivery_status="sent",
        )
        self.chat_input.delete(0, tk.END)

    def _poll_messages_loop(self):
        if not self._polling_active:
            return

        try:
            self.sync_sessions()
            self._prune_expired_chat_records()
            self._render_chat_records()
            ok, result = self.controller.api.get_messages()
            if ok:
                for msg in result:
                    msg_id = int(msg.get("id", -1))
                    if msg_id < 0 or msg_id in self._seen_message_ids:
                        continue
                    sender = msg.get("sender_username", "")
                    sender_device = msg.get("sender_device_id", "")
                    ciphertext = msg.get("ciphertext", "")
                    nonce = msg.get("nonce", "")
                    aad = msg.get("aad", "")
                    aad_obj = self._decode_aad_obj(aad)
                    sender_counter = aad_obj.get("sender_counter")

                    if self.controller.api.is_replay_message(sender, sender_device, sender_counter):
                        self._seen_message_ids.add(msg_id)
                        self.controller.api.ack_message(msg_id)
                        continue

                    try:
                        plaintext, _ = self.controller.crypto.decrypt_message(sender, ciphertext, nonce, aad)
                    except Exception:
                        sender_pem = self._find_identity_key_for_device(sender, sender_device)
                        try:
                            recovered = self.controller.crypto.establish_session_from_prekey_message(
                                sender_username=sender,
                                sender_device_id=sender_device,
                                my_username=self.current_user,
                                my_device_id=self.controller.api.device_id,
                                sender_identity_key_pem=sender_pem,
                                aad_obj=aad_obj,
                            )
                        except Exception:
                            recovered = False
                        if recovered:
                            try:
                                plaintext, _ = self.controller.crypto.decrypt_message(sender, ciphertext, nonce, aad)
                            except Exception:
                                plaintext = "[Unable to decrypt message]"
                        else:
                            reason = "[Unable to decrypt message]"
                            if str(aad_obj.get("session_mode", "")) == "prekey":
                                prekey_id = str(aad_obj.get("prekey_id", "")).strip()
                                if prekey_id:
                                    local = getattr(self.controller.crypto, "local_prekeys", {})
                                    entry = local.get(prekey_id)
                                    if not entry:
                                        reason = "[Missing prekey for this device. Please log in and ask sender to resend]"
                                    else:
                                        dev = str(entry.get("device_id", ""))
                                        if dev and dev != str(self.controller.api.device_id):
                                            reason = "[Device mismatch for prekey. Please use the same profile/device and ask sender to resend]"
                            plaintext = reason
                            if sender not in self._handshake_retry_peers and not self.controller.crypto.has_session_with(sender):
                                self._handshake_retry_peers.add(sender)
                                self._initiate_session_with_peer(sender)

                    self._record_received_message(sender, sender_device, sender_counter)
                    self._append_chat_line(sender, f"{sender}: {plaintext}", expires_at=msg.get("expires_at"))
                    if sender != self._active_chat_friend:
                        self._unread_counts[sender] = int(self._unread_counts.get(sender, 0) or 0) + 1
                        self._save_chat_history()
                        self.refresh_social()
                    self._seen_message_ids.add(msg_id)
                    self.controller.api.ack_message(msg_id)
            self._refresh_outgoing_delivery_statuses()
        except Exception as e:
            self._append_system_message(f"Receive loop recovered from error: {e}")

        self.after(1500, self._poll_messages_loop)

    def clear(self):
        self.chat_input.delete(0, tk.END)
