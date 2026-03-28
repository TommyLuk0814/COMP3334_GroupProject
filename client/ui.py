import tkinter as tk
from tkinter import messagebox, ttk

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
            otp_page.show_qr(username, result)
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

        qr_container = ttk.LabelFrame(self, text="Scan QR Code with Authenticator App", padding=10)
        qr_container.pack(pady=10, fill="both", expand=True, padx=20)

        self.qr_label = ttk.Label(qr_container)
        self.qr_label.pack(expand=True)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Go to Login", command=lambda: controller.show_page("LoginPage")).pack()

    def show_qr(self, username, secret):
        self.secret_entry.delete(0, tk.END)
        self.secret_entry.insert(0, secret)

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

        ttk.Label(self, text="Welcome to Secure IM", font=("Arial", 20)).pack(pady=50)
        self.user_label = ttk.Label(self, text="", font=("Arial", 12))
        self.user_label.pack(pady=10)
        ttk.Button(self, text="Logout", command=self.logout).pack(pady=20)

    def set_user(self, username):
        self.current_user = username
        self.user_label.config(text=f"Logged in as: {username}")

    def logout(self):
        self.controller.api.token = None
        self.controller.show_page("LoginPage")

    def clear(self):
        pass
