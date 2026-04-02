import argparse

from ui import SecureIMApp

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="default", help="Local client profile name, e.g. user1 or user2")
    args = parser.parse_args()

    app = SecureIMApp(profile_name=args.profile)
    app.mainloop()