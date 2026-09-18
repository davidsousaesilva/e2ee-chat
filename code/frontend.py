from getpass import getpass


def print_header(title):
    print("\n" + "=" * 42)
    print(title.center(42))
    print("=" * 42)


def print_ok(message):
    print(f"[OK] {message}")


def print_error(message):
    print(f"[ERROR] {message}")


def print_info(message):
    print(f"[INFO] {message}")


def print_warning(message):
    print(f"[WARNING] {message}")


def show_auth_menu():
    print_header("SECURE CHAT - AUTHENTICATION")
    print("1. Register new user")
    print("2. Login")
    print("3. Exit")
    print("-" * 42)
    return input("Choose an option: ").strip()


def show_main_menu(current_user=None):
    title = "SECURE CHAT"
    if current_user:
        title = f"SECURE CHAT - {current_user}"

    print_header(title)
    print("1. List contacts")
    print("2. Send friend request")
    print("3. View pending requests")
    print("4. Accept friend request")
    print("5. Start secure chat / Send message")
    print("6. Logout")
    print("-" * 42)
    return input("Choose an option: ").strip()


def prompt_credentials():
    username = input("Username: ").strip()
    password = getpass("Password: ")
    return username, password


def prompt_message():
    to_user = input("Send to: ").strip()
    content = input("Message: ")
    return to_user, content


def prompt_target(label="Username"):
    return input(f"{label}: ").strip()