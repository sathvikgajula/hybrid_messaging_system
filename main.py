import argparse
import os


def run_local():
    from user_operations import register_user, send_message, view_message
    while True:
        print("\n--- Hybrid Messaging System (local) ---")
        print("1. Register User\n2. Send Message\n3. View Message\n4. Exit")
        option = input("Choice: ").strip()
        if option == '1':
            register_user()
        elif option == '2':
            send_message()
        elif option == '3':
            view_message()
        elif option == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice.")


def run_cli_client(keyfile):
    from client_app import run
    run(keyfile)


def run_server():
    from server import run_relay
    run_relay()


def run_gui():
    from client_gui import run_gui as launch
    launch()


def main():
    parser = argparse.ArgumentParser(description="Sealed — E2EE messenger")
    parser.add_argument(
        "mode",
        nargs="?",
        default="gui",
        choices=["gui", "local", "client", "server"],
        help="gui (default), local CLI, networked CLI, or relay server",
    )
    parser.add_argument(
        "keyfile",
        nargs="?",
        default="my_private_keys.json",
        help="CLI client keyfile",
    )
    args = parser.parse_args()

    if args.mode == "local":
        run_local()
    elif args.mode == "client":
        run_cli_client(args.keyfile)
    elif args.mode == "server":
        run_server()
    else:
        run_gui()


if __name__ == "__main__":
    main()
