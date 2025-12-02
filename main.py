from user_operations import register_user, send_message, view_message

def main():
    while True:
        print("\n--- Hybrid Messaging System ---")
        print("1. Register User\n2. Send Message\n3. View Message\n4. Exit")
        option = input("Choice: ")
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

if __name__ == "__main__":
    main()