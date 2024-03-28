import socket
import json
import sys
import select
import logging

class ChatClient:
    def __init__(self, server_address, server_port, user_name, targets):
        self.server_address = server_address
        self.server_port = server_port
        self.user_name = user_name
        self.targets = targets
        self.sock = None

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_address, self.server_port))
        except Exception as e:
            print(f"Error connecting to the server: {e}")
            sys.exit(1)

    def send_message(self, action, target=None, message=None, targets=None):
        data = {
            "action": action,
            "user_name": self.user_name,
        }
        if target:
            data["target"] = target
        if message:
            data["message"] = message
        if targets:
            data["targets"] = targets

        try:
            self.sock.sendall(json.dumps(data).encode())
        except Exception as e:
            print(f"Error sending message: {e}")

    def receive_messages(self):
        inputs = [self.sock, sys.stdin]

        while True:
            readable, _, _ = select.select(inputs, [], [])

            for sock in readable:
                if sock == self.sock:
                    data = sock.recv(4096).decode()
                    if not data:
                        print("Disconnected from the server.")
                        sys.exit(0)

                    self.handle_server_message(data)
                else:
                    user_input = sys.stdin.readline().strip()
                    self.handle_user_input(user_input)

    def handle_server_message(self, data):
        try:
            message = json.loads(data)
        except json.JSONDecodeError:
            print("Error decoding server message.")
            return

        if message.get("status") == "disconnect":
            print("Server is shutting down. Disconnecting.")
            sys.exit(0)
        elif message.get("status") == "chat":
            for msg in message.get("history", []):
                print("Received message:", msg)
        else:
            print("Unknown message from server:", message)

    def handle_user_input(self, user_input):
        if user_input.startswith("/"):
            command, *args = user_input[1:].split(" ")
            if command == "join":
                self.send_message("connect", targets=args)
            elif command == "send":
                if len(args) < 2:
                    print("Usage: /send <target> <message>")
                else:
                    target = args[0]
                    message = " ".join(args[1:])
                    self.send_message("message", target=target, message=message)
            elif command == "quit":
                self.send_message("disconnect")
                sys.exit(0)
            else:
                print("Unknown command:", command)
        else:
            print("Unknown command. Usage: </command> <target> <message>")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 3:
        print("Usage: python client.py <server_address> <server_port>")
        sys.exit(1)

    server_address = sys.argv[1]
    server_port = int(sys.argv[2])

    user_name = input("Enter your username: ")
    targets = input("Enter the rooms you want to join (comma-separated): ").split(",")

    client = ChatClient(server_address, server_port, user_name, targets)
    client.connect_to_server()
    client.send_message("connect", targets=targets)

    print("Connected to the server. (Enter command starting with '/'):\n")

    client.receive_messages()
