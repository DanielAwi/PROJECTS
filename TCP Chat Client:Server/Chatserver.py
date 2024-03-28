import socket
import select
import json
import sys

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.message_queue = []
        self.inputs = []

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        print(f"Server is listening on {self.host}:{self.port}")

        self.inputs.append(self.server_socket)

        while True:
            readable, _, _ = select.select(self.inputs, [], [])

            for sock in readable:
                if sock == self.server_socket:
                    client_socket, client_address = self.server_socket.accept()
                    self.handle_new_connection(client_socket)
                else:
                    self.handle_client_message(sock)
                    self.send_messages()

    def handle_new_connection(self, client_socket):
        self.inputs.append(client_socket)
        print(f"New connection from {client_socket.getpeername()}")
        self.clients[client_socket] = {"user_name": None, "targets": []}

    def handle_client_message(self, client_socket):
        try:
            data = client_socket.recv(4096).decode()
            if not data:
                self.remove_client(client_socket)
            else:
                self.process_message(client_socket, data)
        except Exception as e:
            print(f"Error reading from client: {e}")
            self.remove_client(client_socket)

    def process_message(self, client_socket, data):
        try:
            message = json.loads(data)
            self.validate_message(message)

            action = message.get("action")
            if action == "connect":
                self.handle_connect_message(client_socket, message)
            elif action == "message":
                self.handle_message_message(client_socket, message)
            elif action == "disconnect":
                self.remove_client(client_socket)
            else:
                self.queue_error(client_socket, "Unknown action")

        except json.JSONDecodeError:
            self.queue_error(client_socket, "Malformed JSON")
        except ValueError as ve:
            self.queue_error(client_socket, str(ve))

    def validate_message(self, message):
        required_fields = ["action", "user_name"]
        for field in required_fields:
            if field not in message:
                raise ValueError(f"Missing required field: {field}")

        user_name = message["user_name"]
        target = message.get("target", "")
        message_text = message.get("message", "")

        self.check_field_length("user_name", user_name, 60)
        self.check_field_length("target", target, 60)
        self.check_field_length("message", message_text, 3800)

    def check_field_length(self, field_name, field_value, max_length):
        utf8_length = len(field_value.encode("utf-8"))
        if utf8_length > max_length:
            raise ValueError(f"{field_name} exceeds the maximum size limit")

    def handle_connect_message(self, client_socket, message):
        user_name = message["user_name"]
        targets = message.get("targets", [])

        self.clients[client_socket] = {"user_name": user_name, "targets": targets}

    def handle_message_message(self, client_socket, message):
        sender_name = message["user_name"]
        target = message["target"]
        message_text = message["message"]

        if target in self.clients[client_socket]["targets"]:
            # Broadcast the message to all clients in the target room
            self.queue_message(sender_name, target, message_text)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            user_name = self.clients[client_socket]["user_name"]
            print(f"Client {user_name} disconnected")
            del self.clients[client_socket]
            self.inputs.remove(client_socket)
            client_socket.close()

    def queue_message(self, sender, target, message):
        # Queue the message to be sent to clients later
        self.message_queue.append({
            "from": sender,
            "target": target,
            "message": message
        })

    def queue_error(self, client_socket, error_message):
        # Queue the error message to be sent to the client later
        self.message_queue.append({
            "status": "error",
            "message": error_message
        })

    def send_messages(self):
        for client_socket, message in self.message_queue:
            try:
                client_socket.sendall(json.dumps(message).encode())
            except Exception as e:
                print(f"Error sending message to client: {e}")
                self.remove_client(client_socket)

        self.message_queue = []

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python server.py <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    server = ChatServer(host, port)
    server.start()
