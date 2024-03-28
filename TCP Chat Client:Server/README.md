README

Welcome to the Chat Client! This client allows you to connect to a server, join rooms, send messages, and receive updates from the server.

To run the client, execute the following command in your terminal:

python client.py <server_address> <server_port>
Replace <server_address> and <server_port> with the address and port of the chat server (i.e compnet.cs.du.edu/44.218.223.102 and 7775).

How to Use the Client

Upon running the client, you will be prompted to enter your username and the rooms you want to join (comma-separated).

Sending a Message to a Room
To send a message to a room, use the following command:

/send <target> <message>
Replace <target> with the name of the room (e.g /networking) and <message> with the text you want to send.

Sending a Direct Message to a User
To send a direct message to a user, use the following command:

/send <username> <message>
Replace <username> with the target user's name (e.g @Aaron) and <message> with the text you want to send.

Disconnecting
To gracefully disconnect from the server, use the following command:

/quit
This will send a disconnect message to the server and exit the client.

Important Information

Commands must start with a forward slash ("/"). If a command is not recognized, an error message will be displayed.

If you want to join multiple rooms when connecting, use the following command:

/join room1,room2,room3
Replace room1, room2, etc., with the names of the rooms you want to join.

The client will display messages received from the server, including chat history and notifications.

Feel free to explore and enjoy your chat experience! If you encounter any issues, please refer to the error messages for assistance!!!