# SSL-Tunnel
SSL tunneling for any TCP/IP connection.

## About the code
The SSL tunneler consists of two parts, a server side and a client side.
Each side is initiated in a state of "listen-connect".
The client side listens for any TCP/IP connection, once a connection is received a new SSL connection
is made to the server side, when the SSL handshake is done between the client and the server,
The server connects to its tunneling endpoint.
As long as no connection is closed the tunnel will stay open.

## Illustration
![Screen1](https://i.imgur.com/reNF8dM.jpg)