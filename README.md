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
![Screen1](https://i.imgur.com/nKY9Khm.jpg)

### Remarks
The password for the PKCS#12 file that comes with the repo is "12345",
though it is recommended you create your own PKCS#12 file for security reasons.
