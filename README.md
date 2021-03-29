# vpn

Project of the course Internet Security and Privacy

### Description
This project is an implementation of a port forwarding VPN. It operates at the transport layer and is implemented through forwarding applications that forward (or relay) data between TCP connections.

### Usage 

To start the server:
```bash
$ java ForwardServer --handshakeport=2206 --usercert=server.pem--cacert=ca.pem --key=server-private.der
```
The ForwardServer takes four arguments:
- "handshakeport" – the TCP port number where ForwardServer should wait for incoming TCP connections (the default is port 2206). On this port, the HandShake protocol is carried out (more about this later).
- "usercert" – the name of a file with the server's certificate.
- "cacert" –  the name of a file with the certificate of the CA that (is supposed to have) signed the client's certificate.
- "key" – the server's private key.

To start a client:
```bash
$ java ForwardClient --handshakehost=portfw.kth.se  --handshakeport=2206 \
                     --proxyport=12345 \
                     --targethost=server.kth.se --targetport=6789 \
                     --usercert=client.pem --cacert=ca.pem --key=client-private.der 
```
ForwardClient takes seven arguments:
- "handshakeport" – the TCP port number to which FowardClient should connect and carry out the HandShake protocol.
- "handshakehost"  –the name of the host where "handshake port" is.
- "proxyport" – the port number to which the user will connect
- "targetport" – the TCP port number for the final destination of the VPN connection. That is, the port to which the VPN user wants to connect.
- "targethost" –  the name of the host where "targetport" is.
- "usercert" – the name of a file with the client's certificate.
- "cacert" – the name of a file with the certificate of the CA that (is supposed to have) signed the server's certificate.
- "key" – the client's private key.  

### Note
The certificates and key files are not used in any manner in real life and you should not use them as well.
