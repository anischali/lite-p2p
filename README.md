**Encryption speeds (in term of encryption + decryption time, loop max for both encryption and decryption is 1000) **

![Encryption speeds "image ploted with chat gpt"](data/image.png)

# Crypto openssl context: 

# Commands: 
openssl ciphers -dtls -v

** Generate a private key: **
openssl genpkey -algorithm ED448 -out server.key

** Generate a self-signed certificate **
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=localhost"

** tls server: **
openssl s_server -accept 4433 -cert server.crt -key server.key -cipher ECDHE-RSA-AES256-GCM-SHA384 -dtls

** tls client **
openssl s_client -connect 192.168.0.10:4433 -dtls -cipher ECDHE-RSA-AES256-GCM-SHA384