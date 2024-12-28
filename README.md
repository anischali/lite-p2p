**Encryption speeds (in term of encryption + decryption time, loop max for both encryption and decryption is 1000) **
1 - measure cipher: ChaCha20 {key size: 256 bits} [ encryption time: 801 ms - decryption time: 811 ms ]
2 - measure cipher: AES-128-CTR {key size: 128 bits} [ encryption time: 842 ms - decryption time: 907 ms ]
3 - measure cipher: AES-128-CBC {key size: 128 bits} [ encryption time: 758 ms - decryption time: 1003 ms ]
4 - measure cipher: AES-192-CBC {key size: 192 bits} [ encryption time: 787 ms - decryption time: 1022 ms ]
5 - measure cipher: AES-192-CTR {key size: 192 bits} [ encryption time: 921 ms - decryption time: 977 ms ]
6 - measure cipher: AES-256-CBC {key size: 256 bits} [ encryption time: 823 ms - decryption time: 1081 ms ]
7 - measure cipher: AES-128-ECB {key size: 128 bits} [ encryption time: 782 ms - decryption time: 1158 ms ]
8 - measure cipher: AES-192-ECB {key size: 192 bits} [ encryption time: 805 ms - decryption time: 1191 ms ]
9 - measure cipher: AES-256-CTR {key size: 256 bits} [ encryption time: 961 ms - decryption time: 1037 ms ]
10 - measure cipher: ChaCha20-Poly1305 {key size: 256 bits} [ encryption time: 1001 ms - decryption time: 1001 ms ]
11 - measure cipher: AES-256-ECB {key size: 256 bits} [ encryption time: 841 ms - decryption time: 1228 ms ]
12 - measure cipher: id-aes128-GCM {key size: 128 bits} [ encryption time: 1308 ms - decryption time: 1451 ms ]
13 - measure cipher: id-aes192-GCM {key size: 192 bits} [ encryption time: 1345 ms - decryption time: 1557 ms ]
14 - measure cipher: id-aes256-GCM {key size: 256 bits} [ encryption time: 1450 ms - decryption time: 1560 ms ]
15 - measure cipher: CAMELLIA-128-ECB {key size: 128 bits} [ encryption time: 3045 ms - decryption time: 3219 ms ]
16 - measure cipher: CAMELLIA-128-CTR {key size: 128 bits} [ encryption time: 3499 ms - decryption time: 3424 ms ]
17 - measure cipher: ARIA-128-CBC {key size: 128 bits} [ encryption time: 3871 ms - decryption time: 4050 ms ]
18 - measure cipher: ARIA-128-ECB {key size: 128 bits} [ encryption time: 3773 ms - decryption time: 4235 ms ]
19 - measure cipher: CAMELLIA-192-CTR {key size: 192 bits} [ encryption time: 4043 ms - decryption time: 4127 ms ]
20 - measure cipher: CAMELLIA-192-ECB {key size: 192 bits} [ encryption time: 4006 ms - decryption time: 4234 ms ]
21 - measure cipher: ARIA-128-GCM {key size: 128 bits} [ encryption time: 4244 ms - decryption time: 4157 ms ]
22 - measure cipher: CAMELLIA-256-ECB {key size: 256 bits} [ encryption time: 4352 ms - decryption time: 4284 ms ]
23 - measure cipher: ARIA-128-CTR {key size: 128 bits} [ encryption time: 4391 ms - decryption time: 4292 ms ]
24 - measure cipher: ARIA-192-CBC {key size: 192 bits} [ encryption time: 4389 ms - decryption time: 4539 ms ]
25 - measure cipher: CAMELLIA-256-CTR {key size: 256 bits} [ encryption time: 4111 ms - decryption time: 4825 ms ]
26 - measure cipher: ARIA-192-ECB {key size: 192 bits} [ encryption time: 4219 ms - decryption time: 4776 ms ]
27 - measure cipher: ARIA-192-CTR {key size: 192 bits} [ encryption time: 4539 ms - decryption time: 4601 ms ]
28 - measure cipher: ARIA-192-GCM {key size: 192 bits} [ encryption time: 4627 ms - decryption time: 4663 ms ]
29 - measure cipher: ARIA-256-ECB {key size: 256 bits} [ encryption time: 4758 ms - decryption time: 4955 ms ]
30 - measure cipher: CAMELLIA-128-CBC {key size: 128 bits} [ encryption time: 4860 ms - decryption time: 4974 ms ]
31 - measure cipher: ARIA-256-CBC {key size: 256 bits} [ encryption time: 4851 ms - decryption time: 5004 ms ]
32 - measure cipher: ARIA-256-GCM {key size: 256 bits} [ encryption time: 5109 ms - decryption time: 5047 ms ]
33 - measure cipher: ARIA-256-CTR {key size: 256 bits} [ encryption time: 4979 ms - decryption time: 5275 ms ]
34 - measure cipher: CAMELLIA-192-CBC {key size: 192 bits} [ encryption time: 5496 ms - decryption time: 5846 ms ]
35 - measure cipher: CAMELLIA-256-CBC {key size: 256 bits} [ encryption time: 5727 ms - decryption time: 6117 ms ]


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