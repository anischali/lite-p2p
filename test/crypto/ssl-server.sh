#! /usr/bin/env bash

do_clean() {
    [ -e "$(pwd)/server.key" ] && rm "$(pwd)/server.key"
    [ -e "$(pwd)/server.crt" ] && rm "$(pwd)/server.crt"
}

trap do_clean SIGABRT SIGHUP SIGINT SIGQUIT SIGTERM 0

# Generate a private key
openssl genpkey -algorithm ED448 -out server.key

# Generate a self-signed certificate
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=localhost"



openssl s_server -accept 4433 -cert server.crt -key server.key $@