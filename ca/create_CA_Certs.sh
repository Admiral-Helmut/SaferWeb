#!/bin/sh

# TODO: comment all lines
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=SaferWeb Trust"
# generate a ssl certificate to verify the connection to the saferWeb proxy
openssl genrsa -out cert.key 2048
mkdir ../certs/
