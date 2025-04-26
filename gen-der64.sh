#!/bin/zsh

if [ -z "$1" ]; then
    num_bits=3072
else
    num_bits=$1
fi

# Generate 3072-bit RSA private key directly in PEM
openssl genrsa -out private.pem $num_bits

openssl rsa -outform DER -in private.pem -out private.der
openssl rsa -RSAPublicKey_out -outform DER -in private.pem -out public.der

# Base64 encode the DER files (without newlines)
base64 < private.der | tr -d '\n' > private.der.b64
base64 < public.der | tr -d '\n' > public.der.b64

# Write to .env cleanly without extra newlines
{
  printf "JWT_PRIVATE=%s\n" "$(cat private.der.b64)"
  printf "JWT_PUBLIC=%s\n" "$(cat public.der.b64)"
} > .env

