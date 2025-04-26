#!/bin/zsh

# Generate 3072-bit RSA private key directly in PEM
if [ -z "$1" ]; then
    num_bits=3072
else
    num_bits=$1
fi

openssl genrsa -out private.pem $num_bits

# Convert private key to PKCS#8 DER format
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -nocrypt -out private.der

# Extract public key and convert to SubjectPublicKeyInfo DER format
openssl rsa -in private.pem -pubout -outform DER -out public.der

# Base64 encode the DER files (without newlines)
base64 < private.der | tr -d '\n' > private.der.b64
base64 < public.der | tr -d '\n' > public.der.b64

# Write to .env cleanly without extra newlines
{
  printf "JWT_PRIVATE=%s\n" "$(cat private.der.b64)"
  printf "JWT_PUBLIC=%s\n" "$(cat public.der.b64)"
} > .env  

openssl rsa -in private.der -inform DER -check
