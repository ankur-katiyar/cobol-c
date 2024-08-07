#!/bin/bash

# Check if the string and recipient are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <string_to_encrypt> <recipient>"
    exit 1
fi

# Input string and recipient
recipient=$1
input_string=$2

# Encrypt the string and encode it in Base64
encrypted_base64=$(echo "$input_string" | gpg --batch --yes --passphrase "S@mar@123" --encrypt --armor --recipient "$recipient" | base64)

# Output the encrypted and Base64 encoded string
echo "Encrypted and Base64 encoded string:"
echo "$encrypted_base64"

# Decrypt and decode the Base64 string
decrypted_string=$(echo "$encrypted_base64" | base64 --decode | gpg  --batch --yes --passphrase "S@mar@123" --decrypt)

# Output the decrypted string
echo "Decrypted string:"
echo "$decrypted_string"
