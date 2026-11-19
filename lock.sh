#!/bin/bash


usage() {
    echo "Usage:"
    echo "  $0 generate [length]          Generate a random password (default: 20 chars)"
    echo "  $0 encrypt <filename>         Encrypt a file using AES-256"
    echo "  $0 decrypt <filename.enc>     Decrypt a .enc file"
    exit 1
}


if [ "$#" -lt 1 ]; then
    usage
fi

MODE=$1


if [ "$MODE" == "generate" ]; then
    LENGTH=${2:-20} 
    
    
    if ! [[ "$LENGTH" =~ ^[0-9]+$ ]] || [ "$LENGTH" -lt 8 ]; then
        echo "Error: Password length must be a number (minimum 8)."
        exit 1
    fi

    PASSWORD=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c "$LENGTH")
    echo "Generated Password ($LENGTH chars):"
    echo "$PASSWORD"
    exit 0
fi


if [ "$#" -ne 2 ]; then
    usage
fi

FILE=$2

if [ ! -f "$FILE" ]; then
    echo "Error: File '$FILE' not found."
    exit 1
fi


read -s -p "Enter Password: " PASSWORD
echo ""


if [ "$MODE" == "encrypt" ]; then
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in "$FILE" -out "${FILE}.enc" -pass pass:"$PASSWORD"
    if [ $? -eq 0 ]; then
        echo "Success! Encrypted file saved as: ${FILE}.enc"
    else
        echo "Error: Encryption failed."
        exit 1
    fi


elif [ "$MODE" == "decrypt" ]; then
    OUTPUT_FILE="${FILE%.enc}"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in "$FILE" -out "$OUTPUT_FILE" -pass pass:"$PASSWORD"
    if [ $? -eq 0 ]; then
        echo "Success! Decrypted file restored as: $OUTPUT_FILE"
    else
        echo "Error: Decryption failed (wrong password or corrupted file)."
        exit 1
    fi
else
    usage
fi
