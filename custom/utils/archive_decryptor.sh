#!/bin/bash

# @copyright Copyright (c) 2021 Nicolas GRELLETY
# @license https://opensource.org/licenses/GPL-3.0 GNU GPLv3
# @link https://gitlab.internal.lan/octo-project/octobaselines
# @link https://github.com/nillyr/octobaselines
# @since 1.0.0b

usage() {
    echo "Usage: bash $0 <unpacked archive path> <RSA private key path>" >&2
    exit 1
}

decrypt_aes_key() {
    local rsa_private_key_path=$1
    local encrypted_aes_key_path=$2

    decrypted_key=$(base64 -di "$encrypted_aes_key_path" | openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha384 -inkey "$rsa_private_key_path")

    # AES-256 bits => (256/8) * 2 = 64
    if [ ! ${#decrypted_key} -eq 64 ]; then
        # This happens with the PowerShell version of the script (util).
        decrypted_key=$(echo -n "$decrypted_key" | base64 -di | od -t x1 -An | tr -d " ")
        decrypted_key=${decrypted_key//[$'\t\r\n ']}
    fi

    echo -n "$decrypted_key"
}

decrypt_data() {
    local key=$1

    data=$(</dev/stdin)

    IFS_BAK=$IFS; IFS=$'\n' read -d "" -ra encrypted_blocks <<< "$data"; IFS=$IFS_BAK

    for encrypted_block in "${encrypted_blocks[@]}"; do
        encrypted_hex=$(echo "$encrypted_block" | base64 -di | xxd -p | tr -d $'\n')
        iv=${encrypted_hex::32}
        encrypted_hex=${encrypted_hex:32:${#encrypted_hex}}
        echo "$encrypted_hex" | xxd -r -ps | openssl enc -d -aes-256-cbc -K "$key" -iv "$iv" && echo ""
    done
}

decrypt_and_save() {
    local aes_key=$1
    local og_file=$2

    og_file=$(realpath "$og_file")
    tmp_file=$(mktemp -p "${og_file%/*}")
    decrypt_data "$aes_key" < "$og_file" >> "$tmp_file" && mv "$tmp_file" "$og_file"
}

main() {
    if [ $# -le 1 ]; then
	    usage
    fi

    local unpacked_archive_path=$1
    local rsa_private_key_path=$2

    aes_key=$(decrypt_aes_key "$rsa_private_key_path" "$unpacked_archive_path"/aes_key.enc)

    find "$unpacked_archive_path" -type f -name "*.txt" -print0 |
        while read -d $'\0' -r encrypted_file; do
            decrypt_and_save "$aes_key" "$encrypted_file"
        done
}

main "$@"
