#!/bin/sh
BIN=$HOME/cryptobin
$BIN/cryptutil.exe --operation=generate_scheme --scheme_file=new_scheme --algorithm="aes-hmac-sha256-ctr" --encrypt_key_size=128 --mac_key_size=256
$BIN/cryptutil.exe --operation=scheme_encrypt --scheme_file=new_scheme --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=scheme_decrypt --scheme_file=new_scheme --input_file=test_cipher --output_file=test_decrypted
$BIN/cryptutil.exe --operation=encrypt_with_password --algorithm="aes-hmac-sha256-ctr" --encrypt_key_size=128 --mac_key_size=256 --pass="my voice is my password" --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=decrypt_with_password --algorithm="aes-hmac-sha256-ctr" --encrypt_key_size=128 --mac_key_size=256 --pass="my voice is my password" --input_file=test_cipher --output_file=test_decrypted

$BIN/cryptutil.exe --operation=generate_scheme --scheme_file=new_scheme --algorithm="aes-hmac-sha256-cbc" --encrypt_key_size=128 --mac_key_size=256  --key_name=jlm_test_cbc
$BIN/cryptutil.exe --operation=scheme_encrypt --scheme_file=new_scheme --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=scheme_decrypt --scheme_file=new_scheme --input_file=test_cipher --output_file=test_decrypted
$BIN/cryptutil.exe --operation=encrypt_with_password --algorithm="aes-hmac-sha256-cbc" --encrypt_key_size=128 --mac_key_size=256 --pass="my voice is my password" --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=decrypt_with_password --algorithm="aes-hmac-sha256-cbc" --encrypt_key_size=128 --mac_key_size=256 --pass="my voice is my password" --input_file=test_cipher --output_file=test_decrypted

$BIN/cryptutil.exe --operation=get_random --random_size=512 --output_file=random.out
$BIN/cryptutil.exe --operation=hash --algorithm=sha256 --input_file=test_plain
$BIN/cryptutil.exe --operation=to_decimal --input_file=in --output_file=out
$BIN/cryptutil.exe --operation=from_decimal --input_file=in --output_file=out
$BIN/cryptutil.exe --operation=generate_mac --algorithm=alg --key_file=file --mac_key_size=256 --input_file=file --output_file=file
$BIN/cryptutil.exe --operation=verify_mac --algorithm=alg --key_file=file --mac_key_size=256 --input_file=file --input2_file=file
