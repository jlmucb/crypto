#!/bin/sh
BIN=$HOME/cryptobin
$BIN/cryptutil.exe --operation=get_random --random_size=512 --output_file=random.out
$BIN/cryptutil.exe --operation=hash --algorithm=sha256 --input_file=test_plain
$BIN/cryptutil.exe --operation=from_decimal --input_file=decimal --output_file="bytes.out"
$BIN/cryptutil.exe --operation=to_decimal --input_file="bytes.out" --output_file="decimal.out"

$BIN/cryptutil.exe --operation=generate_mac --algorithm=hmac-sha256 --key_file=random.out \
--mac_key_size=256 --input_file=test_plain --output_file=mac_out
$BIN/cryptutil.exe --operation=verify_mac --algorithm=hmac-sha256 --key_file=random.out \
--mac_key_size=256 --input_file=test_plain --input2_file=mac_out

$BIN/cryptutil.exe --operation=generate_key --algorithm=aes --key_file=enc.key --key_size=256 --key_name=test_key
$BIN/cryptutil.exe --operation=read_key --key_file=enc.key
$BIN/cryptutil.exe --operation=encrypt_with_key --key_file=enc.key --input_file=test_plain --output_file=encrypt_out
$BIN/cryptutil.exe --operation=decrypt_with_key --key_file=enc.key --input_file=encrypt_out --output_file=decrypted

$BIN/cryptutil.exe --operation=generate_key --algorithm=rsa --key_file=rsa_enc.key --key_size=1024 --key_name=rsa_test_key
$BIN/cryptutil.exe --operation=encrypt_with_key --key_file=rsa_enc.key --input_file=rsa_plain --output_file=rsa_encrypt_out
$BIN/cryptutil.exe --operation=decrypt_with_key --key_file=rsa_enc.key --input_file=rsa_encrypt_out --output_file=rsa_decrypted

$BIN/cryptutil.exe --operation=pkcs_sign_with_key --algorithm=rsa-1024-sha-256-pkcs --key_file=rsa_enc.key \
--key_size=1024 --key_name=rsa_test_key --signature_file=signature.file --input_file=test_plain  --signer_name=jlm
$BIN/cryptutil.exe --operation=pkcs_verify_with_key --algorithm=rsa-1024-sha-256-pkcs --key_file=rsa_enc.key \
--key_size=1024 --key_name=rsa_test_key --signature_file=signature.file --input_file=test_plain

$BIN/cryptutil.exe --operation=make_certificate_and_sign --algorithm=rsa-1024-sha-256-pkcs --key_file=rsa_enc.key \
--key_size=1024 --key_name=rsa_test_key --key2_file=rsa_enc.key --issuer_name=jlm \
--subject_name=jlm --output_file=cert.out
$BIN/cryptutil.exe --operation=verify_certificate --algorithm=rsa-1024-sha-256-pkcs --key_file=rsa_enc.key \
--key_size=1024 --key_name=rsa_test_key --key2_file=rsa_enc.key  --input_file=cert.out

$BIN/cryptutil.exe --operation=generate_scheme --scheme_file=new_scheme.ctr --algorithm="aes-hmac-sha256-ctr" \
--encrypt_key_size=128 --mac_key_size=256
$BIN/cryptutil.exe --operation=generate_scheme --scheme_file=new_scheme.cbc --algorithm="aes-hmac-sha256-cbc" \
--encrypt_key_size=128 --mac_key_size=256  --key_name=jlm_test_cbc
$BIN/cryptutil.exe --operation=scheme_encrypt --scheme_file=new_scheme.ctr --input_file=test_plain \
--output_file=test_cipher
$BIN/cryptutil.exe --operation=scheme_decrypt --scheme_file=new_scheme.ctr --input_file=test_cipher \
--output_file=test_decrypted
$BIN/cryptutil.exe --operation=scheme_encrypt --scheme_file=new_scheme.cbc --input_file=test_plain \
--output_file=test_cipher
$BIN/cryptutil.exe --operation=scheme_decrypt --scheme_file=new_scheme.cbc --input_file=test_cipher \
--output_file=test_decrypted
$BIN/cryptutil.exe --operation=scheme_encrypt_file --scheme_file=new_scheme.cbc --input_file=test_plain \
--output_file=test_cipher
$BIN/cryptutil.exe --operation=scheme_decrypt_file --scheme_file=new_scheme.cbc --input_file=test_cipher \
--output_file=test_decrypted
$BIN/cryptutil.exe --operation=scheme_encrypt_file --scheme_file=new_scheme.ctr --input_file=test_plain \
--output_file=test_cipher
$BIN/cryptutil.exe --operation=scheme_decrypt_file --scheme_file=new_scheme.ctr --input_file=test_cipher \
--output_file=test_decrypted

$BIN/cryptutil.exe --operation=encrypt_with_password --algorithm="aes-hmac-sha256-ctr" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=decrypt_with_password --algorithm="aes-hmac-sha256-ctr" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_cipher --output_file=test_decrypted
$BIN/cryptutil.exe --operation=encrypt_with_password --algorithm="aes-hmac-sha256-cbc" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=decrypt_with_password --algorithm="aes-hmac-sha256-cbc" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_cipher --output_file=test_decrypted
$BIN/cryptutil.exe --operation=encrypt_file_with_password --algorithm="aes-hmac-sha256-ctr" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=decrypt_file_with_password --algorithm="aes-hmac-sha256-ctr" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_cipher --output_file=test_decrypted
$BIN/cryptutil.exe --operation=encrypt_file_with_password --algorithm="aes-hmac-sha256-cbc" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_plain --output_file=test_cipher
$BIN/cryptutil.exe --operation=decrypt_file_with_password --algorithm="aes-hmac-sha256-cbc" --encrypt_key_size=128 --mac_key_size=256 \
--pass="my voice is my password" --input_file=test_cipher --output_file=test_decrypted


$BIN/cryptutil.exe --operation=generate_key --key_file=ecc_key --algorithm="ecc" \
-- key_name=ecc_test_key --ecc_curve_name="P-256"
$BIN/cryptutil.exe --operation=read_key --key_file=ecc_key
$BIN/cryptutil.exe --operation=encrypt_with_key --key_file=ecc_key --input_file=ecc_plain \
--output_file=pt1.out --output2_file=pt2.out
$BIN/cryptutil.exe --operation=decrypt_with_key --key_file=ecc_key --input_file=pt1.out \
input2_file=pt2.out --output_file=ecc_decrypted

