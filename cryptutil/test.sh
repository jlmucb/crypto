#
./cryptutil.exe --operation=Hash --algorithm=sha-1 --input_file=randFile
./cryptutil.exe --operation=Hash --algorithm=sha-256 --input_file=randFile
./cryptutil.exe --operation=GetRandom --size=256 --output_file=randFile
./cryptutil.exe --operation=ToBase64 direction=right-to-left --input_file=randFile
./cryptutil.exe --operation=ToDecimal --input_file=randFile
./cryptutil.exe --operation=ToBase64 --direction=left-right --input_file=randFile --output_file=base64.out
./cryptutil.exe --operation=FromBase64 --direction=left-right --input_file=base64.out --output_file=base64.out2
./cryptutil.exe --operation=ToHex --direction=left-right --input_file=randFile --output_file=hex.out
./cryptutil.exe --operation=FromHex --direction=left-right --input_file=hex.out --output_file=hex.out2
./cryptutil.exe --operation=ToBase64 --direction=left-right --input_file=randFile --output_file=base64.out
./cryptutil.exe --operation=FromBase64 --direction=left-right --input_file=base64.out --output_file=base64.out2
./cryptutil.exe --operation=GenerateKey --algorithm=aes-128 --key_name=johnkey1 --duration=1Y \
--output_file=johnsaeskey1 --owner=JLM --purpose=bulk-encryption
./cryptutil.exe --operation=ReadKey --algorithm=aes-128 --input_file=johnsaeskey1
./cryptutil.exe --operation=GenerateKey --algorithm=rsa-1024 --key_name=johnkey2 --duration=1Y \
--output_file=johnsrsakey1 --owner=JLM --purpose=bulk-encryption
./cryptutil.exe --operation=SymEncryptWithKey --key_file=johnsaeskey1 --algorithm=aes-128 --input_file=randFile --output_file=randFile.out
./cryptutil.exe --operation=SymDecryptWithKey --key_file=johnsaeskey1 --algorithm=aes-128 --input_file=randFile.out --output_file=randFile.out2
./cryptutil.exe --operation=GenerateScheme --algorithm=aes128-cbc-hmacsha256-sympad --key_name=johnscbcscheme1 --duration=1Y --output_file=cbcschemefile1
./cryptutil.exe --operation=ReadScheme --algorithm=aes128-cbc-hmacsha256-sympad --input_file=cbcschemefile1
./cryptutil.exe --operation=SymEncryptWithScheme --key_file=cbcschemefile1 --algorithm=aes128-cbc-hmacsha256-sympad --input_file=jlmTestSave1 --output_file=jlmTestSave1.enc
./cryptutil.exe --operation=SymDecryptWithScheme --key_file=cbcschemefile1 --algorithm=aes128-cbc-hmacsha256-sympad --input_file=jlmTestSave1.enc --output_file=jlmTestSave1.dec
./cryptutil.exe --operation=GenerateScheme --algorithm=aes128-ctr-hmacsha256-sympad --key_name=johnsctrscheme1 --duration=1Y --output_file=ctrschemefile1
./cryptutil.exe --operation=ReadScheme --algorithm=aes128-ctr-hmacsha256-sympad --input_file=ctrschemefile1
./cryptutil.exe --operation=SymEncryptWithScheme --key_file=ctrschemefile1 --algorithm=aes128-ctr-hmacsha256-sympad --input_file=jlmTestSave1 --output_file=jlmTestSave2.enc
./cryptutil.exe --operation=SymDecryptWithScheme --key_file=ctrschemefile1 --algorithm=aes128-ctr-hmacsha256-sympad --input_file=jlmTestSave2.enc --output_file=jlmTestSave2.dec
./cryptutil.exe --operation=EncryptWithPassword --pass=password --algorithm=aes128-cbc-hmacsha256-sympad --input_file=jlmTestSave1 --output_file=jlmTestSave3.enc
./cryptutil.exe --operation=DecryptWithPassword --algorithm=aes128-cbc-hmacsha256-sympad --input_file=jlmTestSave3.enc --output_file=jlmTestSave3.dec
./cryptutil.exe --operation=EncryptWithPassword --pass=password --algorithm=aes128-ctr-hmacsha256-sympad --input_file=jlmTestSave1 --output_file=jlmTestSave4.enc
./cryptutil.exe --operation=DecryptWithPassword --algorithm=aes128-ctr-hmacsha256-sympad --input_file=jlmTestSave4.enc --output_file=jlmTestSave4.dec
./cryptutil.exe --operation=PkcsSignWithKey --algorithm=rsa-1024-sha-256-pkcs --key_file=johnsrsakey1 --hash_file=randFile --output_file=randFile.sig
./cryptutil.exe --operation=PkcsVerifyWithKey --algorithm=rsa-1024-sha-256-pkcs --key_file=johnsrsakey1 --hash_file=randFile --sig_file=randFile.sig
./cryptutil.exe --operation=PkcsPubSealWithKey --key_file=johnsrsakey1 --algorithm=rsa-1024 --input_file=toseal --output_file=sealedsecret
./cryptutil.exe --operation=PkcsPubUnsealWithKey --key_file=johnsrsakey1 --algorithm=rsa-1024 --input_file=sealedsecret --output_file=secret2

#./cryptutil.exe --operation=Mac --algorithm=alg --keyfile=file --input_file=file --output_file=file
#./cryptutil.exe --operation=VerifyMac --algorithm=alg --keyfile=file --input_file=file --output_file=file

