#
cd crypto_support
make -f test_crypto_support.mak
cd ../hash
make -f test_hash.mak
cd ../symmetric
make -f test_symmetric.mak
cd ../big_num
make -f test_big_num.mak
cd ../rsa
make -f test_rsa.mak
cd ../ecc
make -f test_ecc.mak
cd ..

