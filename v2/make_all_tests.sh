#
cd crypto_support
make clean -f test_crypto_support.mak
make -f test_crypto_support.mak
cd ../hash
make clean -f test_hash.mak
make -f test_hash.mak
cd ../symmetric
make clean -f test_symmetric.mak
make -f test_symmetric.mak
cd ../big_num
make clean -f test_big_num.mak
make -f test_big_num.mak
cd ../rsa
make clean -f test_rsa.mak
make -f test_rsa.mak
cd ../ecc
make clean -f test_ecc.mak
make -f test_ecc.mak
cd ..

