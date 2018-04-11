#!/bin/bash
echo ""
if [ $1 == "clean" ]
then
  make -f cryptolib.mak clean
  cd bignum
  make -f bignumtest.mak clean
  cd ..
  cd common
  make -f commontest.mak clean
  cd ..
  cd cryptutil
  make -f cryptutil.mak clean
  cd ..
  cd ecc
  make -f schoof.mak clean
  cd ..
  cd hash
  make -f hashtest.mak clean
  cd ..
  cd indeterminate
  make -f indeterminatetest.mak clean
  cd ..
  cd keys
  make -f keytest.mak clean
  cd ..
  cd lattice
  make -f lattice.mak clean
  cd ..
  cd rsa
  make -f rsatest.mak clean
  cd ..
  cd splitsecret
  make -f splitsecret.mak clean
  cd ..
  cd symmetric
  make -f symmetrictest.mak clean
  cd ..
fi
make -f cryptolib.mak
cd bignum
make -f bignumtest.mak
cd ..
cd common
make -f commontest.mak
cd ..
cd cryptutil
make -f cryptutil.mak
cd ..
cd ecc
make -f schoof.mak
cd ..
cd hash
make -f hashtest.mak
cd ..
cd indeterminate
make -f indeterminatetest.mak
cd ..
cd keys
make -f keytest.mak
cd ..
cd lattice
make -f lattice.mak
cd ..
cd rsa
make -f rsatest.mak
cd ..
cd splitsecret
make -f splitsecret.mak
cd ..
cd symmetric
make -f symmetrictest.mak
cd ..
