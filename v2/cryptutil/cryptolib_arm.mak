#    Copyright 2014 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#        http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    File: cryptolib_arm.mak


SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
ifndef SRC_DIR
SRC_DIR=$(HOME)/crypto/v2
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
endif
ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
endif
ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE=ARM64
endif

S_SUPPORT=$(SRC_DIR)/crypto_support
S_BIGNUM=$(SRC_DIR)/big_num
S_HASH=$(SRC_DIR)/hash
S_SYMMETRIC=$(SRC_DIR)/symmetric
S_LATTICES=$(SRC_DIR)/lattices
S_RSA=$(SRC_DIR)/rsa
S_ECC=$(SRC_DIR)/ecc
S_ENCRYPTION_SCHEME=$(SRC_DIR)/encryption_scheme
S_MISC=$(SRC_DIR)/misc

O= $(OBJ_DIR)/cryptolib
INCLUDE= -I$(SRC_DIR)/include -I$(S_SUPPORT) -I/usr/local/include

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -D ARM64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -D ARM64

CC=g++
LINK=g++
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread

dobj=  $(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o $(O)/globals.o \
       $(O)/arm64_digit_arith.o $(O)/big_num.o $(O)/basic_arith.o $(O)/number_theory.o \
       $(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o $(O)/hash.o \
       $(O)/sha1.o $(O)/sha256.o $(O)/hmac_sha256.o $(O)/pkcs.o $(O)/pbkdf2.o $(O)/sha3.o \
       $(O)/encryption_scheme.o $(O)/rsa.o  $(O)/ecc.o $(O)/ecc_curve_data.o $(O)/lll.o \
       $(O)/lwe.o $(O)/ntru.o $(O)/symmetric_cipher.o $(O)/aes.o $(O)/tea.o \
       $(O)/rc4.o $(O)/twofish.o $(O)/simonspeck.o



all:	$(OBJ_DIR)/jlmcryptolib.a
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing library file"
	rm $(OBJ_DIR)/jlmcryptolib.a

AR=ar
PROTO=protoc

$(OBJ_DIR)/jlmcryptolib.a: $(dobj) 
	@echo "linking library"
	$(AR) r $(OBJ_DIR)/jlmcryptolib.a $(dobj) # $(LDFLAGS)

$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc

$(O)/crypto_names.o: $(S_SUPPORT)/crypto_names.cc
	@echo "compiling crypto_names.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_names.o $(S_SUPPORT)/crypto_names.cc

$(O)/lll.o: $(S_LATTICES)/lll.cc
	@echo "compiling lll.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/lll.o $(S_LATTICES)/lll.cc

$(O)/lwe.o: $(S_LATTICES)/lwe.cc
	@echo "compiling lwe.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/lwe.o $(S_LATTICES)/lwe.cc

$(O)/ntru.o: $(S_LATTICES)/ntru.cc
	@echo "compiling ntru.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/ntru.o $(S_LATTICES)/ntru.cc

$(O)/globals.o: $(S_BIGNUM)/globals.cc
	@echo "compiling globals.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/globals.o $(S_BIGNUM)/globals.cc

$(O)/arm64_digit_arith.o: $(S_BIGNUM)/arm64_digit_arith.cc
	@echo "compiling arm64_digit_arith.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/arm64_digit_arith.o $(S_BIGNUM)/arm64_digit_arith.cc

$(O)/basic_arith.o: $(S_BIGNUM)/basic_arith.cc
	@echo "compiling basic_arith.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/basic_arith.o $(S_BIGNUM)/basic_arith.cc

$(O)/number_theory.o: $(S_BIGNUM)/number_theory.cc
	@echo "compiling number_theory.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/number_theory.o $(S_BIGNUM)/number_theory.cc

$(O)/big_num.o: $(S_BIGNUM)/big_num.cc
	@echo "compiling big_num.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/big_num.o $(S_BIGNUM)/big_num.cc

$(O)/rsa.o: $(S_RSA)/rsa.cc
	@echo "compiling rsa.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/rsa.o $(S_RSA)/rsa.cc

$(O)/ecc.o: $(S_ECC)/ecc.cc
	@echo "compiling ecc.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/ecc.o $(S_ECC)/ecc.cc

$(O)/ecc_curve_data.o: $(S_ECC)/ecc_curve_data.cc
	@echo "compiling ecc_curve_data.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/ecc_curve_data.o $(S_ECC)/ecc_curve_data.cc

$(O)/symmetric_cipher.o: $(S_SYMMETRIC)/symmetric_cipher.cc
	@echo "compiling symmetric_cipher.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/symmetric_cipher.o $(S_SYMMETRIC)/symmetric_cipher.cc

$(O)/aes.o: $(S_SYMMETRIC)/aes.cc
	@echo "compiling aes.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/aes.o $(S_SYMMETRIC)/aes.cc

$(O)/twofish.o: $(S_SYMMETRIC)/twofish.cc
	@echo "compiling twofish.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/twofish.o $(S_SYMMETRIC)/twofish.cc

$(O)/encryption_scheme.o: $(S_ENCRYPTION_SCHEME)/encryption_scheme.cc
	@echo "compiling encryption_scheme.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/encryption_scheme.o $(S_ENCRYPTION_SCHEME)/encryption_scheme.cc

$(O)/hash.o: $(S_HASH)/hash.cc
	@echo "compiling hash.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hash.o $(S_HASH)/hash.cc

$(O)/sha1.o: $(S_HASH)/sha1.cc
	@echo "compiling sha1.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/sha1.o $(S_HASH)/sha1.cc

$(O)/sha256.o: $(S_HASH)/sha256.cc
	@echo "compiling sha256.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/sha256.o $(S_HASH)/sha256.cc

$(O)/hmac_sha256.o: $(S_HASH)/hmac_sha256.cc
	@echo "compiling hmac_sha256.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hmac_sha256.o $(S_HASH)/hmac_sha256.cc

$(O)/pkcs.o: $(S_HASH)/pkcs.cc
	@echo "compiling pkcs.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/pkcs.o $(S_HASH)/pkcs.cc

$(O)/pbkdf2.o: $(S_HASH)/pbkdf2.cc
	@echo "compiling pbkdf2.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/pbkdf2.o $(S_HASH)/pbkdf2.cc

$(O)/sha3.o: $(S_HASH)/sha3.cc
	@echo "compiling sha3.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/sha3.o $(S_HASH)/sha3.cc

$(O)/tea.o: $(S_SYMMETRIC)/tea.cc
	@echo "compiling tea.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/tea.o $(S_SYMMETRIC)/tea.cc

$(O)/rc4.o: $(S_SYMMETRIC)/rc4.cc
	@echo "compiling rc4.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/rc4.o $(S_SYMMETRIC)/rc4.cc

$(O)/simonspeck.o: $(S_SYMMETRIC)/simonspeck.cc
	@echo "compiling simonspeck.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/simonspeck.o $(S_SYMMETRIC)/simonspeck.cc
