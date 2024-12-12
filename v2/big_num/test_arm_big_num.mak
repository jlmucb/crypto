#    Copyright 2014 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#	http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    File: test_arm_big_num.mak

SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
ifndef SRC_DIR
endif
ifndef OBJ_DIR
SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
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

S= $(SRC_DIR)/big_num
O= $(OBJ_DIR)/big_num
S_SUPPORT= $(SRC_DIR)/crypto_support
INCLUDE= -I$(S) -I$(SRC_DIR)/include -I$(S_SUPPORT) -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -D ARM64
CFLAGS1=$(INCLUDE) -O3 -g -Wall -std=c++11 -D ARM64

# Simulator commands
# readelf: readelf –a running_arm_entropy.exe
# 32 bit arm
# Compiler: arm-linux-gnueabi-g++ --static
# Compiler: arm-linux-gnueabi-gcc --static
# objdump: arm-linux-gnu-objdump --disassemble-all test1_arm.o
# Simulator: qemu-arm running_arm_entropy.exe --in find_key1_arm.o

# 64 bit arm
# compile: aarch64-linux-gnu-g++ -static
# compile: aarch64-linux-gnu-gcc -static
# objdump: aarch64-linux-gnu-objdump --disassemble-all test1_arm.o
# to run: qemu-aarch64-static ~/cryptobin/test_arm_big_num.exe


SIMTARGET=1
ifdef SIMTARGET
	CC=aarch64-linux-gnu-g++ -static
	LINK=aarch64-linux-gnu-g++ -static
	AR=ar
	LDFLAGS= # $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	AR=ar
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
endif

dobj=   $(O)/test_arm_big_num.o $(O)/arm64_digit_arith.o  #$(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o \
        #$(O)/globals.o $(O)/big_num.o $(O)/basic_arith.o $(O)/number_theory.o

all:    test_arm_big_num.exe

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/arm64_bignum_test.exe

test_arm_big_num.exe: $(dobj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/test_arm_big_num.exe $(dobj) $(LDFLAGS)

$(O)/test_arm_big_num.o: $(S)/test_arm_big_num.cc
	@echo "compiling test_arm_big_num.cc"
	$(CC) $(CFLAGS) -c -o $(O)/test_arm_big_num.o $(S)/test_arm_big_num.cc

$(O)/arm64_digit_arith.o: $(S)/arm64_digit_arith.cc
	@echo "compiling arm64_digit_arith.cc"
	$(CC) $(CFLAGS) -c -o $(O)/arm64_digit_arith.o $(S)/arm64_digit_arith.cc

#$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc
#	@echo "compiling support.pb.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

#$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc
#	@echo "compiling crypto_support.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc
#
#$(O)/crypto_names.o: $(S_SUPPORT)/crypto_names.cc
#	@echo "compiling crypto_names.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/crypto_names.o $(S_SUPPORT)/crypto_names.cc
#
#$(O)/globals.o: $(S)/globals.cc
#	@echo "compiling globals.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/globals.o $(S)/globals.cc
#
#$(O)/big_num.o: $(S)/big_num.cc
#	@echo "compiling big_num.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/big_num.o $(S)/big_num.cc
#
#$(O)/basic_arith.o: $(S)/basic_arith.cc
#	@echo "compiling basic_arith.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/basic_arith.o $(S)/basic_arith.cc
#
#$(O)/number_theory.o: $(S)/number_theory.cc
#	@echo "compiling number_theory.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/number_theory.o $(S)/number_theory.cc
