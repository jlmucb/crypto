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
#    File: pwutil.mak


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
TARGET_MACHINE_TYPE= x64
endif

#ifndef SRC_DIR
SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
#endif
#ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
#endif

S= $(SRC_DIR)/rng
O= $(OBJ_DIR)/rng
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(S_SUPPORT) -I/usr/local/include
S_SUPPORT=$(SRC_DIR)/crypto_support
S_HASH=$(SRC_DIR)/hash

CC=g++
LINK=g++
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -DX64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -DX64
PROTO=protoc
AR=ar
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread

dobj=	$(O)/entropy_series.o $(O)/support.pb.o $(O)/crypto_support.o $(O)/probability_support.o $(O)/lz77.o

all:	entropy_series.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/entropy_series.exe

entropy_series.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/entropy_series.exe $(dobj) $(LDFLAGS)

$(O)/entropy_series.o: $(S)/entropy_series.cc
	@echo "compiling entropy_series.cc"
	$(CC) $(CFLAGS) -c -o $(O)/entropy_series.o $(S)/entropy_series.cc

$(O)/probability_support.o: $(S)/probability_support.cc
	@echo "compiling probability_support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/probability_support.o $(S)/probability_support.cc

$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc

$(O)/lz77.o: $(S)/lz77.cc
	@echo "compiling lz77.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/lz77.o $(S)/lz77.cc
