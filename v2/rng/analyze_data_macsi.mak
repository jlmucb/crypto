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
#    File: analyze_data.mak


ifndef SRC_DIR
SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
endif
ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
endif
#ifndef GOOGLE_INCLUDE
#GOOGLE_INCLUDE=/usr/local/include/g
#endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

S= $(SRC_DIR)/rng
O= $(OBJ_DIR)/rng
S_SUPPORT=$(SRC_DIR)/crypto_support
S_HASH=$(SRC_DIR)/hash
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(S_SUPPORT) -I/usr/local/include

NEWPROTOBUF=1

ifndef NEWPROTOBUF
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib -lprotobuf -lgtest -lgflags -lpthread
else
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable -D X64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -Wno-unused-variable -D X64
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread
endif

CC=g++
LINK=g++
PROTO=protoc
AR=ar

dobj=   $(O)/analyze_data.o $(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o \
	$(O)/hash.o $(O)/sha256.o $(O)/hash_df.o $(O)/entropy_collection.o $(O)/lz77.o \
	$(O)/probability_support.o

all:    analyze_data.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/analyze_data.exe

analyze_data.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/analyze_data.exe $(dobj) $(LDFLAGS)

$(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h: $(S_SUPPORT)/support.proto
	$(PROTO) -I=$(S) --cpp_out=$(S_SUPPORT) $(S_SUPPORT)/support.proto

$(O)/analyze_data.o: $(S)/analyze_data.cc
	@echo "compiling analyze_data.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/analyze_data.o $(S)/analyze_data.cc

$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc

$(O)/crypto_names.o: $(S_SUPPORT)/crypto_names.cc
	@echo "compiling crypto_names.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_names.o $(S_SUPPORT)/crypto_names.cc

$(O)/hash.o: $(S_HASH)/hash.cc
	@echo "compiling hash.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hash.o $(S_HASH)/hash.cc

$(O)/sha256.o: $(S_HASH)/sha256.cc
	@echo "compiling sha256.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/sha256.o $(S_HASH)/sha256.cc

$(O)/hash_df.o: hash_df.cc
	@echo "compiling hash_df.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hash_df.o hash_df.cc

$(O)/entropy_collection.o: $(S)/entropy_collection.cc
	@echo "compiling entropy_collection.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/entropy_collection.o $(S)/entropy_collection.cc

$(O)/lz77.o: $(S)/lz77.cc
	@echo "compiling lz77.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/lz77.o $(S)/lz77.cc

$(O)/probability_support.o: $(S)/probability_support.cc
	@echo "compiling probability_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/probability_support.o $(S)/probability_support.cc
