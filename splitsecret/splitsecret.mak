#
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
#    Project: New Cloudproxy Crypto
#    File: splitsecret.mak

#ifndef SRC_DIR
SRC_DIR=$(HOME)/crypto
#endif
#ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj
#endif
#ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
#endif
#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif
#ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
#endif

S= $(SRC_DIR)/splitsecret
O= $(OBJ_DIR)/splitsecret
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(SRC_DIR)/keys

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O3 -g -Wall -std=c++11

include ../OSName
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
endif


dobj_gf2_common_test=$(O)/gf2_common.o $(O)/gf2_common_test.o $(O)/splitsecret.pb.o
dobj_splitsecret=$(O)/gf2_common.o $(O)/splitsecret.pb.o $(O)/splitsecret.o

all:	gf2_common_test.exe splitsecret.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/gf2_common_test.exe

gf2_common_test.exe: $(dobj_gf2_common_test) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/gf2_common_test.exe $(dobj_gf2_common_test) $(LDFLAGS)

splitsecret.exe: $(dobj_splitsecret) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/splitsecret.exe $(dobj_splitsecret) $(LDFLAGS)

$(O)/gf2_common.o: $(S)/gf2_common.cc
	@echo "compiling gf2_common.cc"
	$(CC) $(CFLAGS) -c -o $(O)/gf2_common.o $(S)/gf2_common.cc

$(O)/gf2_common_test.o: $(S)/gf2_common_test.cc
	@echo "compiling gf2_common_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/gf2_common_test.o $(S)/gf2_common_test.cc

$(O)/splitsecret.pb.o: $(S)/splitsecret.pb.cc
	@echo "compiling splitsecret.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/splitsecret.pb.o $(S)/splitsecret.pb.cc

$(O)/splitsecret.o: $(S)/splitsecret.cc
	@echo "compiling splitsecret.cc"
	$(CC) $(CFLAGS) -c -o $(O)/splitsecret.o $(S)/splitsecret.cc

