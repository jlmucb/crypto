//
// Copyright 2014 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// File: keytest.cc

#include "cryptotypes.h"
#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>
#include "keys.pb.h"
#include "keys.h"
#include "util.h"
#include "string.h"
#include "conversions.h"
#include <cmath>


DEFINE_bool(printall, false, "printall flag");

bool simpletest1() {
  SymmetricKey the_key;
  SymmetricKey new_key;

  if (!the_key.GenerateAesKey("JohnsKey", "channel-encryption",
                              "John Manferdelli", 128, COMMON_YEAR_SECONDS)) {
    printf("GenerateAesKey failed\n");
    return false;
  }

    printf("Original key:\n");
    the_key.PrintKey();
    printf("\n");

  string filename("jlmTestSave1");
  if (!((CryptoKey*)&the_key)->SaveKey(filename)) {
    printf("SaveKey failed\n");
    return false;
  }

  if (!((CryptoKey*)&new_key)->ReadKey(filename)) {
    printf("ReadKey failed\n");
    return false;
  }
    printf("Recovered key:\n");
    new_key.PrintKey();
    printf("\n");
  if (the_key.key_name_ != nullptr && *the_key.key_name_ != *new_key.key_name_) {
    printf("key names disagree\n");
    return false;
  }
  if (the_key.key_type_ != nullptr && *the_key.key_type_ != *new_key.key_type_) {
    printf("key types disagree\n");
    return false;
  }
  if (the_key.key_usage_ != nullptr && *the_key.key_usage_ != *new_key.key_usage_) {
    printf("key usage disagree\n");
    return false;
  }
  if (*the_key.symmetric_algorithm_type_ != *new_key.symmetric_algorithm_type_) {
    printf("Algorithm types disagree\n");
    return false;
  }
  if (the_key.symmetric_key_bit_size_ != new_key.symmetric_key_bit_size_) {
    printf("key sizes differ\n");
    return false;
  }
  if (memcmp(the_key.symmetric_key_bytes_ , new_key.symmetric_key_bytes_, the_key.symmetric_key_bit_size_ / 8) !=0) {
    printf("key values differ\n");
    return false;
  }
  return true;
}

bool RunTestSuite() {
  KeyStore key_store;
  SymmetricKey the_key;

  if (!the_key.GenerateAesKey("JohnsStoreKey1", "channel-encryption",
                              "John Manferdelli", 128, COMMON_YEAR_SECONDS)) {
    printf("GenerateAesKey failed\n");
    return false;
  }

  if (!key_store.ReadStore("TestKeyStore")) {
    printf("Can't read key store\n");
    return false;
  }
  if (!key_store.AddKey((CryptoKey*)&the_key)) {
    printf("Can't add to key store\n");
    return false;
  }

  CryptoKey* p_msg = nullptr;
  string* p_string = nullptr;
  if (!key_store.FindKey("JohnsStoreKey1", &p_string, &p_msg)) {
    printf("Cant find key in store\n");
    return false;
  }
  if (FLAGS_printall) {
    ((SymmetricKey*)p_msg)->PrintKey();
  }
  return true;
}

DEFINE_string(log_file, "keytest.log", "keytest logging file name");

int main(int an, char** av) {

  if (!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  int num_tests = 0;
  int num_failed = 0;

  num_tests++;
  if(!simpletest1()) {
    printf("simpletest1() failed\n");
    num_failed++;
  }
  num_tests++;
  if(!RunTestSuite()) {
    printf("RunTestSuite() failed\n");
    num_failed++;
  }
  CloseUtilities();
  printf("%d tests, %d failed\n", num_tests, num_failed);
  return num_failed;
}
