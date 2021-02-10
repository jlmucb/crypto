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
// File: test_hash.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "sha256.h"
#include "pbkdf.h"

DEFINE_bool(debug, false, "Debug");
DEFINE_string(length, "14", "password length");
DEFINE_string(salt, "59a65c58b793ef", "Salt even number of hex digits");
DEFINE_string(password, "", "Password");
DEFINE_string(site, "www.nyt.com", "site url");
const int iter = 100;

char map_c[256] = {
  '1', '2', '3', '4', '5', '6', '7', '8', 
  '9', '0', '-', '_', 'q', 'w', 'e', 'r', 
  't', 'y', 'u', 'i', 'o', 'p', 'a', 's', 
  'd', 'f', 'g', 'h', 'j', 'k', 'l', 'z',
  'x', 'c', 'v', 'b', 'n', 'm', '.', '!',
  '$', '%', '*', '+', 'Q', 'W', 'E', 'R',
  'T', 'Y', 'U', 'I', 'O', 'P', 'A', 'S',
  'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Z', 
  'X', 'C', 'V', 'B', 'N', 'M', '1', '2', 
  '3', '4', '5', '6', '7', '8', '9', '0',
  '-', '_', 'q', 'w', 'e', 'r', 't', 'y', 
  'u', 'i', 'o', 'p', 'a', 's', 'd', 'f',
  'g', 'h', 'j', 'k', 'l', 'z', 'x', 'c', 
  'v', 'b', 'n', 'm', '.', '!', '$', '%', 
  '*', '+', 'Q', 'W', 'E', 'R', 'T', 'Y',
  'U', 'I', 'O', 'P', 'A', 'S', 'D', 'F',
  'G', 'H', 'J', 'K', 'L', 'Z', 'X', 'C',
  'V', 'B', 'N', 'M', '1', '2', '3', '4',
  '5', '6', '7', '8', '9', '0', '-', '_',
  'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 
  'o', 'p', 'a', 's', 'd', 'f', 'g', 'h',
  'j', 'k', 'l', 'z', 'x', 'c', 'v', 'b',
  'n', 'm', '.', '!', '$', '%', '*', '+', 
  'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
  'O', 'P', 'A', 'S', 'D', 'F', 'G', 'H',
  'J', 'K', 'L', 'Z', 'X', 'C', 'V', 'B',
  'N', 'M', '1', '2', '3', '4', '5', '6',
  '7', '8', '9', '0', 'q', 'w', 'e', 'r',
  't', 'y', 'u', 'i', 'o', 'p', 'a', 's',
  'd', 'f', 'g', 'h', 'j', 'k', 'l', 'z',
  'x', 'c', 'v', 'b', 'n', 'm', '.', '!',
  '$', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U'
  };

char bytes_to_char(byte b) {
  return map_c[b];
}

// pwvault utility takes salt, password and site name and produces a password for the site
// Usage: ./pwvault.exe --password="my voice" --site="www.google.com"\ 
//        --salt="bb59a65c58b793ef" --debug=true --length="16"
int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  string password_and_site = FLAGS_site + "-" + FLAGS_password + "-" + FLAGS_site;
  string salt_bytes;
  if (!hex_to_bytes(FLAGS_salt, &salt_bytes)) {
    printf("Can't convert salt\n");
    return 1;
  }

  int pw_size = 14;
  sscanf(FLAGS_length.c_str(), "%d", &pw_size);
  int out_size = pw_size;
  byte out[out_size];
  memset(out, 0, out_size);
  if (!pbkdf2(password_and_site.c_str(), salt_bytes.size(), (byte*)salt_bytes.data(), iter, out_size, out)) {
    printf("pbkdf2 fails\n");
    return 1;
  }

  if (FLAGS_debug) {
    printf("password: %s\n", FLAGS_password.c_str());
    printf("site: %s\n", FLAGS_site.c_str());
    printf("salt: ");
    printf("password_and_site: %s\n", password_and_site.c_str());
    print_bytes((int)salt_bytes.size(), (byte*)salt_bytes.data());
    printf("out bytes: ");
    print_bytes(out_size, out);
    printf("\n");
  }

  printf("Derived password: ");
  for (int i = 0; i < out_size; i++) {
    printf("%c", bytes_to_char(out[i]));
  }
  printf("\n");

  close_crypto();
  printf("\n");
  return 0;
}
