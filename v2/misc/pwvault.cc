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
DEFINE_string(salt, "59a65c58b793ef", "Salt even number of hex digits");
DEFINE_string(password, "", "Password");
DEFINE_string(site, "www.nyt.com", "site url");
const int iter = 100;

char bytes_to_char(byte b) {
  if (b < 0x20)
    return 'x';
  b &= 0x7f;
  return (char) b;
}

// pwvault utility takes salt, password and site name and produces a password for the site
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

  int out_size = 14;
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
