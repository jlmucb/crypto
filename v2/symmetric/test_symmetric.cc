// Copyright 2020 John Manferdelli, All Rights Reserved.
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
#include "crypto_names.h"
#include "symmetric_cipher.h"
#include "aes.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");

byte aes128_test1_plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
byte aes128_test1_key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
byte aes128_test1_cipher[] = {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

byte aes256_test1_plain[] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
byte aes256_test1_key[] = {
 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f 
};
byte aes256_test1_cipher[] = {
  0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
  0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
};
byte twofish_test1_key[] = {
    0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
    0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
};
byte twofish_test1_plain[] = {
  0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
  0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
};
byte twofish_test1_cipher[] = {
  0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
  0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3
};
byte rc4_test1_key[5] = {
  0x01, 0x02, 0x03, 0x04, 0x05
};
byte rc4_test1_plain[16] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
byte rc4_test1_cipher[16] = {
  0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
  0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
};
byte tea_test1_plain[8] = {
  0, 0, 0, 0, 0, 0, 0, 0
};
byte tea_test1_cipher[8] = {
  0x0a, 0x3a, 0xea, 0x41, 0x40, 0xa9, 0xba, 0x94
};
uint64_t simon_test1_key[2] = {
    0x0706050403020100, 0x0f0e0d0c0b0a0908,
};
uint64_t simon_test1_plain[2] = {
    0x6373656420737265, 0x6c6c657661727420,
};
uint64_t simon_test1_cipher[2] = {
    0x49681b1e1e54fe3f, 0x65aa832af84e0bbc,
};

bool test_aes_test1() {
  aes aes_obj;
  byte test_cipher_out[16];
  byte test_plain_out[16];

   if(!aes_obj.init(128, aes128_test1_key, aes::BOTH))
    return false;
  aes_obj.encrypt_block(aes128_test1_plain, test_cipher_out);
  aes_obj.decrypt_block(test_cipher_out, test_plain_out);
  if (FLAGS_print_all) {
    printf("  Key            : ");
    print_bytes(16, aes128_test1_key);
    printf("  Correct plain  : ");
    print_bytes(16, aes128_test1_plain);
    printf("  Correct cipher : ");
    print_bytes(16, aes128_test1_cipher);
    printf("  Computed cipher: ");
    print_bytes(16, test_cipher_out);
    printf("  Computed plain : ");
    print_bytes(16, test_plain_out);
  }
  if (memcmp(aes128_test1_cipher, test_cipher_out, 16) != 0) return false;
  if (memcmp(aes128_test1_plain, test_plain_out, 16) != 0) return false;
  return true;
}
bool test_aesni() {
  return true;
}

TEST (aes, test_aes_test1) {
  EXPECT_TRUE(test_aes_test1());
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  int result = RUN_ALL_TESTS();
  printf("%d tests\n", result);
  printf("Tests complete\n");
  return 0;
}
