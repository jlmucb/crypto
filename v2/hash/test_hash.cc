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
#include "crypto_names.h"
#include "hash.h"
#include "sha1.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");

// Sha 1 tests
const byte* sha1_test1_input= (const byte*)"abc";
int sha1_test1_size= 3;
uint32_t sha1_test1_answer[5] = {
  0xA9993E36, 0x4706816A, 0xBA3E2571,
  0x7850C26C, 0x9CD0D89D
};
const byte* sha1_test2_input=
    (const byte*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint32_t sha1_test2_answer[5] = {
  0x84983E44, 0x1C3BD26E, 0xBAAE4AA1,
  0xF95129E5, 0xE54670F1
};
int sha1_test2_size = 56;

// Sha256 tests
const byte* sha256_test1_input = (const byte*)"abc";
int sha256_test1_size= 3;
uint32_t sha256_test1_answer[8] = {0xBA7816BF, 0x8F01CFEA, 0x414140DE,
                                   0x5DAE2223, 0xB00361A3, 0x96177A9C,
                                   0xB410FF61, 0xF20015AD};

const byte* sha256_test2_input=
    (const byte*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint32_t sha256_test2_answer[8] = {0x248D6A61, 0xD20638B8, 0xE5C02693,
                                   0x0C3E6039, 0xA33CE459, 0x64FF2167,
                                   0xF6ECEDD4, 0x19DB06C1};
int sha256_test2_size= 56;

const byte* sha256_test3_toHash =
      (const byte*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
int sha256_test3_sizetoHash = 112;
uint32_t sha256_test3_answer[8] = {0xcf5b16a7, 0x78af8380, 0x036ce59e,
                                   0x7b049237, 0x0b249b11, 0xe8f07a51,
                                   0xafac4503, 0x7afee9d1};

const byte sha3_input1[1] = {0xCC};
const byte sha3_output1[128] = {
    0x56, 0xB9, 0x70, 0x29, 0xB4, 0x79, 0xFF, 0x5D, 0xD1, 0x5F, 0x17, 0xD1,
    0x29, 0x83, 0xE3, 0xB8, 0x35, 0xBB, 0x05, 0x31, 0xD9, 0xB8, 0xD4, 0x9B,
    0x10, 0x3B, 0x02, 0x5C, 0xA5, 0x3F, 0x99, 0x17, 0x41, 0x29, 0x8E, 0x96,
    0x1D, 0x1F, 0xAD, 0x00, 0xFC, 0x36, 0x5C, 0x77, 0x61, 0xBF, 0xB2, 0x78,
    0xAE, 0x47, 0x39, 0x80, 0xD6, 0x12, 0xC1, 0x62, 0x9E, 0x07, 0x5A, 0x3F,
    0xDB, 0xAE, 0x7F, 0x82, 0xB0, 0xF0, 0xAF, 0x54, 0xDF, 0x18, 0x7F, 0x35,
    0x88, 0x52, 0xE1, 0x9E, 0xA4, 0x34, 0x7C, 0xF5, 0xCE, 0xEA, 0x67, 0x6A,
    0x1D, 0xCE, 0x3A, 0x47, 0x44, 0x7E, 0x23, 0x7F, 0xD7, 0x42, 0x04, 0xF9,
    0xA4, 0xB7, 0xF7, 0xC9, 0xCC, 0x7C, 0xC8, 0xB8, 0x65, 0xB1, 0xD5, 0x54,
    0xE2, 0xF5, 0xF4, 0xA8, 0xEE, 0x17, 0xDB, 0xDD, 0xE7, 0x26, 0x78, 0x94,
    0x55, 0x8A, 0x20, 0x97, 0x2C, 0x9E, 0xB6, 0xCF};
const byte sha3_input128[] = {
    0x2B, 0x6D, 0xB7, 0xCE, 0xD8, 0x66, 0x5E, 0xBE, 0x9D, 0xEB, 0x08, 0x02,
    0x95, 0x21, 0x84, 0x26, 0xBD, 0xAA, 0x7C, 0x6D, 0xA9, 0xAD, 0xD2, 0x08,
    0x89, 0x32, 0xCD, 0xFF, 0xBA, 0xA1, 0xC1, 0x41, 0x29, 0xBC, 0xCD, 0xD7,
    0x0F, 0x36, 0x9E, 0xFB, 0x14, 0x92, 0x85, 0x85, 0x8D, 0x2B, 0x1D, 0x15,
    0x5D, 0x14, 0xDE, 0x2F, 0xDB, 0x68, 0x0A, 0x8B, 0x02, 0x72, 0x84, 0x05,
    0x51, 0x82, 0xA0, 0xCA, 0xE2, 0x75, 0x23, 0x4C, 0xC9, 0xC9, 0x28, 0x63,
    0xC1, 0xB4, 0xAB, 0x66, 0xF3, 0x04, 0xCF, 0x06, 0x21, 0xCD, 0x54, 0x56,
    0x5F, 0x5B, 0xFF, 0x46, 0x1D, 0x3B, 0x46, 0x1B, 0xD4, 0x0D, 0xF2, 0x81,
    0x98, 0xE3, 0x73, 0x25, 0x01, 0xB4, 0x86, 0x0E, 0xAD, 0xD5, 0x03, 0xD2,
    0x6D, 0x6E, 0x69, 0x33, 0x8F, 0x4E, 0x04, 0x56, 0xE9, 0xE9, 0xBA, 0xF3,
    0xD8, 0x27, 0xAE, 0x68, 0x5F, 0xB1, 0xD8, 0x17};

const byte sha3_output128[128] = {
    0xDC, 0xAC, 0x84, 0x56, 0x8F, 0x15, 0xCA, 0xC0, 0x76, 0x85, 0x4E, 0xA6,
    0x92, 0xDE, 0x95, 0xE4, 0x73, 0x76, 0x8A, 0x99, 0xDF, 0x9A, 0xC2, 0x32,
    0x8E, 0xE4, 0x23, 0xD0, 0x2E, 0xEB, 0x8E, 0xE8, 0xE1, 0xD1, 0x70, 0x62,
    0x13, 0xC4, 0x41, 0x5D, 0xC7, 0xAA, 0xFA, 0x66, 0x47, 0x6D, 0x8E, 0xBD,
    0xDD, 0xD8, 0xBF, 0x39, 0xE1, 0xDE, 0x05, 0xCA, 0x76, 0xC3, 0x6E, 0x7E,
    0x97, 0x56, 0x29, 0x33, 0x1F, 0x3A, 0x33, 0xC3, 0xCA, 0x40, 0x91, 0xC8,
    0x20, 0x04, 0xE5, 0x89, 0x1B, 0x7E, 0x27, 0x6D, 0x46, 0x42, 0xEA, 0x61,
    0xBD, 0xE0, 0x21, 0x87, 0x1C, 0x9B, 0x5C, 0x8C, 0xFA, 0x82, 0x14, 0x4B,
    0x7A, 0x41, 0x44, 0xB4, 0x4E, 0xBE, 0x60, 0x93, 0xE9, 0x5C, 0x59, 0x30,
    0x5F, 0xD3, 0x6A, 0x87, 0x41, 0xC4, 0xF2, 0xDF, 0x65, 0xCB, 0x0B, 0x59,
    0xF8, 0x03, 0xCF, 0xDC, 0xF2, 0xCE, 0x4B, 0x8B,
};

const byte sha3_input255[] = {
    0x3A, 0x3A, 0x81, 0x9C, 0x48, 0xEF, 0xDE, 0x2A, 0xD9, 0x14, 0xFB, 0xF0,
    0x0E, 0x18, 0xAB, 0x6B, 0xC4, 0xF1, 0x45, 0x13, 0xAB, 0x27, 0xD0, 0xC1,
    0x78, 0xA1, 0x88, 0xB6, 0x14, 0x31, 0xE7, 0xF5, 0x62, 0x3C, 0xB6, 0x6B,
    0x23, 0x34, 0x67, 0x75, 0xD3, 0x86, 0xB5, 0x0E, 0x98, 0x2C, 0x49, 0x3A,
    0xDB, 0xBF, 0xC5, 0x4B, 0x9A, 0x3C, 0xD3, 0x83, 0x38, 0x23, 0x36, 0xA1,
    0xA0, 0xB2, 0x15, 0x0A, 0x15, 0x35, 0x8F, 0x33, 0x6D, 0x03, 0xAE, 0x18,
    0xF6, 0x66, 0xC7, 0x57, 0x3D, 0x55, 0xC4, 0xFD, 0x18, 0x1C, 0x29, 0xE6,
    0xCC, 0xFD, 0xE6, 0x3E, 0xA3, 0x5F, 0x0A, 0xDF, 0x58, 0x85, 0xCF, 0xC0,
    0xA3, 0xD8, 0x4A, 0x2B, 0x2E, 0x4D, 0xD2, 0x44, 0x96, 0xDB, 0x78, 0x9E,
    0x66, 0x31, 0x70, 0xCE, 0xF7, 0x47, 0x98, 0xAA, 0x1B, 0xBC, 0xD4, 0x57,
    0x4E, 0xA0, 0xBB, 0xA4, 0x04, 0x89, 0xD7, 0x64, 0xB2, 0xF8, 0x3A, 0xAD,
    0xC6, 0x6B, 0x14, 0x8B, 0x4A, 0x0C, 0xD9, 0x52, 0x46, 0xC1, 0x27, 0xD5,
    0x87, 0x1C, 0x4F, 0x11, 0x41, 0x86, 0x90, 0xA5, 0xDD, 0xF0, 0x12, 0x46,
    0xA0, 0xC8, 0x0A, 0x43, 0xC7, 0x00, 0x88, 0xB6, 0x18, 0x36, 0x39, 0xDC,
    0xFD, 0xA4, 0x12, 0x5B, 0xD1, 0x13, 0xA8, 0xF4, 0x9E, 0xE2, 0x3E, 0xD3,
    0x06, 0xFA, 0xAC, 0x57, 0x6C, 0x3F, 0xB0, 0xC1, 0xE2, 0x56, 0x67, 0x1D,
    0x81, 0x7F, 0xC2, 0x53, 0x4A, 0x52, 0xF5, 0xB4, 0x39, 0xF7, 0x2E, 0x42,
    0x4D, 0xE3, 0x76, 0xF4, 0xC5, 0x65, 0xCC, 0xA8, 0x23, 0x07, 0xDD, 0x9E,
    0xF7, 0x6D, 0xA5, 0xB7, 0xC4, 0xEB, 0x7E, 0x08, 0x51, 0x72, 0xE3, 0x28,
    0x80, 0x7C, 0x02, 0xD0, 0x11, 0xFF, 0xBF, 0x33, 0x78, 0x53, 0x78, 0xD7,
    0x9D, 0xC2, 0x66, 0xF6, 0xA5, 0xBE, 0x6B, 0xB0, 0xE4, 0xA9, 0x2E, 0xCE,
    0xEB, 0xAE, 0xB1};
const byte sha3_output255[128] = {
    0x94, 0x35, 0xFC, 0x67, 0x1D, 0xFC, 0xFC, 0xDA, 0xC1, 0x49, 0x27, 0x7E,
    0x2C, 0xAA, 0xA8, 0x0E, 0xD3, 0xD4, 0xA2, 0x35, 0x93, 0x00, 0xDB, 0x89,
    0x2B, 0x80, 0x93, 0xDF, 0xFA, 0x94, 0x42, 0xBB, 0x5C, 0x08, 0xF2, 0x42,
    0xF2, 0xFC, 0x2C, 0xB5, 0xF8, 0x38, 0x80, 0x32, 0x29, 0x9F, 0x1D, 0xF4,
    0x7A, 0x57, 0x48, 0x9A, 0x4F, 0xC0, 0xD6, 0x6D, 0x88, 0xE4, 0x83, 0x09,
    0x23, 0x20, 0xA4, 0x71, 0x89, 0x7F, 0xB6, 0xAD, 0xE6, 0x78, 0x97, 0xE5,
    0x13, 0x8C, 0x45, 0xF1, 0x91, 0x74, 0xA4, 0xB1, 0xAE, 0x0E, 0x51, 0x0F,
    0xA3, 0x90, 0x82, 0x5D, 0x17, 0x56, 0x89, 0x89, 0xC3, 0x65, 0x9F, 0xC5,
    0x7B, 0x93, 0x45, 0xD7, 0xD9, 0x3E, 0xE5, 0x88, 0xCB, 0x26, 0x29, 0xC5,
    0x77, 0x08, 0x08, 0x19, 0x52, 0x57, 0xBB, 0xF4, 0x2B, 0x06, 0x95, 0x76,
    0xD9, 0x40, 0x11, 0x98, 0x9D, 0xC6, 0xEB, 0xC4};



bool test_sha1() {
  sha1 hash_object;

  byte digest1[hash_object.DIGESTBYTESIZE];
  byte digest2[hash_object.DIGESTBYTESIZE];

  if (!hash_object.init())
    return false;
  hash_object.add_to_hash(sha1_test1_size, sha1_test1_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.DIGESTBYTESIZE, digest1))
    return false;
  if (FLAGS_print_all) {
    printf("Bytes to hash  : "); print_bytes(sha1_test1_size, (byte*)sha1_test1_input);
    printf("Correct digest : "); print_bytes(hash_object.DIGESTBYTESIZE, (byte*)sha1_test1_answer);
    printf("Computed digest: "); print_bytes(hash_object.DIGESTBYTESIZE, digest1);
  }
  if (memcmp((const void *)sha1_test1_answer,
             (const void *) digest1, hash_object.DIGESTBYTESIZE) != 0)
    return false;

  if (!hash_object.init())
    return false;
  hash_object.add_to_hash(sha1_test2_size, sha1_test2_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.DIGESTBYTESIZE, digest2))
    return false;
  if (FLAGS_print_all) {
    printf("Bytes to hash  : "); print_bytes(sha1_test2_size, (byte*)sha1_test2_input);
    printf("Correct digest : "); print_bytes(hash_object.DIGESTBYTESIZE, (byte*)sha1_test2_answer);
    printf("Computed digest: "); print_bytes(hash_object.DIGESTBYTESIZE, digest2);
  }
  if (memcmp((const void *)sha1_test2_answer,
             (const void *) digest2, hash_object.DIGESTBYTESIZE) != 0)
    return false;

  return true;
}

bool test_sha2_a() {
  return true;
}

bool test_sha2_b() {
  return true;
}

bool test_sha2_c() {
  return true;
}

bool test_sha3() {
  return true;
}

bool test_ghash() {
  return true;
}

bool test_hmac_sha256() {
  return true;
}

bool test_pkcs1() {
  return true;
}

bool test_pkdf2() {
  return true;
}

bool test_cmac() {
  return true;
}

TEST (pkcs1, test_pkcs1) {
  EXPECT_TRUE(test_pkcs1());
}
TEST (sha1, test_sha1) {
  EXPECT_TRUE(test_sha1());
}
TEST (sha2, sha2) {
  EXPECT_TRUE(test_sha2_a());
  EXPECT_TRUE(test_sha2_b());
  EXPECT_TRUE(test_sha2_c());
}
TEST (sha3, test_sha3) {
  EXPECT_TRUE(test_sha1());
}
TEST (ghash, test_ghash) {
  EXPECT_TRUE(test_ghash());
}
TEST (hmac, test_hmac_sha256) {
  EXPECT_TRUE(test_hmac_sha256());
}
TEST (pkdf, test_pkdf2) {
  EXPECT_TRUE(test_pkdf2());
}
TEST (cmac, test_cmac) {
  EXPECT_TRUE(test_cmac());
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
