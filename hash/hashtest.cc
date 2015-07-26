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
// Project: New Cloudproxy Crypto
// File: hashtest.cc

#include "cryptotypes.h"
#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include "util.h"
#include "hash.h"
#include "sha1.h"
#include "sha256.h"
#include "sha3.h"
#include "hmac_sha256.h"
#include "pkcs.h"
#include "pbkdf.h"
#include "ghash.h"
#include <cmath>

uint64_t cycles_per_second = 10;

class HashTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

// Sha 1 tests
const byte* sha1_test1_toHash = (const byte*)"abc";
int sha1_test1_sizetoHash = 3;
uint32_t sha1_test1_answer[5] = {0xA9993E36, 0x4706816A, 0xBA3E2571, 0x7850C26C,
                                 0x9CD0D89D};

const byte* sha1_test2_toHash =
    (const byte*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint32_t sha1_test2_answer[5] = {0x84983E44, 0x1C3BD26E, 0xBAAE4AA1, 0xF95129E5,
                                 0xE54670F1};
int sha1_test2_sizetoHash = 56;

// Sha256 tests
const byte* sha256_test1_toHash = (const byte*)"abc";
int sha256_test1_sizetoHash = 3;
uint32_t sha256_test1_answer[8] = {0xBA7816BF, 0x8F01CFEA, 0x414140DE,
                                   0x5DAE2223, 0xB00361A3, 0x96177A9C,
                                   0xB410FF61, 0xF20015AD};

const byte* sha256_test2_toHash =
    (const byte*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint32_t sha256_test2_answer[8] = {0x248D6A61, 0xD20638B8, 0xE5C02693,
                                   0x0C3E6039, 0xA33CE459, 0x64FF2167,
                                   0xF6ECEDD4, 0x19DB06C1};
int sha256_test2_sizetoHash = 56;

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

void HashTest::SetUp() {}

void HashTest::TearDown() {}

bool SimpleSha1Test1() {
  byte test1_digest[20];
  byte test2_digest[20];
  Sha1 my_hash;

  printf("SimpleSha1Test1\n");
  if (!my_hash.Init()) {
    return false;
  }
  my_hash.AddToHash(sha1_test1_sizetoHash, sha1_test1_toHash);
  my_hash.Final();
  if (!my_hash.GetDigest(20, (byte*)test1_digest)) {
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sha1_test1_sizetoHash, (byte*)sha1_test1_toHash);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(20, (byte*)test1_digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(20, (byte*)sha1_test1_answer);
  printf("\n");
  if (memcmp((byte*)test1_digest, (byte*)sha1_test1_answer, 20) != 0)
    return false;

  if (!my_hash.Init()) {
    return false;
  }
  my_hash.AddToHash(sha1_test2_sizetoHash, sha1_test2_toHash);
  my_hash.Final();
  if (!my_hash.GetDigest(20, (byte*)test2_digest)) {
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sha1_test2_sizetoHash, (byte*)sha1_test2_toHash);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(20, (byte*)test2_digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(20, (byte*)sha1_test2_answer);
  printf("\n");
  if (memcmp((byte*)test2_digest, (byte*)sha1_test2_answer, 20) != 0)
    return false;
  return true;
}

bool SimpleSha3Test() {
  Sha3 my_hash(1024);
  byte digest[128];

  printf("SimpleSha3Test\n");

  memset(digest, 0, 128);
  if (!my_hash.Init()) {
    return false;
  }
  my_hash.AddToHash(sizeof(sha3_input1), (byte*)sha3_input1);
  my_hash.Final();
  if (!my_hash.GetDigest(128, digest)) {
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sizeof(sha3_input1), (byte*)sha3_input1);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(128, digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(128, (byte*)sha3_output1);
  printf("\n");
  if (memcmp((byte*)sha3_output1, digest, 128) != 0) return false;

  memset(digest, 0, 128);
  if (!my_hash.Init()) {
    return false;
  }
  my_hash.AddToHash(sizeof(sha3_input128), (byte*)sha3_input128);
  my_hash.Final();
  if (!my_hash.GetDigest(128, digest)) {
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sizeof(sha3_input128), (byte*)sha3_input128);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(128, digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(128, (byte*)sha3_output128);
  printf("\n");
  if (memcmp((byte*)sha3_output128, digest, 128) != 0) return false;

  memset(digest, 0, 128);
  if (!my_hash.Init()) {
    return false;
  }
  my_hash.AddToHash(sizeof(sha3_input255), (byte*)sha3_input255);
  my_hash.Final();
  if (!my_hash.GetDigest(128, digest)) {
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sizeof(sha3_input255), (byte*)sha3_input255);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(128, digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(128, (byte*)sha3_output255);
  printf("\n");
  if (memcmp((byte*)sha3_output255, digest, 128) != 0) return false;

  return true;
}

bool SimpleSha256Test1() {
  byte test1_digest[32];
  byte test2_digest[32];
  byte test3_digest[32];
  Sha256 my_hash;

  printf("SimpleSha256Test1\n");
  if (!my_hash.Init()) {
    return false;
  }
  printf("SimpleSha256Test1 initialized\n");
  my_hash.AddToHash(sha256_test1_sizetoHash, sha256_test1_toHash);
  my_hash.Final();
  if (!my_hash.GetDigest(32, (byte*)test1_digest)) {
    printf("GetDigest SimpleSha256Test1 failed\n");
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sha256_test1_sizetoHash, (byte*)sha256_test1_toHash);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(32, (byte*)test1_digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(32, (byte*)sha256_test1_answer);
  printf("\n");
  if (memcmp((byte*)test1_digest, (byte*)sha256_test1_answer, 32) != 0) {
    printf("SimpleSha256Test1 comparison failed\n");
    return false;
  }

  if (!my_hash.Init()) {
    return false;
  }
  my_hash.AddToHash(sha256_test2_sizetoHash, sha256_test2_toHash);
  my_hash.Final();
  if (!my_hash.GetDigest(32, (byte*)test2_digest)) {
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sha256_test2_sizetoHash, (byte*)sha256_test2_toHash);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(32, (byte*)test2_digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(32, (byte*)sha256_test2_answer);
  printf("\n");
  if (memcmp((byte*)test2_digest, (byte*)sha256_test2_answer, 32) != 0)
    return false;

  if (!my_hash.Init()) {
    return false;
  }
  my_hash.AddToHash(sha256_test3_sizetoHash, sha256_test3_toHash);
  my_hash.Final();
  if (!my_hash.GetDigest(32, (byte*)test3_digest)) {
    return false;
  }
  printf("\tInput        : ");
  PrintBytes(sha256_test3_sizetoHash, (byte*)sha256_test3_toHash);
  printf("\n");
  printf("\tComputed hash: ");
  PrintBytes(32, (byte*)test3_digest);
  printf("\n");
  printf("\tCorrect hash:  ");
  PrintBytes(32, (byte*)sha256_test3_answer);
  printf("\n");
  if (memcmp((byte*)test3_digest, (byte*)sha256_test3_answer, 32) != 0)
    return false;

  return true;
}

bool pkcsTest() {
  byte in[64];
  byte out[256];
  int new_out_size = 256;
  byte new_out[256];

  memset(in, 0xbb, 64);
  if (!PkcsEncode("sha-256", in, 256, out)) {
    printf("PkcsEncode failed\n");
    return false;
  }
  printf("encoded hash: ");
  PrintBytes(256, out);
  printf("\n");
  if (!PkcsVerify("sha-256", in, 256, out)) {
    printf("PkcsVerify failed\n");
    return false;
  }
  memset(out, 0, 256);
  memset(new_out, 0, 256);
  if (!PkcsEmbed(64, in, 256, out)) {
    printf("PkcsEmbed failed\n");
    return false;
  }
  printf("embedded message: ");
  PrintBytes(256, out);
  printf("\n");
  if (!PkcsExtract(256, out, &new_out_size, new_out)) {
    printf("PkcsExtract failed\n");
    return false;
  }
  printf("retrieved message: ");
  PrintBytes(new_out_size, new_out);
  printf("\n");
  if (new_out_size != 64 || memcmp(new_out, in, new_out_size) != 0)
    return false;
  return true;
}

#define HASH_DATA_SIZE 50000
byte hash_data[HASH_DATA_SIZE];

void InitHashData() {
  int i;

  for (i = 0; i < HASH_DATA_SIZE; i++) {
    hash_data[i] = (byte)i;
  }
}

bool sha1_benchmark_tests(int num_tests) {
  printf("\nSHA1_TIME_TESTS\n");
  byte out[64];
  int num_tests_executed = 0;
  Sha1 my_hash;

  uint64_t cycles_start_test;
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!my_hash.Init()) {
      return false;
    }
    my_hash.AddToHash(HASH_DATA_SIZE, hash_data);
    my_hash.Final();
    if (!my_hash.GetDigest(20, (byte*)out)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("sha1_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per byte %le\n",
         ((double)cycles_diff) / ((double)HASH_DATA_SIZE *
                                  (num_tests_executed * cycles_per_second)));
  printf("END SHA1_TIME_TESTS\n\n");
  return true;
}

bool sha256_benchmark_tests(int num_tests) {
  printf("\nSHA256_TIME_TESTS\n");
  byte out[64];
  int num_tests_executed = 0;
  Sha256 my_hash;

  uint64_t cycles_start_test;
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!my_hash.Init()) {
      return false;
    }
    my_hash.AddToHash(HASH_DATA_SIZE, hash_data);
    my_hash.Final();
    if (!my_hash.GetDigest(32, (byte*)out)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("sha256_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per byte %le\n",
         ((double)cycles_diff) / ((double)HASH_DATA_SIZE *
                                  (num_tests_executed * cycles_per_second)));
  printf("END SHA256_TIME_TESTS\n\n");
  return true;
}

bool sha3_benchmark_tests(int num_tests) {
  printf("\nSHA3_TIME_TESTS\n");
  byte out[256];
  int num_tests_executed = 0;
  Sha3 my_hash(1024);

  uint64_t cycles_start_test;
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!my_hash.Init()) {
      return false;
    }
    my_hash.AddToHash(HASH_DATA_SIZE, hash_data);
    my_hash.Final();
    if (!my_hash.GetDigest(128, (byte*)out)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("sha3_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per byte %le\n",
         ((double)cycles_diff) / ((double)HASH_DATA_SIZE *
                                  (num_tests_executed * cycles_per_second)));
  printf("END SHA3_TIME_TESTS\n\n");
  return true;
}

bool pbkdfTest() {
  byte out[256];
  int salt_size = 24;
  byte salt[256];

  memset(out, 0, 256);
  memset(salt, 0x09, salt_size);

  if (!pbkdf2("My voice is my password, hear me speak", salt_size, salt, 10, 72,
              out)) {
    printf("pbkdf2 failed\n");
    return false;
  }
  printf("password derived key: ");
  PrintBytes(80, out);
  printf("\n");
  return true;
}

int hmacsha256_test1_keysize = 20;
byte hmacsha256_test1_key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                               0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                               0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
byte* hmacsha256_test1_input = (byte*)"Hi There";
int hmacsha256_test1_size_input = 8;
byte hmacsha256_test1_mac[32] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
    0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
    0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

int hmacsha256_test2_keysize = 4;
byte* hmacsha256_test2_key = (byte*)"Jefe";
byte* hmacsha256_test2_input = (byte*)"what do ya want for nothing?";
int hmacsha256_test2_size_input = 28;
byte hmacsha256_test2_mac[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
    0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
    0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};

int hmacsha256_test3_keysize = 20;
byte hmacsha256_test3_key[20] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
int hmacsha256_test3_size_input = 50;
byte hmacsha256_test3_input[50] = {
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd};
byte hmacsha256_test3_mac[32] = {
    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8,
    0xeb, 0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8,
    0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe};

bool SimpleHmacSha256Test1() {
  byte test1_hmac[32];
  byte test2_hmac[32];
  byte test3_hmac[32];
  HmacSha256 my_mac;
  HmacSha256 my_mac3;
  bool fRet = true;

  printf("SimpleHmacSha256Test1\n");

  if (!my_mac.Init(hmacsha256_test1_keysize, hmacsha256_test1_key)) {
    printf("key init failed\n");
    return false;
  }
  my_mac.AddToInnerHash(hmacsha256_test1_size_input, hmacsha256_test1_input);
  my_mac.Final();
  if (!my_mac.GetHmac(32, (byte*)test1_hmac)) {
    printf("gethmac failed\n");
    return false;
  }
  printf("\tMac key     : ");
  PrintBytes(hmacsha256_test1_keysize, (byte*)hmacsha256_test1_key);
  printf("\n");
  printf("\tMac input   : ");
  PrintBytes(hmacsha256_test1_size_input, hmacsha256_test1_input);
  printf("\n");
  printf("\tComputed mac: ");
  PrintBytes(32, (byte*)test1_hmac);
  printf("\n");
  printf("\tCorrect mac : ");
  PrintBytes(32, (byte*)hmacsha256_test1_mac);
  printf("\n");
  if (memcmp((byte*)test1_hmac, (byte*)hmacsha256_test1_mac, 32) != 0) {
    printf("SimpleHmacSha256Test1 comparison failed\n");
    fRet = false;
  }
  printf("\n");

  printf("SimpleHmacSha256Test2\n");
  if (!my_mac.Init(hmacsha256_test2_keysize, hmacsha256_test2_key)) {
    printf("key init failed\n");
    return false;
  }
  my_mac.AddToInnerHash(hmacsha256_test2_size_input, hmacsha256_test2_input);
  my_mac.Final();
  if (!my_mac.GetHmac(32, (byte*)test2_hmac)) {
    printf("gethmac failed\n");
    return false;
  }
  printf("\tMac key     : ");
  PrintBytes(hmacsha256_test2_keysize, (byte*)hmacsha256_test2_key);
  printf("\n");
  printf("\tMac input   : ");
  PrintBytes(hmacsha256_test2_size_input, hmacsha256_test2_input);
  printf("\n");
  printf("\tComputed mac: ");
  PrintBytes(32, (byte*)test2_hmac);
  printf("\n");
  printf("\tCorrect mac : ");
  PrintBytes(32, (byte*)hmacsha256_test2_mac);
  printf("\n");
  if (memcmp((byte*)test2_hmac, (byte*)hmacsha256_test2_mac, 32) != 0) {
    printf("SimpleHmacSha256Test1 comparison failed\n");
    fRet = false;
  }
  printf("\n");

  printf("SimpleHmacSha256Test3\n");
  if (!my_mac3.Init(hmacsha256_test3_keysize, hmacsha256_test3_key)) {
    printf("key init failed\n");
    return false;
  }
  my_mac3.AddToInnerHash(hmacsha256_test3_size_input, hmacsha256_test3_input);
  my_mac3.Final();
  if (!my_mac3.GetHmac(32, (byte*)test3_hmac)) {
    printf("gethmac failed\n");
    return false;
  }
  printf("\tMac key     : ");
  PrintBytes(hmacsha256_test3_keysize, (byte*)hmacsha256_test3_key);
  printf("\n");
  printf("\tMac input   : ");
  PrintBytes(hmacsha256_test3_size_input, hmacsha256_test3_input);
  printf("\n");
  printf("\tComputed mac: ");
  PrintBytes(32, (byte*)test3_hmac);
  printf("\n");
  printf("\tCorrect mac : ");
  PrintBytes(32, (byte*)hmacsha256_test3_mac);
  printf("\n");
  if (memcmp((byte*)test3_hmac, (byte*)hmacsha256_test3_mac, 32) != 0) {
    printf("SimpleHmacSha256Test1 comparison failed\n");
    fRet = false;
  }

  return fRet;
}

bool RunTestSuite() { return true; }

TEST(FirstSha1Case, FirstSha1Test) {
  EXPECT_TRUE(SimpleSha1Test1());
  EXPECT_TRUE(sha1_benchmark_tests(3000));
}
TEST(FirstSha256Case, FirstSha256Test) {
  EXPECT_TRUE(SimpleSha256Test1());
  EXPECT_TRUE(sha256_benchmark_tests(3000));
}
TEST(FirstSha3Case, FirstSha3Test) {
  EXPECT_TRUE(SimpleSha3Test());
  EXPECT_TRUE(sha3_benchmark_tests(3000));
}
TEST(FirstHmacSha256Case, FirstHmacSha256Test) {
  EXPECT_TRUE(SimpleHmacSha256Test1());
}
TEST(FirstPkcsCase, FirstPkcsTest) { EXPECT_TRUE(pkcsTest()); }
TEST(FirstKdfCase, FirstKdfTest) { EXPECT_TRUE(pbkdfTest()); }

uint64_t test_min_poly[3] = {0x83, 0x0, 0x1};
uint64_t test_poly_a1[2] = {0x1, 0x0};
uint64_t test_poly_b[2] = {0x7, 0x3};
uint64_t test_poly_a2[2] = {0x3, 0x0};
uint64_t test_poly_a3[3] = {0x2, 0x0, 0x1};

TEST(Shift, ShiftTest) {
  uint64_t a[2] = {0xffffffULL, 0xffff000000000000ULL};
  uint64_t c[4];

  for (int i = 0; i < 128; i++) {
    Shift(2, a, i, 4, c) ;
    printf("%016llx%016llx << %03d = %016llx%016llx%016llx%016llx\n",
           a[1], a[0], i, c[3], c[2], c[1], c[0]);
  }
}

TEST(MultPoly, MultPolyTest1) {
  uint64_t c[4];
  uint64_t d[4];
  memset(d, 0, 4 * sizeof(uint64_t));
  uint64_t d_expected[4] = {0x09, 0x05, 0x0, 0x0};

  EXPECT_TRUE(MultPoly(2, test_poly_b, 2,  test_poly_a1, 4, c));
  EXPECT_TRUE(memcmp(test_poly_b, c, 16) == 0);
  EXPECT_TRUE(MultPoly(2, test_poly_b, 2, test_poly_a2, 4, d));
  EXPECT_TRUE(memcmp(d_expected, d, 32) == 0);
}

TEST(MultPoly, MultPolyTest2) {
  uint64_t c[4] = {0x9999999999999999ULL, 0x9999999999999999ULL};
  uint64_t d[4];
  memset(d, 0, 4 * sizeof(uint64_t));

  EXPECT_TRUE(MultPoly(2, c, 2, c, 4, d));
  printf("%016llx%016llx**2 = %016llx%016llx%016llx%016llx\n",
         c[1],c[0], d[3],d[2], d[1],d[0]);
}

TEST(Reduce, ReduceTest) {
  uint64_t expected[4] = {0x81, 0x0, 0x0, 0x0};

  Reduce(4, test_poly_a3, 3, test_min_poly);
  EXPECT_TRUE(memcmp(expected, test_poly_a3, 32) == 0);
}

TEST(MultAndReduce, MultAndReduceTest1) {
  uint64_t A[3] = {0x0087ULL, 0x0ULL, 0x1ULL};
  uint64_t B[2] = {0x07ULL, 0ULL };
  uint64_t C[4];
  uint64_t p[3] = {0x87ULL, 0ULL, 1ULL};

  EXPECT_TRUE(MultAndReduce(3, A, 1, B, 3, p, 4, C));
  printf("%016llx%016llx%016llx x %016llx\n",
         A[2], A[1], A[0], B[0]);
  printf("%016llx%016llx%016llx%016llx\n",
         C[3], C[2], C[1], C[0]);
  EXPECT_TRUE(C[3] == 0ULL && C[2] == 0ULL &&
              C[1] == 0ULL && C[0] == 0ULL);

  A[0] = 0x86ULL;
  A[1] = 0ULL;
  A[2] = 1ULL;
  B[0] = 1ULL;
  C[0] = 0ULL; C[1] = 0ULL; C[2] = 0ULL; C[3] = 0ULL;
  EXPECT_TRUE(MultAndReduce(3, A, 1, B, 3, p, 4, C));
#if 0
  printf("MultAndReduce %016llx%016llx%016llx x %016llx\n",
         A[2], A[1], A[0], B[0]);
  printf("%016llx%016llx%016llx%016llx\n",
         C[3], C[2], C[1], C[0]);
#endif
  EXPECT_TRUE(C[3] == 0ULL && C[2] == 0ULL &&
              C[1] == 0ULL && C[0] == 1ULL);

  A[0] = 0x0ULL;
  A[1] = 0x1ULL;
  B[0] = 0ULL;
  B[1] = 1ULL;
  C[0] = 0ULL; C[1] = 0ULL; C[2] = 0ULL; C[3] = 0ULL;
  EXPECT_TRUE(MultAndReduce(2, A, 2, B, 3, p, 4, C));
#if 0
  printf("%016llx%016llx x %016llx%016llx\n",
         A[1], A[0], B[1], B[0]);
  printf("%016llx%016llx%016llx%016llx\n",
         C[3], C[2], C[1], C[0]);
#endif
  EXPECT_TRUE(C[3] == 0ULL && C[2] == 0ULL &&
              C[1] == 0ULL && C[0] == 0x87ULL);

  A[0] = 0x0ULL;
  A[1] = 0x2ULL;
  B[0] = 0ULL;
  B[1] = 1ULL;
  C[0] = 0ULL; C[1] = 0ULL; C[2] = 0ULL; C[3] = 0ULL;
  EXPECT_TRUE(MultAndReduce(2, A, 2, B, 3, p, 4, C));
#if 0
  printf("%016llx%016llx x %016llx%016llx\n",
         A[1], A[0], B[1], B[0]);
  printf("%016llx%016llx%016llx%016llx\n",
         C[3], C[2], C[1], C[0]);
#endif
  EXPECT_TRUE(C[3] == 0ULL && C[2] == 0ULL &&
              C[1] == 0ULL && C[0] == 0x10eULL);
}

TEST(MultAndReduce, MultAndReduceTest2) {
  uint64_t c[4] = {0x9999999999999999ULL, 0x9999999999999999ULL};
  uint64_t p[3] = {0x3ULL, 0ULL, 0x1ULL};
  uint64_t d[4];
  memset(d, 0, 4 * sizeof(uint64_t));

  EXPECT_TRUE(MultAndReduce(2, c, 2, c, 3, p, 4, d));
  printf("%016llx%016llx**2 (mod %016llx%016llx%016llx) = %016llx%016llx%016llx%016llx\n",
         c[1],c[0], p[2], p[1],p[0], d[3],d[2], d[1],d[0]);
}


uint64_t A[8] = {
  0xD609B1F056637A0DULL,
  0x46DF998D88E5222AULL,
  0xB2C2846512153524ULL,
  0xC0895E8108000F10ULL,
  0x1112131415161718ULL,
  0x191A1B1C1D1E1F20ULL,
  0x2122232425262728ULL,
  0x292A2B2C2D2E2F30ULL,
};

uint64_t X[8] = {
  0xEF7998E399C01CA4ULL,
  0x6B0BE68D67C6EE03ULL,
  0xCCCB028441197B22ULL,
  0x5AABADF6D7806EC0ULL,
  0xD7FDB0687192D293ULL,
  0xFE072BFE2811A68AULL,
  0xFB356E435DBB4CD0ULL,
  0xA47252D1A7E09B49ULL,
};

TEST(Ghash, GhashTest0) {
  byte HH[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  byte      AA[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
}

TEST(Ghash, GhashTest1) {
  byte HH[16] = {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  byte      AA[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
}

TEST(Ghash, GhashTest2) {
  byte HH[16] = {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  byte      AA[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
}

TEST(Ghash, GhashTest3) {
  byte HH[16] = {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  byte      AA[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
}

TEST(Ghash, GhashTest4) {
  byte HH[16] = {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  byte      AA[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
}

TEST(Ghash, GhashTest5) {
  byte HH[16] = {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  byte AA[16] = {0x8, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x4, 0x4};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
}

TEST(Ghash, GhashTest6) {
  byte HH[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
  byte      AA[16] = {0x11, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x00, 0x00};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
}

TEST(Ghash, GhashTest7) {
  byte HH[16] = {
    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e
};
  byte      AA[16] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
};
byte X1[16] = {
    0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88,
    0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53, 0xde, 0xb7
};

  Ghash hash;
  hash.Init(HH);
  hash.AddCHash(16, AA);
  printf("X1        : "); PrintBytes(16, X1); printf("\n");
}


TEST(Ghash, GhashTestx) {
/*
  byte AA[64];
  byte XX[64];

  ReverseCpy(8, (byte*)&A[0], &AA[0]);
  ReverseCpy(8, (byte*)&A[1], &AA[8]);
  ReverseCpy(8, (byte*)&A[2], &AA[16]);
  ReverseCpy(8, (byte*)&A[3], &AA[24]);
  ReverseCpy(8, (byte*)&A[4], &AA[32]);
  ReverseCpy(8, (byte*)&A[5], &AA[40]);
  ReverseCpy(8, (byte*)&A[6], &AA[48]);
  ReverseCpy(8, (byte*)&A[7], &AA[56]);

  ReverseCpy(8, (byte*)&X[0], &XX[8]);
  ReverseCpy(8, (byte*)&X[1], &XX[0]);
  ReverseCpy(8, (byte*)&X[2], &XX[24]);
  ReverseCpy(8, (byte*)&X[3], &XX[16]);
  ReverseCpy(8, (byte*)&X[4], &XX[40]);
  ReverseCpy(8, (byte*)&X[5], &XX[32]);
  ReverseCpy(8, (byte*)&X[6], &XX[56]);
  ReverseCpy(8, (byte*)&X[7], &XX[48]);

  uint64_t  H[2] = {
    0xA850253FCF43120E,
    0x73A23D80121DE2D5
  };
  uint64_t HH[2];
  ReverseCpy(8, (byte*)&H[0], (byte*)&HH[1]);
  ReverseCpy(8, (byte*)&H[1], (byte*)&HH[0]);

  Ghash hash;
  hash.Init((uint64_t*)HH);
  hash.AddAHash(64, (byte*)AA);
 */
}


DEFINE_string(log_file, "hashtest.log", "hashtest log file name");

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
  if (!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  cycles_per_second = CalibrateRdtsc();
  printf("Cycles per second on this machine: %lld\n\n", cycles_per_second);
  InitHashData();
  int result = RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}
