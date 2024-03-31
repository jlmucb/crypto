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
#include "sha256.h"
#include "sha3.h"
#include "hmac_sha256.h"
#include "pkcs.h"
#include "pbkdf.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");

// sha 1 tests
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

// sha256 tests
const byte* sha256_test1_input = (const byte*)"abc";
int sha256_test1_size= 3;
uint32_t sha256_test1_answer[8] = {
  0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223,
  0xB00361A3, 0x96177A9C, 0xB410FF61, 0xF20015AD
};
const byte* sha256_test2_input=
    (const byte*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint32_t sha256_test2_answer[8] = {
  0x248D6A61, 0xD20638B8, 0xE5C02693, 0x0C3E6039, 
  0xA33CE459, 0x64FF2167, 0xF6ECEDD4, 0x19DB06C1
};
int sha256_test2_size= 56;

const byte* sha256_test3_input=
      (const byte*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
int sha256_test3_size= 112;
uint32_t sha256_test3_answer[8] = {
  0xcf5b16a7, 0x78af8380, 0x036ce59e, 0x7b049237, 
  0x0b249b11, 0xe8f07a51, 0xafac4503, 0x7afee9d1
};

// sha-3

const int sha3_testa_size = 0;
const byte sha3_testa_answer[128] = {
  0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
  0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
  0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
  0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
  0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
  0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
  0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
  0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
};


const int sha3_test0_size = 3;
const byte sha3_test0_input[3] = {0x61, 0x62, 0x63};
const byte sha3_test0_answer[128] = {
  0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
  0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
  0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
  0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
  0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
  0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
  0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
  0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
};

// sha-3 256
const int sha3_test0a_size = 3;
const byte sha3_test0a_input[3] = {0x61, 0x62, 0x63};
const byte sha3_test0a_answer[128] = {
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
    0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
    0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
};

// c = 1024, d=64
const int sha3_test1_size = 1;
const byte sha3_test1_input[1] = {0xCC};
const byte sha3_test1_answer[64] = {
    0x39, 0x39, 0xFC, 0xC8, 0xB5, 0x7B, 0x63, 0x61,
    0x25, 0x42, 0xDA, 0x31, 0xA8, 0x34, 0xE5, 0xDC,
    0xC3, 0x6E, 0x2E, 0xE0, 0xF6, 0x52, 0xAC, 0x72,
    0xE0, 0x26, 0x24, 0xFA, 0x2E, 0x5A, 0xDE, 0xEC,
    0xC7, 0xDD, 0x6B, 0xB3, 0x58, 0x02, 0x24, 0xB4,
    0xD6, 0x13, 0x87, 0x06, 0xFC, 0x6E, 0x80, 0x59,
    0x7B, 0x52, 0x80, 0x51, 0x23, 0x0B, 0x00, 0x62,
    0x1C, 0xC2, 0xB2, 0x29, 0x99, 0xEA, 0xA2, 0x05
};

// c = 512, d=32
const int sha3_test1a_size = 1;
const byte sha3_test1a_input[1] = {0xCC};
const byte sha3_test1a_answer[32] = {
    0x67, 0x70, 0x35, 0x39, 0x1C, 0xD3, 0x70, 0x12,
    0x93, 0xD3, 0x85, 0xF0, 0x37, 0xBA, 0x32, 0x79,
    0x62, 0x52, 0xBB, 0x7C, 0xE1, 0x80, 0xB0, 0x0B,
    0x58, 0x2D, 0xD9, 0xB2, 0x0A, 0xAA, 0xD7, 0xF0
};

// shake-128
const int shake128_test1_size = 1;
const byte shake128_test1_input[1] = {0x0e};
const byte shake128_test1_answer[16] = {
    0xfa, 0x99, 0x6d, 0xaf, 0xaa, 0x20, 0x8d, 0x72,
    0x28, 0x7c, 0x23, 0xbc, 0x4e, 0xd4, 0xbf, 0xd5
};

// shake-256
const int shake256_test1_size = 1;
const byte shake256_test1_input[1] = {0x0f};
const byte shake256_test1_answer[32] = {
    0xaa, 0xbb, 0x07, 0x48, 0x8f, 0xf9, 0xed, 0xd0,
    0x5d, 0x6a, 0x60, 0x3b, 0x77, 0x91, 0xb6, 0x0a,
    0x16, 0xd4, 0x50, 0x93, 0x60, 0x8f, 0x1b, 0xad,
    0xc0, 0xc9, 0xcc, 0x9a, 0x91, 0x54, 0xf2, 0x15
};


int hmacsha256_test1_keysize = 20;
byte hmacsha256_test1_key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
byte* hmacsha256_test1_input = (byte*)"Hi There";
int hmacsha256_test1_size_input = 8;
byte hmacsha256_test1_mac[32] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
    0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
    0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

int hmacsha256_test2_keysize = 4;
byte* hmacsha256_test2_key = (byte*)"Jefe";
byte* hmacsha256_test2_input = (byte*)"what do ya want for nothing?";
int hmacsha256_test2_size_input = 28;
byte hmacsha256_test2_mac[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
    0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
    0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
};

int hmacsha256_test3_keysize = 20;
byte hmacsha256_test3_key[20] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};
int hmacsha256_test3_size_input = 50;
byte hmacsha256_test3_input[50] = {
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd
};
byte hmacsha256_test3_mac[32] = {
    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8,
    0xeb, 0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8,
    0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe
};


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

bool test_sha256() {
  sha256 hash_object;

  byte digest1[hash_object.DIGESTBYTESIZE];
  byte digest2[hash_object.DIGESTBYTESIZE];

  if (!hash_object.init())
    return false;
  hash_object.add_to_hash(sha256_test1_size, sha256_test1_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.DIGESTBYTESIZE, digest1))
    return false;
  if (FLAGS_print_all) {
    printf("Bytes to hash  : "); print_bytes(sha256_test1_size, (byte*)sha256_test1_input);
    printf("Correct digest : "); print_bytes(hash_object.DIGESTBYTESIZE, (byte*)sha256_test1_answer);
    printf("Computed digest: "); print_bytes(hash_object.DIGESTBYTESIZE, digest1);
  }
  if (memcmp((const void *)sha256_test1_answer,
             (const void *) digest1, hash_object.DIGESTBYTESIZE) != 0)
    return false;

  if (!hash_object.init())
    return false;
  hash_object.add_to_hash(sha256_test2_size, sha256_test2_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.DIGESTBYTESIZE, digest2))
    return false;
  if (FLAGS_print_all) {
    printf("Bytes to hash  : "); print_bytes(sha256_test2_size, (byte*)sha256_test2_input);
    printf("Correct digest : "); print_bytes(hash_object.DIGESTBYTESIZE, (byte*)sha256_test2_answer);
    printf("Computed digest: "); print_bytes(hash_object.DIGESTBYTESIZE, digest2);
  }
  if (memcmp((const void *)sha256_test2_answer,
             (const void *) digest2, hash_object.DIGESTBYTESIZE) != 0)
    return false;

  return true;
}

bool test_sha3() {
  sha3 hash_object;
  byte digest[1024 / NBITSINBYTE];

  if (FLAGS_print_all) {
    printf("Sha3 test0\n");
  }
  memset(digest, 0, 1024 / NBITSINBYTE);
  if (!hash_object.init(1024, 256)) {
    return false;
  }
  hash_object.add_to_hash(sizeof(sha3_test0_input), (byte*)sha3_test0_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.num_out_bytes_, digest)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("SHA-3(c= %d, r= %d), hash size: %d\n", hash_object.c_, hash_object.r_, hash_object.num_out_bytes_);
    printf("\tInput        : ");
    print_bytes(sizeof(sha3_test0_input), (byte*)sha3_test0_input);
    printf("\tComputed hash: ");
    print_bytes(hash_object.num_out_bytes_, digest);
    printf("\tCorrect hash:  ");
    print_bytes(hash_object.num_out_bytes_, (byte*)sha3_test0_answer);
    printf("\n");
  }
  if (memcmp((byte*)sha3_test0_answer, digest, hash_object.num_out_bytes_) != 0) return false;

  if (FLAGS_print_all) {
    printf("Sha3 test0a\n");
  }
  memset(digest, 0, 1024 / NBITSINBYTE);
  if (!hash_object.init(512, 256)) {
    return false;
  }
  hash_object.add_to_hash(sizeof(sha3_test0a_input), (byte*)sha3_test0a_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.num_out_bytes_, digest)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("SHA-3(c= %d, r= %d), hash size: %d\n", hash_object.c_, hash_object.r_, hash_object.num_out_bytes_);
    printf("\tInput        : ");
    print_bytes(sizeof(sha3_test0a_input), (byte*)sha3_test0a_input);
    printf("\tComputed hash: ");
    print_bytes(hash_object.num_out_bytes_, digest);
    printf("\tCorrect hash:  ");
    print_bytes(hash_object.num_out_bytes_, (byte*)sha3_test0a_answer);
    printf("\n");
  }
  if (memcmp((byte*)sha3_test0a_answer, digest, hash_object.num_out_bytes_) != 0) return false;

  if (FLAGS_print_all) {
    printf("Sha3 test1\n");
  }
  memset(digest, 0, 1024 / NBITSINBYTE);
  if (!hash_object.init(1024, 512)) {
    return false;
  }
  hash_object.add_to_hash(sizeof(sha3_test1_input), (byte*)sha3_test1_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.num_out_bytes_, digest)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("SHA-3(c= %d, r= %d), hash size: %d\n", hash_object.c_, hash_object.r_, hash_object.num_out_bytes_);
    printf("\tInput        : ");
    print_bytes(sizeof(sha3_test1_input), (byte*)sha3_test1_input);
    printf("\tComputed hash: ");
    print_bytes(hash_object.num_out_bytes_, digest);
    printf("\tCorrect hash:  ");
    print_bytes(hash_object.num_out_bytes_, (byte*)sha3_test1_answer);
    printf("\n");
  }
  if (memcmp((byte*)sha3_test1_answer, digest, hash_object.num_out_bytes_) != 0) return false;

  if (FLAGS_print_all) {
    printf("Sha3 test1a\n");
  }
  memset(digest, 0, 1024 / NBITSINBYTE);
  if (!hash_object.init(512, 256)) {
    return false;
  }
  hash_object.add_to_hash(sizeof(sha3_test1a_input), (byte*)sha3_test1a_input);
  hash_object.finalize();
  if (!hash_object.get_digest(hash_object.num_out_bytes_, digest)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("SHA-3(c= %d, r= %d), hash size: %d\n", hash_object.c_, hash_object.r_, hash_object.num_out_bytes_);
    printf("\tInput        : ");
    print_bytes(sizeof(sha3_test1a_input), (byte*)sha3_test1a_input);
    printf("\tComputed hash: ");
    print_bytes(hash_object.num_out_bytes_, digest);
    printf("\tCorrect hash:  ");
    print_bytes(hash_object.num_out_bytes_, (byte*)sha3_test1a_answer);
    printf("\n");
  }
  if (memcmp((byte*)sha3_test1a_answer, digest, hash_object.num_out_bytes_) != 0) return false;

  if (FLAGS_print_all) {
    printf("Shake256 test1\n");
  }
  memset(digest, 0, 1024 / NBITSINBYTE);
  if (!hash_object.init(512, 256)) {
    return false;
  }
  hash_object.add_to_hash(sizeof(shake256_test1_input), (byte*)shake256_test1_input);
  hash_object.shake_finalize();
  if (!hash_object.get_digest(hash_object.num_out_bytes_, digest)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("Shake256(c= %d, r= %d), hash size: %d\n", hash_object.c_, hash_object.r_, hash_object.num_out_bytes_);
    printf("\tInput        : ");
    print_bytes(sizeof(shake256_test1_input), (byte*)shake256_test1_input);
    printf("\tComputed hash: ");
    print_bytes(hash_object.num_out_bytes_, digest);
    printf("\tCorrect hash:  ");
    print_bytes(hash_object.num_out_bytes_, (byte*)shake256_test1_answer);
    printf("\n");
  }
  if (memcmp((byte*)shake256_test1_answer, digest, hash_object.num_out_bytes_) != 0) return false;


  return true;
}

bool test_ghash() {
  return true;
}

bool test_hmac_sha256() {
  byte test1_hmac[sha256::DIGESTBYTESIZE];
  byte test2_hmac[sha256::DIGESTBYTESIZE];
  byte test3_hmac[sha256::DIGESTBYTESIZE];
  hmac_sha256 mac1;
  hmac_sha256 mac2;
  hmac_sha256 mac3;

  if (!mac1.init(hmacsha256_test1_keysize, hmacsha256_test1_key)) {
    return false;
  }
  mac1.add_to_inner_hash(hmacsha256_test1_size_input, hmacsha256_test1_input);
  mac1.finalize();
  if (!mac1.get_hmac(sha256::DIGESTBYTESIZE, (byte*)test1_hmac)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("\tMac key     : ");
    print_bytes(hmacsha256_test1_keysize, (byte*)hmacsha256_test1_key);
    printf("\tMac input   : ");
    print_bytes(hmacsha256_test1_size_input, hmacsha256_test1_input);
    printf("\tComputed mac: ");
    print_bytes(sha256::DIGESTBYTESIZE, (byte*)test1_hmac);
    printf("\tCorrect mac : ");
    print_bytes(sha256::DIGESTBYTESIZE, (byte*)hmacsha256_test1_mac);
  }
  if (memcmp((byte*)test1_hmac, (byte*)hmacsha256_test1_mac, sha256::DIGESTBYTESIZE) != 0) {
    return false;
  }

  if (!mac2.init(hmacsha256_test2_keysize, hmacsha256_test2_key)) {
    return false;
  }
  mac2.add_to_inner_hash(hmacsha256_test2_size_input, hmacsha256_test2_input);
  mac2.finalize();
  if (!mac2.get_hmac(sha256::DIGESTBYTESIZE, (byte*)test2_hmac)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("\tMac key     : ");
    print_bytes(hmacsha256_test2_keysize, (byte*)hmacsha256_test2_key);
    printf("\tMac input   : ");
    print_bytes(hmacsha256_test2_size_input, hmacsha256_test2_input);
    printf("\tComputed mac: ");
    print_bytes(sha256::DIGESTBYTESIZE, (byte*)test2_hmac);
    printf("\tCorrect mac : ");
    print_bytes(sha256::DIGESTBYTESIZE, (byte*)hmacsha256_test2_mac);
  }
  if (memcmp((byte*)test2_hmac, (byte*)hmacsha256_test2_mac, sha256::DIGESTBYTESIZE) != 0) {
    return false;
  }

  if (!mac3.init(hmacsha256_test3_keysize, hmacsha256_test3_key)) {
    return false;
  }
  mac3.add_to_inner_hash(hmacsha256_test3_size_input, hmacsha256_test3_input);
  mac3.finalize();
  if (!mac3.get_hmac(sha256::DIGESTBYTESIZE, (byte*)test3_hmac)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("\tMac key     : ");
    print_bytes(hmacsha256_test3_keysize, (byte*)hmacsha256_test3_key);
    printf("\tMac input   : ");
    print_bytes(hmacsha256_test3_size_input, hmacsha256_test3_input);
    printf("\tComputed mac: ");
    print_bytes(sha256::DIGESTBYTESIZE, (byte*)test3_hmac);
    printf("\tCorrect mac : ");
    print_bytes(sha256::DIGESTBYTESIZE, (byte*)hmacsha256_test3_mac);
  }
  if (memcmp((byte*)test3_hmac, (byte*)hmacsha256_test3_mac, sha256::DIGESTBYTESIZE) != 0) {
    return false;
  }

  return true;
}

bool test_pkcs() {
  byte in[64];
  byte out[256];
  int new_out_size = 256;
  byte new_out[256];

  random_source rs;

  if (!rs.start_random_source())
    return false;

  memset(in, 0xbb, 64);
  if (!pkcs_encode("sha-256", in, 256, out)) {
    printf("PkcsEncode failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("encoded hash: ");
    print_bytes(256, out);
    printf("\n");
  }
  if (!pkcs_verify("sha-256", in, 256, out)) {
    printf("PkcsVerify failed\n");
    return false;
  }
  memset(out, 0, 256);
  memset(new_out, 0, 256);
  if (!pkcs_embed(64, in, 256, out)) {
    printf("PkcsEmbed failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("embedded message: ");
    print_bytes(256, out);
    printf("\n");
  }
  if (!pkcs_extract(256, out, &new_out_size, new_out)) {
    printf("PkcsExtract failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("retrieved message: ");
    print_bytes(new_out_size, new_out);
    printf("\n");
  }
  if (new_out_size != 64 || memcmp(new_out, in, new_out_size) != 0)
    return false;

  rs.close_random_source();
  return true;
}

bool test_pkdf2() {
  byte out[256];
  int salt_size = 24;
  byte salt[256];
  
  memset(out, 0, 256); 
  memset(salt, 0x09, salt_size);

  if (!pbkdf2("My voice is my password, hear me speak", salt_size, salt, 10, 72,
              out)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("password derived key: ");
    print_bytes(80, out);
    printf("\n");
  }

  return true;
}

bool test_cmac() {
  return true;
}

TEST (ghash, test_ghash) {
  EXPECT_TRUE(test_ghash());
}
TEST (cmac, test_cmac) {
  EXPECT_TRUE(test_cmac());
}
TEST (sha1, test_sha1) {
  EXPECT_TRUE(test_sha1());
}
TEST (sha2, sha2) {
  EXPECT_TRUE(test_sha256());
}
TEST(hmac, test_hmac_sha256) {
  EXPECT_TRUE(test_hmac_sha256());
}
TEST (pkcs1, test_pkcs) {
  EXPECT_TRUE(test_pkcs());
}
TEST (pkdf, test_pkdf2) {
  EXPECT_TRUE(test_pkdf2());
}
TEST (sha3, test_sha3) {
  EXPECT_TRUE(test_sha3());
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return result;
}
