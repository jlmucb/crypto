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
#include "twofish.h"
#include "hash.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "encryption_scheme.h"


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

const int twofish_test1_key_size = 16;
byte twofish_test1_key[] = {
    0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
    0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
};
byte twofish_test1_plain[] = {
  0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
  0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
};

bool test_padding() {
  return true;
}

bool test_aes_sha256_ctr_test1() {
  encryption_scheme enc_scheme;
  bool ret_value = true;

  string enc_key;
  string hmac_key;
  string nonce;
  byte x[32];

  for (int i = 0; i < 32; i++)
    x[i] = i;
  enc_key.assign((char*)x, 32);
  for (int i = 0; i < 32; i++)
    x[i] = i+32;
  hmac_key.assign((char*)x, 32);
  for (int i = 0; i < 32; i++)
    x[i] = i+64;
  nonce.assign((char*)x, 32);

  time_point t1, t2;
  t1.time_now();
  string s1, s2;
  if (!t1.encode_time(&s1))
    return false;
  t2.add_interval_to_time(t1, 5 * 365 * 86400.0);
  if (!t2.encode_time(&s2))
    return false;

  // encrypt init
  if (!enc_scheme.init("aes128-hmacsha256-ctr", "scheme-test",
        "ctr", "sym-pad", "testing", s1.c_str(), s2.c_str(),
        "aes", 128, enc_key, "aes_test_key", "hmac-sha256",
        hmac_key.size(),  hmac_key, 256, nonce)) {
    return false;
  }

  const char* message = "Four score and severn years ago, out forefathers brought forth stuff";
  int msg_encrypt_size = strlen(message) + 1;
  int allocated = msg_encrypt_size + 3 * enc_scheme.get_block_size() + enc_scheme.get_mac_size();
  int msg_decrypt_size;
  int decrypted_size;
  byte* plain = nullptr;
  byte* cipher = nullptr;
  byte* recovered = nullptr;

  plain = new byte[allocated];
  if (plain == nullptr) {
    ret_value = false;
    goto done;
  }
  cipher = new byte[allocated];
  if (cipher == nullptr) {
    ret_value = false;
    goto done;
  }
  recovered = new byte[allocated];
  if (recovered == nullptr) {
    ret_value = false;
    goto done;
  }
  memcpy(plain, (byte*)message, msg_encrypt_size);
  memset(cipher, 0, allocated);
  memset(recovered, 0, allocated);

  // encrypt
  if (!enc_scheme.encrypt_message(msg_encrypt_size, plain, allocated, cipher)) {
    ret_value = false;
    goto done;
  }

  msg_decrypt_size = enc_scheme.get_total_bytes_output();
  if (FLAGS_print_all) {
    printf("encryption alg: %s\n", "aes");
    printf("encryption key: "); print_bytes((int)enc_key.size(), (byte*)enc_key.data());
    printf("hmac alg      : %s\n", "hmac-sha256");
    printf("hmac key      : "); print_bytes((int)hmac_key.size(), (byte*)hmac_key.data());
    printf("nonce         : "); print_bytes((int)nonce.size(), (byte*)nonce.data());
    printf("%d bytes encrypted\n", enc_scheme.get_bytes_encrypted());
    printf("%d bytes output\n", enc_scheme.get_total_bytes_output());
    printf("plain         : "); print_bytes(msg_encrypt_size, plain);
    printf("cipher        : ");print_bytes(msg_decrypt_size, cipher);
  }
  if(!enc_scheme.get_message_valid()) {
    ret_value = false;
    goto done;
  }
  enc_scheme.clear();

  // decrypt
  if (!enc_scheme.init("aes128-hmacsha256-ctr", "scheme-test",
        "ctr", "sym-pad", "testing", s1.c_str(), s2.c_str(),
        "aes", 128, enc_key, "aes_test_key", "hmac-sha256",
        hmac_key.size(),  hmac_key, 256, nonce)) {
    ret_value = false;
    goto done;
  }
  if (!enc_scheme.decrypt_message(msg_decrypt_size, cipher, allocated, recovered)) {
    ret_value = false;
    goto done;
  }
  if(!enc_scheme.get_message_valid()) {
    ret_value = false;
    goto done;
  }
  decrypted_size = enc_scheme.get_bytes_encrypted();
  if (FLAGS_print_all) {
    printf("%d bytes decrypted\n", decrypted_size);
    printf("%d bytes output\n", enc_scheme.get_total_bytes_output());
    printf("decrypted     : "); print_bytes(decrypted_size, recovered);
  }
  if (memcmp(plain, recovered, decrypted_size) != 0) {
    ret_value = false;
    goto done;
  }

done:
  if (plain != nullptr)
    delete []plain;
  if (cipher != nullptr)
    delete []cipher;
  if (recovered != nullptr)
    delete []recovered;
  return ret_value;
}

bool test_aes_sha256_cbc_test1() {
  return true;
}

TEST (padding, simple) {
  EXPECT_TRUE(test_aes_sha256_ctr_test1());
}
TEST (aes_sha256_ctr, test_aes_sha256_ctr) {
  EXPECT_TRUE(test_aes_sha256_ctr_test1());
}
TEST (aes_sha256_cbc, test_aes_sha256_cbc) {
  EXPECT_TRUE(test_aes_sha256_cbc_test1());
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto())
    return 1;
  int result = RUN_ALL_TESTS();
  close_crypto();

  printf("\n");
  return result;
}
