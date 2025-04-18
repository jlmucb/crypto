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
// File: test_encryption_scheme.cc

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

byte_t aes128_test1_plain[] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
byte_t aes128_test1_key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
byte_t aes128_test1_cipher[] = {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

byte_t aes256_test1_plain[] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
byte_t aes256_test1_key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f 
};
byte_t aes256_test1_cipher[] = {
  0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
  0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
};

const int twofish_test1_key_size = 16;
byte_t twofish_test1_key[] = {
  0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
  0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
};
byte_t twofish_test1_plain[] = {
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
  byte_t x[32];

  for (int i = 0; i < 32; i++)
    x[i] = i;
  enc_key.assign((char*)x, 16);
  for (int i = 0; i < 32; i++)
    x[i] = i+32;
  hmac_key.assign((char*)x, 32);

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
        256, hmac_key)) {
printf("ctr init failed\n");  // REMOVE
    return false;
  }

  const char* message = "Four score and seven years ago, out forefathers brought forth stuff";
  int msg_encrypt_size = strlen(message) + 1;
  int allocated = msg_encrypt_size + 3 * enc_scheme.get_block_size() + enc_scheme.get_mac_size();
  int msg_decrypt_size;
  int decrypted_size;
  byte_t* plain = nullptr;
  byte_t* cipher = nullptr;
  byte_t* recovered = nullptr;

  plain = new byte_t[allocated];
  if (plain == nullptr) {
    ret_value = false;
    goto done;
  }
  cipher = new byte_t[allocated];
  if (cipher == nullptr) {
    ret_value = false;
    goto done;
  }
  recovered = new byte_t[allocated];
  if (recovered == nullptr) {
    ret_value = false;
    goto done;
  }
  memcpy(plain, (byte_t*)message, msg_encrypt_size);
  memset(cipher, 0, allocated);
  memset(recovered, 0, allocated);
  // encrypt
  if (!enc_scheme.encrypt_message(msg_encrypt_size, plain, allocated, cipher)) {
printf("ctr encrypt_message failed\n");  // REMOVE
    ret_value = false;
    goto done;
  }

  msg_decrypt_size = enc_scheme.get_total_bytes_output();
  if (FLAGS_print_all) {
    printf("aes-sh256-ctr\n");
    printf("encryption alg: %s\n", "aes");
    printf("encryption key: "); print_bytes((int)enc_key.size(), (byte_t*)enc_key.data());
    printf("hmac alg      : %s\n", "hmac-sha256");
    printf("hmac key      : "); print_bytes((int)hmac_key.size(), (byte_t*)hmac_key.data());
    printf("nonce         : "); print_bytes((int)nonce.size(), (byte_t*)nonce.data());
    printf("%d bytes encrypted\n", enc_scheme.get_bytes_encrypted());
    printf("%d bytes output\n", enc_scheme.get_total_bytes_output());
    printf("plain         : "); print_bytes(msg_encrypt_size, plain);
    printf("cipher        : ");print_bytes(msg_decrypt_size, cipher);
  }
  if(!enc_scheme.get_message_valid()) {
printf("ctr ms valid failed\n");  // REMOVE
    ret_value = false;
    goto done;
  }
  enc_scheme.clear();

  // decrypt
  if (!enc_scheme.init("aes128-hmacsha256-ctr", "scheme-test",
        "ctr", "sym-pad", "testing", s1.c_str(), s2.c_str(),
        "aes", 128, enc_key, "aes_test_key", "hmac-sha256",
        256,  hmac_key)) {
printf("ctr decrypt init failed\n");  // REMOVE
    ret_value = false;
    goto done;
  }
  if (!enc_scheme.decrypt_message(msg_decrypt_size, cipher, allocated, recovered)) {
printf("ctr decrypt_message failed\n");  // REMOVE
    ret_value = false;
    goto done;
  }
  if(!enc_scheme.get_message_valid()) {
printf("ctr decrypt msg valid failed\n");  // REMOVE
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
  encryption_scheme enc_scheme;
  bool ret_value = true;

  string enc_key;
  string hmac_key;
  string nonce;
  byte_t x[32];

  for (int i = 0; i < 32; i++)
    x[i] = i;
  enc_key.assign((char*)x, 16);
  for (int i = 0; i < 32; i++)
    x[i] = i+32;
  hmac_key.assign((char*)x, 32);
  for (int i = 0; i < 32; i++)
    x[i] = i+64;
  nonce.assign((char*)x, 16);

  time_point t1, t2;
  t1.time_now();
  string s1, s2;
  if (!t1.encode_time(&s1))
    return false;
  t2.add_interval_to_time(t1, 5 * 365 * 86400.0);
  if (!t2.encode_time(&s2))
    return false;

  // encrypt init
  if (!enc_scheme.init("aes128-hmacsha256-cbc", "scheme-test",
        "cbc", "sym-pad", "testing", s1.c_str(), s2.c_str(),
        "aes", 128, enc_key, "aes_test_key", "hmac-sha256",
        256,  hmac_key)) {
    return false;
  }

  const char* message = "Four score and seven years ago, out forefathers brought forth stuff";
  int msg_encrypt_size = strlen(message) + 1;
  int allocated = msg_encrypt_size + 3 * enc_scheme.get_block_size() + enc_scheme.get_mac_size();
  int msg_decrypt_size;
  int decrypted_size;
  byte_t* plain = nullptr;
  byte_t* cipher = nullptr;
  byte_t* recovered = nullptr;

  plain = new byte_t[allocated];
  if (plain == nullptr) {
    ret_value = false;
    goto done;
  }
  cipher = new byte_t[allocated];
  if (cipher == nullptr) {
    ret_value = false;
    goto done;
  }
  recovered = new byte_t[allocated];
  if (recovered == nullptr) {
    ret_value = false;
    goto done;
  }
  memcpy(plain, (byte_t*)message, msg_encrypt_size);
  memset(cipher, 0, allocated);
  memset(recovered, 0, allocated);

  // encrypt
  if (!enc_scheme.encrypt_message(msg_encrypt_size, plain, allocated, cipher)) {
    ret_value = false;
    goto done;
  }

  msg_decrypt_size = enc_scheme.get_total_bytes_output();
  if (FLAGS_print_all) {
    printf("aes-sh256-cbc\n");
    printf("encryption alg: %s\n", "aes");
    printf("encryption key: "); print_bytes((int)enc_key.size(), (byte_t*)enc_key.data());
    printf("hmac alg      : %s\n", "hmac-sha256");
    printf("hmac key      : "); print_bytes((int)hmac_key.size(), (byte_t*)hmac_key.data());
    printf("nonce         : "); print_bytes((int)nonce.size(), (byte_t*)nonce.data());
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
  if (!enc_scheme.init("aes128-hmacsha256-cbc", "scheme-test",
        "cbc", "sym-pad", "testing", s1.c_str(), s2.c_str(),
        "aes", 128, enc_key, "aes_test_key", "hmac-sha256",
        256,  hmac_key)) {
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
  return true;
}

// CTR
byte_t aes128ctr_test2_key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
byte_t test2_hmac_key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

byte_t aes128ctr_test2_counter[32] = {
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x00
};
byte_t aes128ctr_test2_plain[32] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
byte_t aes128ctr_test2_cipher[32] = {
  0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
  0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
  0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
  0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff
};

// CBC
byte_t aes128cbc_test2_key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
byte_t aes128cbc_test2_iv[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
byte_t aes128cbc_test2_plain[16] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
byte_t aes128cbc_test2_cipher[16] = {
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
  0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
};

const char* aes_cbc_test4_key = "06a9214036b8a15b512e03d534120006";
const char* aes_cbc_test4_iv =  "3dafba429d9eb430b422da802c9fac41";
const char* aes_cbc_test4_plain = "Single block msg";
const char* aes_cbc_test4_cipher = "e353779c1079aeb82708942dbe77181a";
const char* aes_cbc_test4_hmac_key = "0102030405060708090a0b0c0d0e0f00";

bool test_aes_sha256_ctr_test2() {
  return true;
}

bool test_aes_sha256_cbc_test2() {
  encryption_scheme enc_scheme;
  bool ret_value = true;

  string enc_key_hex(aes_cbc_test4_key);
  string hmac_key_hex(aes_cbc_test4_hmac_key);
  string nonce_hex(aes_cbc_test4_iv);
  string cipher_hex(aes_cbc_test4_cipher);

  string enc_key;
  string hmac_key;
  string nonce;
  string known_cipher_text;

  if (!hex_to_bytes(enc_key_hex, &enc_key))
    return false;
  if (!hex_to_bytes(hmac_key_hex, &hmac_key))
    return false;
  if (!hex_to_bytes(nonce_hex, &nonce))
    return false;
  if (!hex_to_bytes(cipher_hex, &known_cipher_text))
    return false;

  time_point t1, t2;
  t1.time_now();
  string s1, s2;
  if (!t1.encode_time(&s1))
    return false;
  t2.add_interval_to_time(t1, 5 * 365 * 86400.0);
  if (!t2.encode_time(&s2))
    return false;

  // encrypt init
  if (!enc_scheme.init("aes128-hmacsha256-cbc", "scheme-test",
        "cbc", "sym-pad", "testing", s1.c_str(), s2.c_str(),
        "aes", 128, enc_key, "aes_test_key", "hmac-sha256",
        256,  hmac_key)) {
    return false;
  }

  int msg_encrypt_size = strlen(aes_cbc_test4_plain);
  int allocated = msg_encrypt_size + 3 * enc_scheme.get_block_size() + enc_scheme.get_mac_size();
  int msg_decrypt_size;
  int decrypted_size;
  byte_t* plain = nullptr;
  byte_t* cipher = nullptr;
  byte_t* recovered = nullptr;

  plain = new byte_t[allocated];
  if (plain == nullptr) {
    ret_value = false;
    goto done;
  }
  cipher = new byte_t[allocated];
  if (cipher == nullptr) {
    ret_value = false;
    goto done;
  }
  recovered = new byte_t[allocated];
  if (recovered == nullptr) {
    ret_value = false;
    goto done;
  }
  memcpy(plain, (byte_t*)aes_cbc_test4_plain, msg_encrypt_size);
  memset(cipher, 0, allocated);
  memset(recovered, 0, allocated);

  // encrypt
  if (!enc_scheme.encrypt_message(msg_encrypt_size, plain, allocated, cipher)) {
    ret_value = false;
    goto done;
  }

  msg_decrypt_size = enc_scheme.get_total_bytes_output();
  if (FLAGS_print_all) {
    printf("aes-sh256-cbc\n");
    printf("encryption alg: %s\n", "aes");
    printf("encryption key: "); print_bytes((int)enc_key.size(), (byte_t*)enc_key.data());
    printf("hmac alg      : %s\n", "hmac-sha256");
    printf("hmac key      : "); print_bytes((int)hmac_key.size(), (byte_t*)hmac_key.data());
    printf("nonce         : "); print_bytes((int)nonce.size(), (byte_t*)nonce.data());
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
  if (!enc_scheme.init("aes128-hmacsha256-cbc", "scheme-test",
        "cbc", "sym-pad", "testing", s1.c_str(), s2.c_str(),
        "aes", 128, enc_key, "aes_test_key", "hmac-sha256",
        256,  hmac_key)) {
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
  if (memcmp(&cipher[aes::BLOCKBYTESIZE], (byte_t*)known_cipher_text.data(),
         aes::BLOCKBYTESIZE) != 0) {
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
  return true;
}

TEST (aes_sha256_ctr, test_aes_sha256_ctr) {
  EXPECT_TRUE(test_aes_sha256_ctr_test1());
  EXPECT_TRUE(test_aes_sha256_ctr_test2());
}
TEST (aes_sha256_cbc, test_aes_sha256_cbc) {
  EXPECT_TRUE(test_aes_sha256_cbc_test1());
  EXPECT_TRUE(test_aes_sha256_cbc_test2());
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
