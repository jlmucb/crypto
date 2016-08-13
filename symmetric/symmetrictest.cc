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
// File: symmetric.cc

#include <stdio.h>
#include <string.h>

#include <string>

#include "util.h"
#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "conversions.h"
#include "symmetric_cipher.h"
#include "keys.h"
#include "aes.h"
#include "twofish.h"
#include "rc4.h"
#include "tea.h"
#include "simonspeck.h"
#include "encryption_algorithm.h"
#include "aescbchmac256sympad.h"
#include "aesctrhmac256sympad.h"
#include "aesgcm.h"
#include "aessiv.h"

#include <memory>
#include <cmath>


DEFINE_bool(printall, false, "printall flag");

uint64_t cycles_per_second = 10;

class SymmetricTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void SymmetricTest::SetUp() {}

void SymmetricTest::TearDown() {}

byte aes128_test1_plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
byte aes128_test1_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
byte aes128_test1_cipher[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

bool SimpleAes128Test() {
  Aes aes128_object;
  byte test_cipher_out[16];
  byte test_plain_out[16];

  if (FLAGS_printall) {
    printf("Aes-128 test\n");
    printf("\n");
  }

  if (!aes128_object.Init(128, aes128_test1_key, Aes::BOTH)) {
    printf("Can't init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(aes128_test1_plain, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  if (FLAGS_printall) {
    printf("\tKey            : ");
    PrintBytes(16, aes128_test1_key);
    printf("\n");
    printf("\tCorrect plain  : ");
    PrintBytes(16, aes128_test1_plain);
    printf("\n");
    printf("\tCorrect cipher : ");
    PrintBytes(16, aes128_test1_cipher);
    printf("\tComputed cipher: ");
    PrintBytes(16, test_cipher_out);
    printf("\n");
    printf("\tComputed plain : ");
    PrintBytes(16, test_plain_out);
    printf("\n");
    printf("\n");
  }
  if (memcmp(aes128_test1_cipher, test_cipher_out, 16) != 0) return false;
  if (memcmp(aes128_test1_plain, test_plain_out, 16) != 0) return false;
  return true;
}

bool SimpleAes128NiTest() {
  AesNi aes128_object;
  byte test_cipher_out[16];
  byte test_plain_out[16];

  if (!HaveAesNi()) return true;
  if (FLAGS_printall) {
    printf("AesNi-128 test\n");
  }

  if (!aes128_object.Init(128, aes128_test1_key, AesNi::BOTH)) {
    printf("Cant init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(aes128_test1_plain, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  if (FLAGS_printall) {
    printf("\tKey            : ");
    PrintBytes(16, aes128_test1_key);
    printf("\n");
    printf("\tCorrect plain  : ");
    PrintBytes(16, aes128_test1_plain);
    printf("\n");
    printf("\tCorrect cipher : ");
    PrintBytes(16, aes128_test1_cipher);
    printf("\n");
    printf("\tComputed cipher: ");
    PrintBytes(16, test_cipher_out);
    printf("\n");
    printf("\tComputed plain : ");
    PrintBytes(16, test_plain_out);
    printf("\n");
    printf("\n");
  }
  if (memcmp(aes128_test1_cipher, test_cipher_out, 16) != 0) return false;
  if (memcmp(aes128_test1_plain, test_plain_out, 16) != 0) return false;
  return true;
}

static byte twofish_k128[] = {
    0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
    0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
};
static byte twofish_p128[] = {0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
                              0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19};
static byte twofish_c128[] = {0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
                              0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3};

bool SimpleTwofishTest() {
  Twofish enc_obj;

  if (FLAGS_printall) {
    printf("Twofish test\n");
    printf("\tKey: ");
    PrintBytes(16, twofish_k128);
    printf("\n");
  }
  if (!enc_obj.Init(128, twofish_k128, 0)) {
    printf("failed initialization\n");
    return false;
  }

  byte encrypted[16];
  byte decrypted[16];

  memset(encrypted, 0, 16);
  enc_obj.Encrypt(16, twofish_p128, encrypted);
  if (FLAGS_printall) {
    printf("\tplaintext: ");
    PrintBytes(16, twofish_p128);
    printf("\n");
    printf("\tencrypted: ");
    PrintBytes(16, encrypted);
    printf("\n");
    printf("\texpected : ");
    PrintBytes(16, twofish_c128);
    printf("\n");
    printf("\n");
  }

  memset(decrypted, 0, 16);
  enc_obj.Decrypt(16, encrypted, decrypted);
  if (FLAGS_printall) {
    printf("\tdecrypted: ");
    PrintBytes(16, decrypted);
    printf("\n");
    printf("\n");
  }
  if (memcmp(twofish_p128, decrypted, 16) != 0 ||
      memcmp(twofish_c128, encrypted, 16) != 0) {
    printf("Twofish: decrypted in and encrypted/decrypted text dont match\n");
    return false;
  }
  return true;
}

bool CbcEncryptTest(int size_enc_key, byte* enc_key, int size_int_key,
                    byte* int_key, int size_iv, byte* iv, int size_in, byte* in,
                    int size_out, byte* out, int size_out2, byte* out2,
                    int size_correct, byte* correct_cipher, bool aes_ni) {
  AesCbcHmac256Sympad encrypt_obj;
  AesCbcHmac256Sympad decrypt_obj;

  if (!encrypt_obj.InitEnc(size_enc_key, enc_key, size_int_key, int_key,
                           size_iv, iv, aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad encrypt object\n");
    return false;
  }

  if (!decrypt_obj.InitDec(size_enc_key, enc_key, size_int_key, int_key,
                           aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad decrypt object\n");
    return false;
  }

#if 0
  if (FLAGS_printall) {
    printf("\n");
    printf("name: %s\n", encrypt_obj.alg_name_->c_str());
    if (aes_ni) {
      printf("Aes key : ");
      PrintBytes(16, encrypt_obj.aesni_obj_.key_);
      printf("\n");
    } else {
      printf("Aes key : ");
      PrintBytes(16, encrypt_obj.aes_obj_.key_);
      printf("\n");
    }
    printf("Hmac key: ");
     PrintBytes(16, encrypt_obj.hmac_.key_);
    printf("\n");
    printf("input_bytes_processed_: %d, output_bytes_produced_: %d\n",
         encrypt_obj.input_bytes_processed_,
         encrypt_obj.output_bytes_produced_);
    printf("iv      : ");
    PrintBytes(16, encrypt_obj.iv_);
    printf("\n");
    printf("\n");
    }
#endif

  int encrypt_quantum = encrypt_obj.EncryptInputQuantum();
  int decrypt_quantum = decrypt_obj.DecryptInputQuantum();
  int encrypt_max_final = encrypt_obj.MinimumFinalEncryptIn();
  int decrypt_max_final = decrypt_obj.MinimumFinalDecryptIn();
  int encrypt_max_additional_output = encrypt_obj.MaxAdditionalOutput();
  int decrypt_max_additional_final_output =
      decrypt_obj.MaxAdditionalFinalOutput();

  if (FLAGS_printall) {
    printf("encrypt_quantum: %d, decrypt_quantum: %d\n", encrypt_quantum,
         decrypt_quantum);
    printf(
      "encrypt_max_additional_output: %d, decrypt_max_additional_final_output: "
      "%d\n",
      encrypt_max_additional_output, decrypt_max_additional_final_output);
    printf("encrypt_max_final: %d, decrypt_max_final: %d\n", encrypt_max_final,
         decrypt_max_final);
  }

  // bool ProcessInput(int size_in, byte* in, int* size_out, byte* out);
  int new_size_out = size_out2;
  if (!encrypt_obj.FinalPlainIn(size_in, in, &new_size_out, out)) {
    printf("encrypt_obj.FinalPlainIn failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Plain bytes in: %d, Cipher bytes out: %d\n",
         encrypt_obj.InputBytesProcessed(), encrypt_obj.OutputBytesProduced());
  }
  if (!decrypt_obj.FinalCipherIn(new_size_out, out, &new_size_out, out2)) {
    printf("FinalCipherIn failed\n");
    return false;
  }
  printf("Cipher bytes in: %d, Plain bytes out: %d\n",
         decrypt_obj.InputBytesProcessed(), decrypt_obj.OutputBytesProduced());

  int encrypt_input_bytes_processed = encrypt_obj.InputBytesProcessed();
  int encrypt_output_bytes_produced = encrypt_obj.OutputBytesProduced();
  if (FLAGS_printall) {
    printf( "encrypt_input_bytes_processed: %d, encrypt_input_bytes_produced: %d\n",
      encrypt_input_bytes_processed, encrypt_output_bytes_produced);
  }
  int decrypt_input_bytes_processed = decrypt_obj.InputBytesProcessed();
  int decrypt_output_bytes_produced = decrypt_obj.OutputBytesProduced();
  if (FLAGS_printall) {
    printf( "decrypt_input_bytes_processed: %d, decrypt_output_bytes_produced: %d\n",
      decrypt_input_bytes_processed, decrypt_output_bytes_produced);
  }
  if (decrypt_obj.MessageValid()) {
    printf("decrypt object valid\n");
  } else {
    printf("message invalid\n");
  }
  if (decrypt_obj.output_bytes_produced_ != size_in ||
      memcmp(in, out2, size_in) != 0) {
    printf("bad comparison, sizein: %d, new sizein: %d\n", size_in,
           new_size_out);
    return false;
  }
  if (FLAGS_printall) {
    printf("in              : ");
    PrintBytes(size_in, in);
    printf("\n");
    printf("correct cipher  : xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    PrintBytes(size_correct, correct_cipher);
    printf("\n");
    printf("computed cipher : ");
    PrintBytes(encrypt_output_bytes_produced, out);
    printf("\n");
    printf("out             : ");
    PrintBytes(decrypt_obj.output_bytes_produced_, out2);
    printf("\n");
    printf("\n");
  }
  if (memcmp(out + 16, correct_cipher, size_correct) == 0)
    printf("cipher matches\n");
  else
    return false;
  return true;
}

bool CtrEncryptTest(int size_enc_key, byte* enc_key, int size_int_key,
                    byte* int_key, byte* nonce, byte* iv, int size_in, byte* in,
                    int size_out, byte* out, int size_out2, byte* out2,
                    int size_correct, byte* correct_cipher, bool aes_ni) {
  AesCtrHmac256Sympad encrypt_obj;
  AesCtrHmac256Sympad decrypt_obj;

  if (!encrypt_obj.Init(size_enc_key, enc_key, size_int_key, int_key, 4, nonce,
                        8, iv, aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad encrypt object\n");
    return false;
  }

  if (!decrypt_obj.Init(size_enc_key, enc_key, size_int_key, int_key, 4, nonce,
                        8, iv, aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad decrypt object\n");
    return false;
  }

  if (FLAGS_printall) {
    printf("\n");
    printf("name: %s\n", encrypt_obj.alg_name_->c_str());
    if (aes_ni) {
      printf("Aes key : ");
      PrintBytes(16, encrypt_obj.aesni_obj_.key_);
      printf("\n");
    } else {
      printf("Aes key : ");
      PrintBytes(16, encrypt_obj.aes_obj_.key_);
      printf("\n");
    }
    printf("Hmac key: ");
    PrintBytes(16, encrypt_obj.hmac_.key_);
    printf("\n");
    printf("input_bytes_processed_: %d, output_bytes_produced_: %d\n",
         encrypt_obj.input_bytes_processed_, encrypt_obj.output_bytes_produced_);
    printf("\n");
  }

  int encrypt_quantum = encrypt_obj.EncryptInputQuantum();
  int decrypt_quantum = decrypt_obj.DecryptInputQuantum();
  int encrypt_max_final = encrypt_obj.MinimumFinalEncryptIn();
  int decrypt_max_final = decrypt_obj.MinimumFinalDecryptIn();
  int encrypt_max_additional_output = encrypt_obj.MaxAdditionalOutput();
  int decrypt_max_additional_final_output =
      decrypt_obj.MaxAdditionalFinalOutput();

  if (FLAGS_printall) {
    printf("encrypt_quantum: %d, decrypt_quantum: %d\n", encrypt_quantum,
         decrypt_quantum);
    printf("encrypt_max_additional_output: %d, decrypt_max_additional_final_output: "
      "%d\n",
      encrypt_max_additional_output, decrypt_max_additional_final_output);
    printf("encrypt_max_final: %d, decrypt_max_final: %d\n", encrypt_max_final,
         decrypt_max_final);
  }

  // bool ProcessInput(int size_in, byte* in, int* size_out, byte* out);
  int new_size_out = size_out2;
  if (!encrypt_obj.FinalPlainIn(size_in, in, &new_size_out, out)) {
    printf("encrypt_obj.FinalPlainIn failed\n");
    return false;
  }
  if (!decrypt_obj.FinalCipherIn(new_size_out, out, &new_size_out, out2)) {
    printf("FinalCipherIn failed\n");
    return false;
  }

  int encrypt_input_bytes_processed = encrypt_obj.InputBytesProcessed();
  int encrypt_output_bytes_produced = encrypt_obj.OutputBytesProduced();
  if (FLAGS_printall) {
    printf( "encrypt_input_bytes_processed: %d, encrypt_output_bytes_produced: %d\n",
      encrypt_input_bytes_processed, encrypt_output_bytes_produced);
  }
  int decrypt_input_bytes_processed = decrypt_obj.InputBytesProcessed();
  int decrypt_output_bytes_produced = decrypt_obj.OutputBytesProduced();
  if (FLAGS_printall) {
    printf("decrypt_input_bytes_processed: %d, decrypt_output_bytes_produced: %d\n",
      decrypt_input_bytes_processed, decrypt_output_bytes_produced);
  }
  if (decrypt_obj.MessageValid()) {
    printf("decrypt object valid\n");
  } else {
    printf("decrypt object invalid\n");
  }
  if (decrypt_obj.output_bytes_produced_ != size_in ||
      memcmp(in, out2, size_in) != 0) {
    printf("bad comparison, sizein: %d, new sizein: %d\n", size_in,
           new_size_out);
    return false;
  }
  if (FLAGS_printall) {
    printf("in              : ");
    PrintBytes(size_in, in);
    printf("\n");
    printf("out             : ");
    PrintBytes(encrypt_output_bytes_produced, out);
    printf("\n");
    printf("out2            : ");
    PrintBytes(decrypt_obj.output_bytes_produced_, out2);
    printf("\n");
  }
  if (memcmp(in, out2, size_in) == 0)
    printf("cipher matches\n");
  else
    return false;
  return true;
}

// CTR
byte aes128CTRTestKey1[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
byte aes128CTRTestCounterBlock[32] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
    0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
    0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x00};
byte aes128CTRTestPlain[32] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                               0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                               0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                               0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
byte aes128CTRTestCipher[32] = {0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
                                0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
                                0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
                                0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff};

// CBC
byte aes128CBCTestKey1[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
byte aes128CBCTestIV1[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
byte aes128CBCTestPlain1a[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
                                 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
                                 0x73, 0x93, 0x17, 0x2a};
byte aes128CBCTestCipher1a[16] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19,
                                  0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b,
                                  0x12, 0xe9, 0x19, 0x7d};
byte aes128CBCTestPlain1b[16] = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
                                 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
                                 0x45, 0xaf, 0x8e, 0x51};
byte aes128CBCTestCipher1b[16] = {0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72,
                                  0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
                                  0x91, 0x76, 0x78, 0xb2};
byte aes128CBCTestPlain1c[16] = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c,
                                 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
                                 0x1a, 0x0a, 0x52, 0xef};
byte aes128CBCTestCipher1c[16] = {0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1,
                                  0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e,
                                  0x22, 0x22, 0x95, 0x16};
byte aes128CBCTestPlain1d[16] = {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f,
                                 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
                                 0xe6, 0x6c, 0x37, 0x10};
byte aes128CBCTestCipher1d[16] = {0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f,
                                  0xac, 0x09, 0x12, 0x0e, 0xca, 0x30,
                                  0x75, 0x86, 0xe1, 0xa7};

bool SimpleCbcTest() {
  int num_out = 512;
  byte out_buf[512];
  int num_out2 = 512;
  byte out_buf2[512];
  bool use_aesni = HaveAesNi();

  printf("CbcEncryptTest\n");
  if (!CbcEncryptTest(sizeof(aes128CBCTestKey1), aes128CBCTestKey1,
                      sizeof(aes128CBCTestKey1), aes128CBCTestKey1,
                      sizeof(aes128CBCTestIV1), aes128CBCTestIV1,
                      sizeof(aes128CBCTestPlain1a), aes128CBCTestPlain1a,
                      num_out, out_buf, num_out2, out_buf2, 16,
                      aes128CBCTestCipher1a, use_aesni)) {
    printf("CbcEncryptTest failed\n");
    return false;
  }
  return true;
}

byte encryption_algorithm_test_iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                       0x0c, 0x0d, 0x0e, 0x0f};
byte encryption_algorithm_hmac_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
byte encryption_algorithm_enc_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                       0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f,
                                       0x08, 0x09, 0x0a, 0x0b};

bool AesNi128Compare(int size_key, byte* key, int size_in, byte* in) {
  AesNi aes128_object;
  byte test_cipher_out[16];
  byte test_plain_out[16];

  if (FLAGS_printall) {
    printf("AesCompare: Aes-128 test\n");
  }
  if (!aes128_object.Init(128, key, Aes::BOTH)) {
    printf("Aes128Compare: Cant init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(in, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  if (FLAGS_printall) {
    printf("\tKey            : ");
    PrintBytes(size_key, key);
    printf("\n");
    printf("\tPlain          : ");
    PrintBytes(16, in);
    printf("\n");
    printf("\tComputed plain : ");
    PrintBytes(16, test_plain_out);
    printf("\n");
  }
  if (memcmp(in, test_plain_out, 16) != 0) {
    printf("Aes-128 test failed\n");
    return false;
  }
  return true;
}

bool Aes128Compare(int size_key, byte* key, int size_in, byte* in) {
  Aes aes128_object;
  byte test_cipher_out[16];
  byte test_plain_out[16];

  if (!aes128_object.Init(128, key, Aes::BOTH)) {
    printf("Aes128Compare: Cant init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(in, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  if (FLAGS_printall) {
    printf("\tKey            : ");
    PrintBytes(size_key, key);
    printf("\n");
    printf("\tPlain          : ");
    PrintBytes(16, in);
    printf("\n");
    printf("\tComputed plain : ");
    PrintBytes(16, test_plain_out);
    printf("\n");
  }
  if (memcmp(in, test_plain_out, 16) != 0) {
    printf("AesCompare: Aes-128 test failed\n");
    return false;
  }
  return true;
}

bool CbcCompare(int size_enc_key, byte* enc_key, int size_int_key,
                byte* int_key, int size_iv, byte* iv, int size_in, byte* in,
                bool use_aesni) {
  AesCbcHmac256Sympad encrypt_obj;
  AesCbcHmac256Sympad decrypt_obj;

  if (!encrypt_obj.InitEnc(size_enc_key, enc_key, size_int_key, int_key,
                           size_iv, iv, use_aesni)) {
    printf("CbcCompare: Cant initialize AesCbcHmac256Sympad encrypt object\n");
    return false;
  }

  if (!decrypt_obj.InitDec(size_enc_key, enc_key, size_int_key, int_key,
                           use_aesni)) {
    printf("CbcCompare: Cant initialize AesCbcHmac256Sympad decrypt object\n");
    return false;
  }

  byte* cipher = new byte[size_enc_key + 128];
  byte* computeplain = new byte[size_enc_key + 128];
  bool fRet = true;

  int cipher_size = size_enc_key + 128;
  int plain_size = size_enc_key + 128;

  if (!encrypt_obj.FinalPlainIn(size_in, in, &cipher_size, cipher)) {
    printf("encrypt_obj.FinalPlainIn failed\n");
    fRet = false;
    goto done;
  }
  if (!decrypt_obj.FinalCipherIn(cipher_size, cipher, &plain_size,
                                 computeplain)) {
    printf("FinalCipherIn failed\n");
    fRet = false;
    goto done;
  }

#if 0
  int encrypt_input_bytes_processed = encrypt_obj.InputBytesProcessed();
  int encrypt_output_bytes_produced = encrypt_obj.OutputBytesProduced();
  int decrypt_input_bytes_processed = decrypt_obj.InputBytesProcessed();
  int decrypt_output_bytes_produced = decrypt_obj.OutputBytesProduced();
  if (size_in != decrypt_output_bytes_produced) {
    printf("input size does not match output size\n");
    fRet = false;
    goto done;
  }
#endif

  if (!decrypt_obj.MessageValid()) {
    printf("decrypt object invalid\n");
    fRet = false;
    goto done;
  }
  if (memcmp(in, computeplain, size_in) != 0) {
    printf("input does not match output\n");
    fRet = false;
    goto done;
  }

done:
  if (!fRet) {
    if (false) { //FLAGS_printall) {
      printf("Enc key: ");
      PrintBytes(size_enc_key, enc_key);
      printf("\n");
      printf("Int key: ");
      PrintBytes(size_int_key, int_key);
      printf("\n");
      printf("iv     : ");
      PrintBytes(size_iv, iv);
      printf("\n");
      printf("in     : ");
      PrintBytes(size_in, in);
      printf("\n");
      printf("\n");
    }
  }
  delete []cipher;
  delete []computeplain;
  return fRet;
}

bool SimpleCbcEncryptionAlgorithmTest() {
  AesCbcHmac256Sympad encryption_algorithm;
  crypto_encryption_algorithm_message message;
  byte in[AesNi::BLOCKBYTESIZE];
  byte out[512];
  byte out2[512];
  bool use_aesni = HaveAesNi();

  encryption_algorithm.message_id_ = new string("message-103");
  encryption_algorithm.initialized_ = true;
  encryption_algorithm.use_aesni_ = use_aesni;
  if (use_aesni) {
    if (!encryption_algorithm.aesni_obj_.Init(128, aes128CBCTestKey1,
                                              Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  } else {
    if (!encryption_algorithm.aes_obj_.Init(128, aes128CBCTestKey1,
                                            Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  }
  memcpy(encryption_algorithm.hmac_.key_, encryption_algorithm_hmac_key,
         HmacSha256::BLOCKBYTESIZE);
  memcpy(encryption_algorithm.iv_, aes128CBCTestIV1, AesNi::BLOCKBYTESIZE);
  EncryptionAlgorithm* encryption_algorithm_pointer =
      (EncryptionAlgorithm*)&encryption_algorithm;
  if (!encryption_algorithm_pointer->SerializeEncryptionAlgorithmToMessage(
          message)) {
    LOG(ERROR) << "can't serialize encryption_algorithm to message\n";
    return false;
  }
#if 0
  string sbuf= message.DebugString();
  printf("Buffer string: %s\n", sbuf.c_str());
#endif
  AesCbcHmac256Sympad* new_encryption_algorithm = new AesCbcHmac256Sympad();
  crypto_encryption_algorithm_message new_message;
  if (!((EncryptionAlgorithm*)new_encryption_algorithm)
           ->DeserializeEncryptionAlgorithmFromMessage(message)) {
    LOG(ERROR) << "can't deserialize encryption_algorithm from message\n";
    return false;
  }
  if (FLAGS_printall) {
    printf("\nCbcEncryptTest using desserialized state\n");
    new_encryption_algorithm->PrintEncryptionAlgorithm();
  }
  memcpy(in, aes128CBCTestPlain1a, AesNi::BLOCKBYTESIZE);
  byte* cbc_aes_key;
  if (use_aesni)
    cbc_aes_key = encryption_algorithm.aesni_obj_.key_;
  else
    cbc_aes_key = encryption_algorithm.aes_obj_.key_;
  if (!CbcEncryptTest(AesNi::BLOCKBYTESIZE, cbc_aes_key, AesNi::BLOCKBYTESIZE,
                      encryption_algorithm.iv_, AesNi::BLOCKBYTESIZE,
                      encryption_algorithm.iv_, AesNi::BLOCKBYTESIZE, in, 512,
                      out, 512, out2, AesNi::BLOCKBYTESIZE,
                      aes128CBCTestCipher1a, use_aesni)) {
    printf("CbcEncryptTest failed\n");
    return false;
  } else {
    printf("CbcEncryptTest succeeded\n");
  }
  return true;
}

bool SimpleCtrEncryptionAlgorithmTest() {
  AesCbcHmac256Sympad encryption_algorithm;
  crypto_encryption_algorithm_message message;
  byte in[AesNi::BLOCKBYTESIZE];
  byte out[512];
  byte out2[512];
  bool use_aesni = HaveAesNi();

  if (FLAGS_printall) {
    printf("SimpleCtrEncryptionAlgorithmTest\n");
  }
  encryption_algorithm.message_id_ = new string("message-104");
  encryption_algorithm.initialized_ = true;
  encryption_algorithm.use_aesni_ = use_aesni;
  if (use_aesni) {
    if (!encryption_algorithm.aesni_obj_.Init(128, aes128CBCTestKey1,
                                              Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  } else {
    if (!encryption_algorithm.aes_obj_.Init(128, aes128CBCTestKey1,
                                            Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  }
  memcpy(encryption_algorithm.hmac_.key_, encryption_algorithm_hmac_key,
         HmacSha256::BLOCKBYTESIZE);
  EncryptionAlgorithm* encryption_algorithm_pointer =
      (EncryptionAlgorithm*)&encryption_algorithm;
  if (!encryption_algorithm_pointer->SerializeEncryptionAlgorithmToMessage(
          message)) {
    LOG(ERROR) << "can't serialize encryption_algorithm to message\n";
    return false;
  }
  AesCtrHmac256Sympad* new_encryption_algorithm = new AesCtrHmac256Sympad();
  crypto_encryption_algorithm_message new_message;
  if (!((EncryptionAlgorithm*)new_encryption_algorithm)
           ->DeserializeEncryptionAlgorithmFromMessage(message)) {
    LOG(ERROR) << "can't deserialize encryption_algorithm from message\n";
    return false;
  }
  new_encryption_algorithm->PrintEncryptionAlgorithm();
  memcpy(in, aes128CBCTestPlain1a, AesNi::BLOCKBYTESIZE);
  if (!CtrEncryptTest(
          AesNi::BLOCKBYTESIZE, aes128CTRTestKey1, HmacSha256::BLOCKBYTESIZE,
          encryption_algorithm.hmac_.key_, aes128CTRTestCounterBlock,
          &aes128CTRTestCounterBlock[4], 32, aes128CTRTestPlain, 128, out, 128,
          out2, 128, aes128CTRTestCipher, use_aesni)) {
    printf("CtrEncryptTest failed\n");
    return false;
  } else {
    printf("CtrEncryptTest succeeded\n");
  }
  return true;
}

byte my_keys[1024];
byte my_test[1024];

void init_test() {
  int j;
  for (j = 0; j < 1024; j++) {
    my_keys[j] = (byte)j;
    my_test[j] = (byte)j;
  }
}

bool aes_benchmark_tests(byte* key, int num_tests, bool use_aesni) {
  printf("\nAES_TIME_TESTS\n");
  byte in[64];
  byte out[64];
  int num_tests_executed = 0;
  use_aesni &= HaveAesNi();

  uint64_t cycles_start_test;
  if (use_aesni) {
    AesNi aes;
    if (!aes.Init(128, key, Aes::ENCRYPT)) {
      cycles_start_test = 0;
      printf("AesNi failed Init()\n");
    } else {
      cycles_start_test = ReadRdtsc();
      for (num_tests_executed = 0; num_tests_executed < num_tests;
           num_tests_executed++) {
        aes.EncryptBlock(in, out);
      }
    }
  } else {
    Aes aes;
    if (!aes.Init(128, key, Aes::ENCRYPT)) {
      cycles_start_test = 0;
      printf("Aes failed Init()\n");
    } else {
      cycles_start_test = ReadRdtsc();
      for (num_tests_executed = 0; num_tests_executed < num_tests;
           num_tests_executed++) {
        aes.EncryptBlock(in, out);
      }
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  if (use_aesni) {
    printf("using aesni, ");
  } else {
    printf("not using aesni, ");
  }
  printf("aes_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per block %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END AES_TIME_TESTS\n\n");
  return true;
}

bool sha1_benchmark_tests() {
  /*
   */
  return true;
}

bool sha256_benchmark_tests() {
  /*
   */
  return true;
}

byte rc4_test_key[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
byte rc4_test_in[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
byte rc4_test_out[16] = {0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
                         0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8};
TEST(Rc4, Simple) {
  byte out[16];
  Rc4 rc4;

  EXPECT_TRUE(rc4.Init(5, rc4_test_key));
  rc4.Encrypt(16, rc4_test_in, out);
  if (FLAGS_printall) {
    printf("Rc4 test\n");
    printf("\tKey            : ");
    PrintBytes(5, rc4_test_key);
    printf("\n");
    printf("\tCorrect out : ");
    PrintBytes(16, rc4_test_out);
    printf("\n");
    printf("\tout         : ");
    PrintBytes(16, out);
    printf("\n");
    printf("\n");
  }
  EXPECT_TRUE(memcmp(out, rc4_test_out, 16) == 0);
}

byte tea_test_key[16] = {
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0
};
byte tea_test_in[8] = {0, 0, 0, 0, 0, 0, 0, 0};
byte tea_test_out[8] = {0x0a, 0x3a, 0xea, 0x41, 0x40, 0xa9, 0xba, 0x94};
TEST(Tea, Simple) {
  byte in[16];
  byte out[16];
  Tea tea;

  if (FLAGS_printall) {
    printf("Tea test\n");
  }
  EXPECT_TRUE(tea.Init(128, tea_test_key, 0));
  tea.Encrypt(8, tea_test_in, out);
  tea.Decrypt(8, out, in);
  if (FLAGS_printall) {
    printf("\tKey            : ");
    PrintBytes(16, tea_test_key);
    printf("\n");
    printf("\tin             : ");
    PrintBytes(8, tea_test_in);
    printf("\n");
    printf("\tcorrect out    : ");
    PrintBytes(8, tea_test_out);
    printf("\n");
    printf("\tEncrypted      : ");
    PrintBytes(8, out);
    printf("\n");
    printf("\tDecrypted      : ");
    PrintBytes(8, in);
    printf("\n");
  }
  EXPECT_TRUE(memcmp(out, tea_test_out, 8) == 0);
  EXPECT_TRUE(memcmp(in, tea_test_in, 8) == 0);
}

uint64_t t_k[2] = {
    0x0706050403020100, 0x0f0e0d0c0b0a0908,
};
uint64_t t_i[2] = {
    0x6373656420737265, 0x6c6c657661727420,
};
uint64_t t_o[2] = {
    0x49681b1e1e54fe3f, 0x65aa832af84e0bbc,
};
byte* simon_test_key = (byte*)t_k;
byte* simon_test_in = (byte*)t_i;
byte* simon_test_out = (byte*)t_o;
TEST(Simon, Simple) {
  byte out[16];
  byte in[16];
  Simon128 simon;

  EXPECT_TRUE(simon.Init(128, simon_test_key, 0));
  uint64_t* o1 = (uint64_t*)out;
  uint64_t* o2 = (uint64_t*)(out + 8);
  uint64_t* i1 = (uint64_t*)in;
  uint64_t* i2 = (uint64_t*)(in + 8);
  simon.Encrypt(16, simon_test_in, out);
  simon.Decrypt(16, out, in);
  if (FLAGS_printall) {
    printf("Simon128 test\n");
    printf("\tKey         : %016llx %016llx\n", t_k[0], t_k[1]);
    printf("\tCorrect in  : %016llx %016llx\n", t_i[0], t_i[1]);
    printf("\tCorrect out : %016llx %016llx\n", t_o[0], t_o[1]);
    printf("\tin          : %016llx %016llx\n", *i1, *i2);
    printf("\tout         : %016llx %016llx\n", *o1, *o2);
    printf("\n");
  }
  EXPECT_TRUE(memcmp(out, simon_test_out, 16) == 0);
  EXPECT_TRUE(memcmp(in, simon_test_in, 16) == 0);
}

byte test_key[] = {
    0x01, 0x02, 0x03, 0x04, 0x51, 0x52, 0x53, 0x54,
    0x91, 0x92, 0x93, 0x94, 0xe1, 0xe2, 0xe3, 0xe4,
};

TEST(FirstAesCase, FirstAesTest) {
  EXPECT_TRUE(SimpleAes128Test());
  EXPECT_TRUE(SimpleAes128NiTest());
  EXPECT_TRUE(aes_benchmark_tests(test_key, 10000, true));
  EXPECT_TRUE(aes_benchmark_tests(test_key, 10000, false));
}
TEST(FirstTwofishCase, FirstTwofishTest) { EXPECT_TRUE(SimpleTwofishTest()); }
TEST(FirstCbcCase, FirstCbcTest) { EXPECT_TRUE(SimpleCbcTest()); }
TEST(FirstCbcEncryptionAlgorithmTest, FirstEncryptionCbcAlgorithmTest) {
  EXPECT_TRUE(SimpleCbcEncryptionAlgorithmTest());
}
TEST(FirstCtrEncryptionAlgorithmTest, FirstEncryptionCtrAlgorithmTest) {
  EXPECT_TRUE(SimpleCtrEncryptionAlgorithmTest());
}

void ReverseInPlace(int size, byte* in) {
  std::shared_ptr<byte>t(new byte[16]);
  ReverseCpy(size, in, t.get());
  memcpy((void*)in, (void*)t.get(), size);
}

byte test_aesgcm_K_1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
byte test_aesgcm_iv_1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
byte test_aesgcm_H_1[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};
byte test_aesgcm_Y0_1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
byte test_aesgcm_EY0_1[16] = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                              0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
byte test_aesgcm_len_1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
byte test_aesgcm_Ghash_1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
byte test_aesgcm_T_1[16] = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                            0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};

TEST(AesGcm, FirstAesGcmTest) {
  AesGcm aesgcm_obj;

  EXPECT_TRUE(aesgcm_obj.Init(NBITSINBYTE * sizeof(test_aesgcm_K_1), test_aesgcm_K_1, 128,
             16, test_aesgcm_iv_1, AesGcm::ENCRYPT, false));
  int size_out = 16;
  byte test_out[16];
  EXPECT_TRUE(aesgcm_obj.FinalPlainIn(0, 0, &size_out, test_out));
  byte tag[32];
  aesgcm_obj.GetComputedTag(16, tag);
  if (FLAGS_printall) {
    printf("Computed tag   : "); PrintBytes(16, tag); printf("\n");
    printf("test_aesgcm_T_1: "); PrintBytes(16, test_aesgcm_T_1); printf("\n");
  }
  EXPECT_TRUE(memcmp(tag, test_aesgcm_T_1, 16) == 0);
}

/*
    cafebabefacedbaddecaf88800000001 // Y0
    3247184b3c4f69a44dbcd22887bbb418 // E(K,Y0)
    cafebabefacedbaddecaf88800000002 // Y1
    9bb22ce7d9f372c1ee2b28722b25f206 // E(K,Y1)
    cafebabefacedbaddecaf88800000003 // Y2
    650d887c3936533a1b8d4e1ea39d2b5c // E(K,Y2)
    cafebabefacedbaddecaf88800000004 // Y3
    3de91827c10e9a4f5240647ee5221f20 // E(K,Y3
    cafebabefacedbaddecaf88800000005  //Y4
    aac9e6ccc0074ac0873b9ba85d908bd0 // E(K,Y4)
    59ed3f2bb1a0aaa07c9f56c6a504647b // X1
    b714c9048389afd9f9bc5c1d4378e052 // X2
    47400c6577b1ee8d8f40b2721e86ff10 // X3
    4796cf49464704b5dd91f159bb1b7f95 // X4
    00000000000000000000000000000200 // len(A)||len(C )
 */

byte test_P_2[64] = {
  0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
  0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
  0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
  0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55,
};
byte test_C_2[64] = {
  0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
  0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
  0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
  0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,0x47,0x3f,0x59,0x85,
};
byte test_aesgcm_K_2[16] = {
  0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
};
byte test_aesgcm_iv_2[16] = {
  0xca, 0xfe, 0xba, 0xbe, 
  0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
  0x00, 0x00, 0x00, 0x01
};
byte test_aesgcm_H_2[16] = {
  0xb8,0x3b,0x53,0x37,0x08,0xbf,0x53,0x5d,0x0a,0xa6,0xe5,0x29,0x80,0xd5,0x3b,0x78,
};
byte test_aesgcm_Ghash_2[16] = {
  0x7f,0x1b,0x32,0xb8,0x1b,0x82,0x0d,0x02,0x61,0x4f,0x88,0x95,0xac,0x1d,0x4e,0xac,
};
byte test_aesgcm_T_2[16] = {
  0x4d,0x5c,0x2a,0xf3,0x27,0xcd,0x64,0xa6,0x2c,0xf3,0x5a,0xbd,0x2b,0xa6,0xfa,0xb4,
};
byte test_aesgcm_X1_2[16] = {
  0x59, 0xed, 0x3f, 0x2b, 0xb1, 0xa0, 0xaa, 0xa0, 0x7c, 0x9f, 0x56, 0xc6, 0xa5, 0x04, 0x64, 0x7b
};

TEST(AesGcm, SecondAesGcmTest) {
  AesGcm aesgcm_obj;

  if (FLAGS_printall) {
    printf("SecondAesGcmTest\n");
  }
  EXPECT_TRUE(aesgcm_obj.Init(NBITSINBYTE * sizeof(test_aesgcm_K_2), test_aesgcm_K_2, 128,
             16, test_aesgcm_iv_2, AesGcm::ENCRYPT, false));
  int size_out = 128;
  byte test_out[128];
  EXPECT_TRUE(aesgcm_obj.FinalPlainIn(sizeof(test_P_2), test_P_2, &size_out, test_out));
  byte tag[16];
  aesgcm_obj.GetComputedTag(16, tag);
  EXPECT_TRUE(memcmp(test_aesgcm_T_2, tag, 16)==0);
  if (FLAGS_printall) {
    printf("Key               : "); PrintBytes(16, test_aesgcm_K_2); printf("\n");
    printf("IV                : "); PrintBytes(16, test_aesgcm_iv_2); printf("\n");
    printf("Plain             : "); PrintBytes(64, test_P_2); printf("\n");
    printf("Cipher            : "); PrintBytes(64, test_out); printf("\n");
    printf("Cipher should be  : "); PrintBytes(64, test_C_2); printf("\n");
    printf("tag               : "); PrintBytes(16, tag); printf("\n");
    printf("tag should be     : "); PrintBytes(16, test_aesgcm_T_2); printf("\n");
    printf("X1  should be     : "); PrintBytes(16, test_aesgcm_X1_2); printf("\n");
    printf("H should be       : "); PrintBytes(16, test_aesgcm_H_2); printf("\n");
    printf("Ghash should be   : "); PrintBytes(16, test_aesgcm_Ghash_2); printf("\n");
    printf("Done\n");
  }
}

byte test_P_3[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
byte test_C_3[16] = {
  0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
};
byte test_aesgcm_K_3[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
byte test_aesgcm_iv_3[16] = {
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
byte test_aesgcm_H_3[16] = {
  0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e
};
byte test_aesgcm_Ghash_3[16] = {
  0xf3,0x8c,0xbb,0x1a,0xd6,0x92,0x23,0xdc,0xc3,0x45,0x7a,0xe5,0xb6,0xb0,0xf8,0x85
};
byte test_aesgcm_T_3[16] = {
  0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
};
byte test_aesgcm_X1_3[16] = {
  0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53, 0xde, 0xb7
};

TEST(AesGcm, ThirdAesGcmTest) {
  AesGcm aesgcm_obj;

  if (FLAGS_printall) {
    printf("ThirdAesGcmTest\n");
  }
  ReverseInPlace(16, test_aesgcm_iv_3);
  EXPECT_TRUE(aesgcm_obj.Init(NBITSINBYTE * sizeof(test_aesgcm_K_3), test_aesgcm_K_3, 128,
             16, test_aesgcm_iv_3, AesGcm::ENCRYPT, false));
  int size_out = 128;
  byte test_out[128];
  EXPECT_TRUE(aesgcm_obj.FinalPlainIn(sizeof(test_P_3), test_P_3, &size_out, test_out));
  byte tag[32];
  aesgcm_obj.GetComputedTag(16, tag);
  EXPECT_TRUE(memcmp(tag, test_aesgcm_T_3, 16) ==0);
  if (FLAGS_printall) {
    printf("Key               : "); PrintBytes(16, test_aesgcm_K_3); printf("\n");
    printf("IV                : "); PrintBytes(16, test_aesgcm_iv_3); printf("\n");
    printf("Plain             : "); PrintBytes(16, test_P_3); printf("\n");
    printf("Cipher            : "); PrintBytes(16, test_out); printf("\n");
    printf("Cipher should be  : "); PrintBytes(16, test_C_3); printf("\n");
    printf("tag               : "); PrintBytes(16, tag); printf("\n");
    printf("tag should be     : "); PrintBytes(16, test_aesgcm_T_3); printf("\n");
    printf("X1  should be     : "); PrintBytes(16, test_aesgcm_X1_3); printf("\n");
    printf("H should be       : "); PrintBytes(16, test_aesgcm_H_3); printf("\n");
    printf("Ghash should be   : "); PrintBytes(16, test_aesgcm_Ghash_3); printf("\n");
    printf("Done\n");
  }
}

TEST(AesGcm, FourthAesGcmTest) {
  AesGcm aesgcm_obj_enc;
  AesGcm aesgcm_obj_dec;
  byte computed_tag[16];
  byte computed_C[64];
  byte computed_P[64];
  int size_out;

  if (FLAGS_printall) {
    printf("FourthAesGcmTest\n");
  }
  EXPECT_TRUE(aesgcm_obj_enc.Init(128, test_aesgcm_K_2, 16,
            16, test_aesgcm_iv_2, AesGcm::ENCRYPT, false));
  size_out = 128;
  EXPECT_TRUE(aesgcm_obj_enc.FinalPlainIn(64, test_P_2, &size_out, computed_C));
  EXPECT_TRUE(memcmp(computed_C, test_C_2, 64)==0);
  aesgcm_obj_enc.GetComputedTag(16, computed_tag);
  if (FLAGS_printall) {
    printf("P          :"); PrintBytes(64, test_P_2); printf("\n");
    printf("Key        :"); PrintBytes(16, test_aesgcm_K_2); printf("\n");
    printf("IV         :"); PrintBytes(16, test_aesgcm_iv_2); printf("\n");
    printf("Tag        :"); PrintBytes(16, test_aesgcm_T_2); printf("\n");
    printf("C          :"); PrintBytes(64, test_C_2); printf("\n");
  }

  EXPECT_TRUE(aesgcm_obj_dec.Init(128, test_aesgcm_K_2, 16,
            16, test_aesgcm_iv_2, AesGcm::ENCRYPT, false));
  aesgcm_obj_dec.SetReceivedTag(16, test_aesgcm_T_2);
  size_out = 128;
  EXPECT_TRUE(aesgcm_obj_dec.FinalCipherIn(64, computed_C, &size_out, computed_P));
  EXPECT_TRUE(memcmp(computed_P, test_P_2, 64)==0);
  EXPECT_TRUE(aesgcm_obj_dec.MessageValid());
}

TEST(AesSiv, AesSivTest) {

  int size_out = 256;
  byte out[256];
  int size_decrypt_out =256;
  byte decrypt_out[256];

  byte Test_Siv_Key[32] = {
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  };
  byte Test_Siv_Hdr[24] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
  };
  byte Test_Siv_Plaintext[14] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
  };
  byte Test_Siv_pad[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x80, 0x00
  };
  byte Test_Siv_CMAC[16] = {
    0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f, 0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93
  };
  byte Test_Siv_output[30] = {
    0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f, 0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
    0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c
  };
  printf("Test_Siv_Key       : "); PrintBytes(sizeof(Test_Siv_Key), Test_Siv_Key); printf("\n");
  printf("Test_Siv_Hdr       : "); PrintBytes(sizeof(Test_Siv_Hdr), Test_Siv_Hdr); printf("\n");
  printf("Test_Siv_Plaintext : "); PrintBytes(sizeof(Test_Siv_Plaintext), Test_Siv_Plaintext); printf("\n");
  printf("Test_Siv_pad       : "); PrintBytes(sizeof(Test_Siv_pad), Test_Siv_pad); printf("\n");
  printf("Test_Siv_CMAC      : "); PrintBytes(sizeof(Test_Siv_CMAC), Test_Siv_CMAC); printf("\n");
  printf("Test_Siv_output    : "); PrintBytes(sizeof(Test_Siv_output), Test_Siv_output); printf("\n");

  AesSiv aes_siv_encrypt;
  EXPECT_TRUE(aes_siv_encrypt.Encrypt(Test_Siv_Key, sizeof(Test_Siv_Hdr), Test_Siv_Hdr,
              sizeof(Test_Siv_Plaintext), Test_Siv_Plaintext, &size_out, out));
  EXPECT_TRUE(memcmp(out, Test_Siv_output, size_out) == 0);
  printf("Computed SIV Encrypt (%d): ", size_out); PrintBytes(size_out, out); printf("\n");

  AesSiv aes_siv_decrypt;
  EXPECT_TRUE(aes_siv_decrypt.Decrypt(Test_Siv_Key, sizeof(Test_Siv_Hdr), Test_Siv_Hdr,
              size_out, out, &size_decrypt_out, decrypt_out));
  printf("Computed SIV Decrypt (%d): ", size_decrypt_out); PrintBytes(size_decrypt_out, decrypt_out); printf("\n");
  EXPECT_TRUE(memcmp(decrypt_out, Test_Siv_Plaintext, size_decrypt_out) == 0);
}

DEFINE_string(log_file, "symmetrictest.log", "symmetrictest file name");

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
  if (!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  cycles_per_second = CalibrateRdtsc();
  printf("Cycles per second on this machine: %llu\n\n", cycles_per_second);
  int result = RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}
