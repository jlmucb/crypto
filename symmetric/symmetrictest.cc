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
// File: symmetric.cc

#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "util.h"
#include "conversions.h"
#include "symmetric_cipher.h"
#include "keys.h"
#include "aes.h"
#include "twofish.h"
#include "encryption_algorithm.h"
#include "aescbchmac256sympad.h"
#include "aesctrhmac256sympad.h"
#include <cmath>


uint64_t  cycles_per_second= 10;


class SymmetricTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void SymmetricTest::SetUp() {
}

void SymmetricTest::TearDown() {
}

byte aes128_test1_plain[]= {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
byte aes128_test1_key[]= {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
byte aes128_test1_cipher[]= {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
 
 
bool SimpleAes128Test() {
  Aes  aes128_object;
  byte test_cipher_out[16];
  byte test_plain_out[16];

  printf("Aes-128 test\n");
  printf("\tKey            : ");
  PrintBytes(16, aes128_test1_key);
  printf("\n");
  printf("\tCorrect plain  : ");
  PrintBytes(16, aes128_test1_plain);
  printf("\n");
  printf("\tCorrect cipher : ");
  PrintBytes(16, aes128_test1_cipher);
  printf("\n");

  if(!aes128_object.Init(128, aes128_test1_key, Aes::BOTH)) {
    printf("Cant init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(aes128_test1_plain, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  printf("\tComputed cipher: ");
  PrintBytes(16, test_cipher_out);
  printf("\n");
  printf("\tComputed plain : ");
  PrintBytes(16, test_plain_out);
  printf("\n");
  if(memcmp(aes128_test1_cipher, test_cipher_out, 16)!=0)
    return false;
  if(memcmp(aes128_test1_plain, test_plain_out, 16)!=0)
    return false;
  return true;
}
 
 
bool SimpleAes128NiTest() {
  AesNi  aes128_object;
  byte   test_cipher_out[16];
  byte   test_plain_out[16];

  if(!HaveAesNi())
    return true;
  printf("AesNi-128 test\n");
  printf("\tKey            : ");
  PrintBytes(16, aes128_test1_key);
  printf("\n");
  printf("\tCorrect plain  : ");
  PrintBytes(16, aes128_test1_plain);
  printf("\n");
  printf("\tCorrect cipher : ");
  PrintBytes(16, aes128_test1_cipher);
  printf("\n");

  if(!aes128_object.Init(128, aes128_test1_key, AesNi::BOTH)) {
    printf("Cant init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(aes128_test1_plain, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  printf("\tComputed cipher: ");
  PrintBytes(16, test_cipher_out);
  printf("\n");
  printf("\tComputed plain : ");
  PrintBytes(16, test_plain_out);
  printf("\n");
  if(memcmp(aes128_test1_cipher, test_cipher_out, 16)!=0)
    return false;
  if(memcmp(aes128_test1_plain, test_plain_out, 16)!=0)
    return false;
  return true;
}

static byte twofish_k128[] = {
0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
};
static byte twofish_p128[] = {
0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
};
static byte twofish_c128[] = {
0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3
};

bool SimpleTwofishTest() {
  Twofish    enc_obj;

  printf("Twofish test\n");
  printf("\tKey: "); PrintBytes(16, twofish_k128); printf("\n");
  if(!enc_obj.Init(128, twofish_k128, 0)) {
    printf("failed initialization\n");
    return false;
  }

  byte   encrypted[16];
  byte   decrypted[16];

  memset(encrypted, 0, 16);
  enc_obj.Encrypt(16, twofish_p128, encrypted);
  printf("\tplaintext: "); PrintBytes(16, twofish_p128); printf("\n");
  printf("\tencrypted: "); PrintBytes(16, encrypted); printf("\n");
  printf("\texpected : "); PrintBytes(16, twofish_c128); printf("\n");

  memset(decrypted, 0, 16);
  enc_obj.Decrypt(16, encrypted, decrypted);
  printf("\tdecrypted: "); PrintBytes(16, decrypted); printf("\n");
  if(memcmp(twofish_p128, decrypted, 16)!=0 || 
     memcmp(twofish_c128, encrypted, 16)!=0) {
    printf("Twofish: decrypted in and encrypted/decrypted text dont match\n");
    return false;
  }
  return true;
}

bool CbcEncryptTest(int size_enc_key, byte* enc_key, int size_int_key, 
                    byte* int_key, int size_iv, byte* iv, int size_in, byte* in,
                    int size_out, byte* out, int size_out2, byte* out2, int size_correct,
                    byte* correct_cipher, bool aes_ni) {
  AesCbcHmac256Sympad encrypt_obj;
  AesCbcHmac256Sympad decrypt_obj;

  if(!encrypt_obj.InitEnc(size_enc_key, enc_key, size_int_key, int_key, 
                          size_iv, iv, aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad encrypt object\n");
    return false;
  }

  if(!decrypt_obj.InitDec(size_enc_key, enc_key, size_int_key, int_key,
                aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad decrypt object\n");
    return false;
  }

#if 1
  printf("\n");
  printf("name: %s\n", encrypt_obj.alg_name_->c_str());
  if(aes_ni) {
    printf("Aes key : ");PrintBytes(16, encrypt_obj.aesni_obj_.key_); printf("\n");
  } else {
    printf("Aes key : ");PrintBytes(16, encrypt_obj.aes_obj_.key_); printf("\n");
  }
  printf("Hmac key: ");PrintBytes(16, encrypt_obj.hmac_.key_); printf("\n");
  printf("input_bytes_processed_: %d, output_bytes_produced_: %d\n",
         encrypt_obj.input_bytes_processed_, 
         encrypt_obj.output_bytes_produced_);
  printf("iv      : ");PrintBytes(16, encrypt_obj.iv_); printf("\n");
  printf("\n");
#endif

  int  encrypt_quantum= encrypt_obj.EncryptInputQuantum();
  int  decrypt_quantum= decrypt_obj.DecryptInputQuantum();
  int  encrypt_max_final= encrypt_obj.MinimumFinalEncryptIn();
  int  decrypt_max_final= decrypt_obj.MinimumFinalDecryptIn();
  int  encrypt_max_additional_output= encrypt_obj.MaxAdditionalOutput();
  int  decrypt_max_additional_final_output= 
                                 decrypt_obj.MaxAdditionalFinalOutput();

  printf("encrypt_quantum: %d, decrypt_quantum: %d\n", 
          encrypt_quantum, decrypt_quantum);
  printf("encrypt_max_additional_output: %d, decrypt_max_additional_final_output: %d\n", 
          encrypt_max_additional_output, decrypt_max_additional_final_output);
  printf("encrypt_max_final: %d, decrypt_max_final: %d\n", 
          encrypt_max_final, decrypt_max_final);

  // bool ProcessInput(int size_in, byte* in, int* size_out, byte* out);
  int new_size_out= size_out2;
  if(!encrypt_obj.FinalPlainIn(size_in, in, &new_size_out, out)) {
    printf("encrypt_obj.FinalPlainIn failed\n");
    return false;
  }
  printf("Plain bytes in: %d, Cipher bytes out: %d\n",
         encrypt_obj.InputBytesProcessed(), encrypt_obj.OutputBytesProduced());
  if(!decrypt_obj.FinalCipherIn(new_size_out, out, &new_size_out, out2)) {
    printf("FinalCipherIn failed\n");
    return false;
  }
  printf("Cipher bytes in: %d, Plain bytes out: %d\n",
         decrypt_obj.InputBytesProcessed(), decrypt_obj.OutputBytesProduced());

  int encrypt_input_bytes_processed= encrypt_obj.InputBytesProcessed();
  int encrypt_output_bytes_produced= encrypt_obj.OutputBytesProduced();
  printf("encrypt_input_bytes_processed: %d, encrypt_input_bytes_produced: %d\n", 
          encrypt_input_bytes_processed, encrypt_output_bytes_produced);
  int decrypt_input_bytes_processed= decrypt_obj.InputBytesProcessed();
  int decrypt_output_bytes_produced= decrypt_obj.OutputBytesProduced();
  printf("decrypt_input_bytes_processed: %d, decrypt_output_bytes_produced: %d\n", 
          decrypt_input_bytes_processed, decrypt_output_bytes_produced);
  if(decrypt_obj.MessageValid()) {
    printf("decrypt object valid\n");
  }
  else {
    printf("message invalid\n");
  }
  if(decrypt_obj.output_bytes_produced_!=size_in || memcmp(in, out2, size_in)!=0) {
    printf("bad comparison, sizein: %d, new sizein: %d\n", size_in, new_size_out);
    printf("in : ");
    PrintBytes(size_in, in);
    printf("\n");
    printf("out: ");
    PrintBytes(encrypt_obj.output_bytes_produced_, out);
    printf("\n");
    printf("out2: ");
    PrintBytes(decrypt_obj.output_bytes_produced_, out2);
    printf("\n");
    return false;
  }
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
  if(memcmp(out+16, correct_cipher, size_correct)==0)
    printf("cipher matches\n");
  else
    return false;
  return true;
}

bool CtrEncryptTest(int size_enc_key, byte* enc_key, int size_int_key, 
                    byte* int_key, byte* nonce, byte* iv, int size_in, byte* in,
                    int size_out, byte* out, int size_out2, byte* out2, int size_correct,
                    byte* correct_cipher, bool aes_ni) {
  AesCtrHmac256Sympad encrypt_obj;
  AesCtrHmac256Sympad decrypt_obj;

  if(!encrypt_obj.Init(size_enc_key, enc_key, size_int_key, int_key, 
                          4, nonce, 8, iv, aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad encrypt object\n");
    return false;
  }

  if(!decrypt_obj.Init(size_enc_key, enc_key, size_int_key, int_key,
                          4, nonce, 8, iv, aes_ni)) {
    printf("Cant initialize AesCbcHmac256Sympad decrypt object\n");
    return false;
  }

#if 1
  printf("\n");
  printf("name: %s\n", encrypt_obj.alg_name_->c_str());
  if(aes_ni) {
    printf("Aes key : ");PrintBytes(16, encrypt_obj.aesni_obj_.key_); printf("\n");
  } else {
    printf("Aes key : ");PrintBytes(16, encrypt_obj.aes_obj_.key_); printf("\n");
  }
  printf("Hmac key: ");PrintBytes(16, encrypt_obj.hmac_.key_); printf("\n");
  printf("input_bytes_processed_: %d, output_bytes_produced_: %d\n",
         encrypt_obj.input_bytes_processed_, 
         encrypt_obj.output_bytes_produced_);
  printf("\n");
#endif

  int  encrypt_quantum= encrypt_obj.EncryptInputQuantum();
  int  decrypt_quantum= decrypt_obj.DecryptInputQuantum();
  int  encrypt_max_final= encrypt_obj.MinimumFinalEncryptIn();
  int  decrypt_max_final= decrypt_obj.MinimumFinalDecryptIn();
  int  encrypt_max_additional_output= encrypt_obj.MaxAdditionalOutput();
  int  decrypt_max_additional_final_output= 
                                 decrypt_obj.MaxAdditionalFinalOutput();

  printf("encrypt_quantum: %d, decrypt_quantum: %d\n", 
          encrypt_quantum, decrypt_quantum);
  printf("encrypt_max_additional_output: %d, decrypt_max_additional_final_output: %d\n", 
          encrypt_max_additional_output, decrypt_max_additional_final_output);
  printf("encrypt_max_final: %d, decrypt_max_final: %d\n", 
          encrypt_max_final, decrypt_max_final);

  // bool ProcessInput(int size_in, byte* in, int* size_out, byte* out);
  int new_size_out= size_out2;
  if(!encrypt_obj.FinalPlainIn(size_in, in, &new_size_out, out)) {
    printf("encrypt_obj.FinalPlainIn failed\n");
    return false;
  }
  if(!decrypt_obj.FinalCipherIn(new_size_out, out, &new_size_out, out2)) {
    printf("FinalCipherIn failed\n");
    return false;
  }

  int encrypt_input_bytes_processed= encrypt_obj.InputBytesProcessed();
  int encrypt_output_bytes_produced= encrypt_obj.OutputBytesProduced();
  printf("encrypt_input_bytes_processed: %d, encrypt_output_bytes_produced: %d\n", 
          encrypt_input_bytes_processed, encrypt_output_bytes_produced);
  int decrypt_input_bytes_processed= decrypt_obj.InputBytesProcessed();
  int decrypt_output_bytes_produced= decrypt_obj.OutputBytesProduced();
  printf("decrypt_input_bytes_processed: %d, decrypt_output_bytes_produced: %d\n", 
          decrypt_input_bytes_processed, decrypt_output_bytes_produced);
  if(decrypt_obj.MessageValid()) {
    printf("decrypt object valid\n");
  }
  else {
    printf("decrypt object invalid\n");
  }
  if(decrypt_obj.output_bytes_produced_!=size_in || memcmp(in, out2, size_in)!=0) {
    printf("bad comparison, sizein: %d, new sizein: %d\n", size_in, new_size_out);
    printf("in : ");
    PrintBytes(size_in, in);
    printf("\n");
    printf("out: ");
    PrintBytes(encrypt_obj.output_bytes_produced_, out);
    printf("\n");
    printf("out: ");
    PrintBytes(decrypt_obj.output_bytes_produced_, out2);
    printf("\n");
    return false;
  }
  printf("in              : ");
  PrintBytes(size_in, in);
  printf("\n");
  printf("out             : ");
  PrintBytes(encrypt_output_bytes_produced, out);
  printf("\n");
  printf("out2            : ");
  PrintBytes(decrypt_obj.output_bytes_produced_, out2);
  printf("\n");
  if(memcmp(in, out2, size_in)==0)
    printf("cipher matches\n");
  else
    return false;
  return true;
}

// CTR
byte aes128CTRTestKey1[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
byte aes128CTRTestCounterBlock[32] = {
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x00 
};
byte aes128CTRTestPlain[32] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 
};
byte aes128CTRTestCipher[32] = {
  0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
  0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
  0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
  0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff 
};

// CBC
byte aes128CBCTestKey1[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
byte aes128CBCTestIV1[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
byte aes128CBCTestPlain1a[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
                                 0x2a};
byte aes128CBCTestCipher1a[16] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2,
                                  0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
                                  0x19, 0x7d};
byte aes128CBCTestPlain1b[16] = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
                                 0x51};
byte aes128CBCTestCipher1b[16] = {0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19,
                                  0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
                                  0x78, 0xb2};
byte aes128CBCTestPlain1c[16] = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52,
                                 0xef};
byte aes128CBCTestCipher1c[16] = {0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74,
                                  0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22,
                                  0x95, 0x16};
byte aes128CBCTestPlain1d[16] = {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37,
                                 0x10};
byte aes128CBCTestCipher1d[16] = {0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac,
                                  0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86,
                                  0xe1, 0xa7};


bool SimpleCbcTest() {
  int   num_out= 512;
  byte  out_buf[512];
  int   num_out2= 512;
  byte  out_buf2[512];
  bool  use_aesni= HaveAesNi();

  printf("CbcEncryptTest\n");
  if(!CbcEncryptTest(sizeof(aes128CBCTestKey1), aes128CBCTestKey1,
                     sizeof(aes128CBCTestKey1), aes128CBCTestKey1,
                     sizeof(aes128CBCTestIV1), aes128CBCTestIV1, 
                     sizeof(aes128CBCTestPlain1a), aes128CBCTestPlain1a,
                     num_out, out_buf, num_out2, out_buf2,
                     16, aes128CBCTestCipher1a, use_aesni)) {
    printf("CbcEncryptTest failed\n");
    return false;
  }
  return true;
}


byte encryption_algorithm_test_iv[] = {
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f
};
byte encryption_algorithm_hmac_key[] = {
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f
};
byte encryption_algorithm_enc_key[] = {
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x0c, 0x0d, 0x0e, 0x0f,
  0x08, 0x09, 0x0a, 0x0b
};

bool AesNi128Compare(int size_key, byte* key, int size_in, byte* in)
{
  AesNi  aes128_object;
  byte   test_cipher_out[16];
  byte   test_plain_out[16];

  if(!aes128_object.Init(128, key, Aes::BOTH)) {
    printf("Aes128Compare: Cant init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(in, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  if(memcmp(in, test_plain_out, 16)!=0) {
    printf("AesCompare: Aes-128 test\n");
    aes128_object.EncryptBlock(in, test_cipher_out);
    aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
    printf("\tKey            : ");
    PrintBytes(size_key, key);
    printf("\n");
    printf("\tPlain          : ");
    PrintBytes(16, in);
    printf("\n");
    printf("\tComputed plain : ");
    PrintBytes(16, test_plain_out);
    printf("\n");
    return false;
  }
  return true;
}

bool Aes128Compare(int size_key, byte* key, int size_in, byte* in) {
  Aes    aes128_object;
  byte   test_cipher_out[16];
  byte   test_plain_out[16];

  if(!aes128_object.Init(128, key, Aes::BOTH)) {
    printf("Aes128Compare: Cant init aes object\n");
    return false;
  }
  aes128_object.EncryptBlock(in, test_cipher_out);
  aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
  if(memcmp(in, test_plain_out, 16)!=0) {
    printf("AesCompare: Aes-128 test\n");
    aes128_object.EncryptBlock(in, test_cipher_out);
    aes128_object.DecryptBlock(test_cipher_out, test_plain_out);
    printf("\tKey            : ");
    PrintBytes(size_key, key);
    printf("\n");
    printf("\tPlain          : ");
    PrintBytes(16, in);
    printf("\n");
    printf("\tComputed plain : ");
    PrintBytes(16, test_plain_out);
    printf("\n");
    return false;
  }
  return true;
}

bool CbcCompare(int size_enc_key, byte* enc_key, int size_int_key, 
                    byte* int_key, int size_iv, byte* iv, int size_in, 
                    byte* in, bool use_aesni) {
  AesCbcHmac256Sympad encrypt_obj;
  AesCbcHmac256Sympad decrypt_obj;

  if(!encrypt_obj.InitEnc(size_enc_key, enc_key, size_int_key, int_key, 
                          size_iv, iv, use_aesni)) {
    printf("CbcCompare: Cant initialize AesCbcHmac256Sympad encrypt object\n");
    return false;
  }

  if(!decrypt_obj.InitDec(size_enc_key, enc_key, size_int_key, int_key,
                use_aesni)) {
    printf("CbcCompare: Cant initialize AesCbcHmac256Sympad decrypt object\n");
    return false;
  }

  byte*   cipher= new byte[size_enc_key+128];
  byte*   computeplain= new byte[size_enc_key+128];
  bool    fRet= true;
  int     encrypt_input_bytes_processed;
  int     encrypt_output_bytes_produced;
  int     decrypt_input_bytes_processed;
  int     decrypt_output_bytes_produced;

  int cipher_size= size_enc_key+128;
  int plain_size= size_enc_key+128;

  if(!encrypt_obj.FinalPlainIn(size_in, in, &cipher_size, cipher)) {
    printf("encrypt_obj.FinalPlainIn failed\n");
    fRet= false;
    goto done;
  }
  if(!decrypt_obj.FinalCipherIn(cipher_size, cipher, &plain_size, computeplain)) {
    printf("FinalCipherIn failed\n");
    fRet= false;
    goto done;
  }

  encrypt_input_bytes_processed= encrypt_obj.InputBytesProcessed();
  encrypt_output_bytes_produced= encrypt_obj.OutputBytesProduced();
  decrypt_input_bytes_processed= decrypt_obj.InputBytesProcessed();
  decrypt_output_bytes_produced= decrypt_obj.OutputBytesProduced();

  if(!decrypt_obj.MessageValid()) {
    printf("decrypt object invalid\n");
    fRet= false;
    goto done;
  }
  if(size_in!=decrypt_output_bytes_produced) {
    printf("input size does not match output size\n");
    fRet= false;
    goto done;
  }
  if(memcmp(in, computeplain, size_in)!=0) {
    printf("input does not match output\n");
    fRet= false;
    goto done;
  }

done:
  if(!fRet) {
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
  }
  delete cipher;
  delete computeplain;
  return fRet;
}


bool SimpleCbcEncryptionAlgorithmTest() {
  AesCbcHmac256Sympad                 encryption_algorithm;
  crypto_encryption_algorithm_message message;
  byte                                in[AesNi::BLOCKBYTESIZE];
  byte                                out[512];
  byte                                out2[512];
  bool                                use_aesni= HaveAesNi();

  encryption_algorithm.message_id_= new string("message-103");
  encryption_algorithm.initialized_= true;
  encryption_algorithm.use_aesni_= use_aesni;
  if(use_aesni) {
    if(!encryption_algorithm.aesni_obj_.Init(128, aes128CBCTestKey1, Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  } else {
    if(!encryption_algorithm.aes_obj_.Init(128, aes128CBCTestKey1, Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  }
  memcpy(encryption_algorithm.hmac_.key_, encryption_algorithm_hmac_key, HmacSha256::BLOCKBYTESIZE);
  memcpy(encryption_algorithm.iv_, aes128CBCTestIV1, AesNi::BLOCKBYTESIZE);
  EncryptionAlgorithm* encryption_algorithm_pointer= 
                (EncryptionAlgorithm*) &encryption_algorithm;
  if(!encryption_algorithm_pointer->SerializeEncryptionAlgorithmToMessage(message)) {
    LOG(ERROR) << "can't serialize encryption_algorithm to message\n";
    return false;
  }
#if 0
  string sbuf= message.DebugString();
  printf("Buffer string: %s\n", sbuf.c_str());
#endif
  AesCbcHmac256Sympad* new_encryption_algorithm= new AesCbcHmac256Sympad();
  crypto_encryption_algorithm_message new_message;
  if(!((EncryptionAlgorithm*) new_encryption_algorithm)
                       ->DeserializeEncryptionAlgorithmFromMessage(message)) {
    LOG(ERROR) << "can't deserialize encryption_algorithm from message\n";
    return false;
  }
  printf("\nCbcEncryptTest using desserialized state\n");
  new_encryption_algorithm->PrintEncryptionAlgorithm();
  memcpy(in, aes128CBCTestPlain1a, AesNi::BLOCKBYTESIZE);
  byte* cbc_aes_key;
  if(use_aesni)
    cbc_aes_key= encryption_algorithm.aesni_obj_.key_;
  else
    cbc_aes_key= encryption_algorithm.aes_obj_.key_;
  if(!CbcEncryptTest(AesNi::BLOCKBYTESIZE, cbc_aes_key,
                     AesNi::BLOCKBYTESIZE, encryption_algorithm.iv_, 
                     AesNi::BLOCKBYTESIZE, encryption_algorithm.iv_, 
                     AesNi::BLOCKBYTESIZE, in,
                     512, out, 512, out2, AesNi::BLOCKBYTESIZE, 
                     aes128CBCTestCipher1a, use_aesni)) {
    printf("CbcEncryptTest failed\n");
    return false;
  } else {
    printf("CbcEncryptTest succeeded\n");
  }
  return true;
}

bool SimpleCtrEncryptionAlgorithmTest() {
  AesCbcHmac256Sympad                 encryption_algorithm;
  crypto_encryption_algorithm_message message;
  byte                                in[AesNi::BLOCKBYTESIZE];
  byte                                out[512];
  byte                                out2[512];
  bool                                use_aesni= HaveAesNi();

  printf("SimpleCtrEncryptionAlgorithmTest\n");
  encryption_algorithm.message_id_= new string("message-104");
  encryption_algorithm.initialized_= true;
  encryption_algorithm.use_aesni_= use_aesni;
  if(use_aesni) {
    if(!encryption_algorithm.aesni_obj_.Init(128, aes128CBCTestKey1, Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  } else {
    if(!encryption_algorithm.aes_obj_.Init(128, aes128CBCTestKey1, Aes::ENCRYPT)) {
      LOG(ERROR) << "can't init aes object\n";
      return false;
    }
  }
  memcpy(encryption_algorithm.hmac_.key_, encryption_algorithm_hmac_key, HmacSha256::BLOCKBYTESIZE);
  EncryptionAlgorithm* encryption_algorithm_pointer= 
                (EncryptionAlgorithm*) &encryption_algorithm;
  if(!encryption_algorithm_pointer->SerializeEncryptionAlgorithmToMessage(message)) {
    LOG(ERROR) << "can't serialize encryption_algorithm to message\n";
    return false;
  }
#if 0
  string sbuf= message.DebugString();
  printf("Buffer string: %s\n", sbuf.c_str());
#endif
  AesCtrHmac256Sympad* new_encryption_algorithm= new AesCtrHmac256Sympad();
  crypto_encryption_algorithm_message new_message;
  if(!((EncryptionAlgorithm*) new_encryption_algorithm)
                       ->DeserializeEncryptionAlgorithmFromMessage(message)) {
    LOG(ERROR) << "can't deserialize encryption_algorithm from message\n";
    return false;
  }
  new_encryption_algorithm->PrintEncryptionAlgorithm();
  memcpy(in, aes128CBCTestPlain1a, AesNi::BLOCKBYTESIZE);
  byte* ctr_aes_key;
  if(use_aesni)
    ctr_aes_key= encryption_algorithm.aesni_obj_.key_;
  else
    ctr_aes_key= encryption_algorithm.aes_obj_.key_;
  if(!CtrEncryptTest(AesNi::BLOCKBYTESIZE, aes128CTRTestKey1,
                     HmacSha256::BLOCKBYTESIZE, encryption_algorithm.hmac_.key_,
                     aes128CTRTestCounterBlock, &aes128CTRTestCounterBlock[4],
                     32, aes128CTRTestPlain, 128, out, 128, out2, 128, 
                     aes128CTRTestCipher, use_aesni)) {
    printf("CtrEncryptTest failed\n");
    return false;
  } else {
    printf("CtrEncryptTest succeeded\n");
  }
  return true;
}


byte      my_keys[1024];
byte      my_test[1024];

void init_test() {
  int j;
  for(j=0;j<1024;j++) {
    my_keys[j]= (byte)j;
    my_test[j]= (byte)j;
  }
}

bool RunTestSuite() {
  int   i, j, k, m, n;
  bool  use_aesni= HaveAesNi();

  for(i= 0; i<750; i++) {
    for(j= 0; j< 750; j++) {
      if(!Aes128Compare(16, &my_keys[j], 16, &my_test[i]))
        return false;
      if(use_aesni)
        if(!AesNi128Compare(16, &my_keys[j], 16, &my_test[i]))
          return false;
    }
  }
  for(i= 0; i<8; i++) {
    for(j= 0; j<8; j++) {
      for(k= 0; k<4; k++) {
        for(m= 0; m<32; m++) {
          for(n= 0; n<32; n++) {
            if(!CbcCompare(16, &my_keys[i], 16, &my_keys[j],
                           16, &my_keys[k], m, &my_test[n], use_aesni)) 
              return false;
          }
        }
      }
    }
  }
  return true;
}

bool aes_benchmark_tests(byte* key, int num_tests, bool use_aesni) {
printf("\nAES_TIME_TESTS\n");
  byte      in[64];
  byte      out[64];
  int       num_tests_executed= 0;
  use_aesni&= HaveAesNi();
  
  uint64_t  cycles_start_test;
  if(use_aesni) {
    AesNi   aes;
    if(!aes.Init(128, key, Aes::ENCRYPT)) {
      cycles_start_test= 0;
      printf("AesNi failed Init()\n");
    } else {
      cycles_start_test= ReadRdtsc();
      for(num_tests_executed=0; num_tests_executed<num_tests;num_tests_executed++) {
        aes.EncryptBlock(in, out);
      }
    }
  } else {
    Aes     aes;
    if(!aes.Init(128, key, Aes::ENCRYPT)) {
      cycles_start_test= 0;
      printf("Aes failed Init()\n");
    } else {
      cycles_start_test= ReadRdtsc();
      for(num_tests_executed=0; num_tests_executed<num_tests;num_tests_executed++) {
        aes.EncryptBlock(in, out);
      }
    }
  }
  uint64_t  cycles_end_test= ReadRdtsc();
  uint64_t  cycles_diff= cycles_end_test-cycles_start_test;
  if(use_aesni) {
    printf("using aesni, ");
  } else {
    printf("not using aesni, ");
  }
  printf("aes_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n", ((double)cycles_diff)/((double)cycles_per_second));
  printf("time per block %le\n", 
                 ((double)cycles_diff)/((double)(num_tests_executed*cycles_per_second)));
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

byte test_key[]= {
  0x01, 0x02, 0x03, 0x04, 
  0x51, 0x52, 0x53, 0x54, 
  0x91, 0x92, 0x93, 0x94, 
  0xe1, 0xe2, 0xe3, 0xe4, 
};

TEST(FirstAesCase, FirstAesTest) {
  EXPECT_TRUE(SimpleAes128Test());
  EXPECT_TRUE(SimpleAes128NiTest());
  EXPECT_TRUE(aes_benchmark_tests(test_key, 10000, true));
  EXPECT_TRUE(aes_benchmark_tests(test_key, 10000, false));
}
TEST(FirstTwofishCase, FirstTwofishTest) {
  EXPECT_TRUE(SimpleTwofishTest());
}
TEST(FirstCbcCase, FirstCbcTest) {
  EXPECT_TRUE(SimpleCbcTest());
}
TEST(FirstCbcEncryptionAlgorithmTest, FirstEncryptionCbcAlgorithmTest) {
  EXPECT_TRUE(SimpleCbcEncryptionAlgorithmTest());
}
TEST(FirstCtrEncryptionAlgorithmTest, FirstEncryptionCtrAlgorithmTest) {
  EXPECT_TRUE(SimpleCtrEncryptionAlgorithmTest());
}
TEST(RunTestSuite, RunTestSuite) {
  EXPECT_TRUE(RunTestSuite());
}

DEFINE_string(log_file, "symmetrictest.log", "symmetrictest file name");

int main(int an, char** av) {

  ::testing::InitGoogleTest(&an, av);
  if(!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  cycles_per_second= CalibrateRdtsc();
  printf("Cycles per second on this machine: %lld\n\n", cycles_per_second);
  int result= RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}


