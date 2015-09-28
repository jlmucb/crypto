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
// File: cryptutil.cc

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <string>
#include <iostream>
#include <fstream>
#include <memory>

#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "hash.h"
#include "sha1.h"
#include "sha256.h"
#include "sha3.h"
#include "util.h"
#include "conversions.h"
#include "keys.h"
#include "keys.pb.h"
#include "hmac_sha256.h"
#include "aes.h"
#include "twofish.h"
#include "rc4.h"
#include "tea.h"
#include "simonspeck.h"
#include "encryption_algorithm.h"
#include "aescbchmac256sympad.h"
#include "aesctrhmac256sympad.h"
#include "aesgcm.h"
#include "pkcs.h"
#include "pbkdf.h"
#include "bignum.h"

using std::string;

int num_cryptutil_ops = 28;
std::string cryptutil_ops[] = {
    "--operation=ToBase64 --direction=[left-right|right-left] " \
    "--input_file=file --output_file=file",
    "--operation=FromBase64 --direction=[left-right|right-left] " \
    "--input_file=file --output_file=file",
    "--operation=ToHex --direction=[left-right|right-left] --input_file=file " \
    "--output_file=file",
    "--operation=FromHex --direction=[left-right|right-left] --input_file=file " \
    "--output_file=file",
    "--operation=ToDecimal --direction=[left-right|right-left] " \
    "--input_file=file",
    "--operation=FromDecimal --direction=[left-right|right-left] " \
    "--input_file=file --output_file=file",
    "--operation=Hash --algorithm=alg --input_file=file",
    "--operation=Mac --algorithm=alg --key_file=file --input_file=file " \
    "--output_file=file",
    "--operation=GetRandom --size=num-bits --output_file=file",
    "--operation=GenerateKey --algorithm=alg --key_name=name " \
    "--purpose=pur --owner=own --duration=dur --output_file=file",
    "--operation=ReadKey --algorithm=alg --key_name=name " \
    "--duration=dur --input_file=file",
    "--operation=EncryptWithKey --key_file=key_file --algorithm=alg " \
    "--input_file=file --output_file=file",
    "--operation=DecryptWithKey --key_file=key_file --algorithm=alg " \
    "--input_file=file --output_file=file",
    "--operation=GenerateScheme --algorithm=alg --key_name=name " \
    "--duration=dur --output_file=file",
    "--operation=ReadScheme --algorithm=alg --key_name=name" \
    " --duration=dur --input_file=file",
    "--operation=EncryptWithScheme --scheme_file=scheme_file " \
    "--algorithm=alg --input_file=file --output_file=file",
    "--operation=DecryptWithScheme --scheme_file=scheme_file" \
    " --algorithm=alg --input_file=file --output_file=file",
    "--operation=PkcsSignWithKey --algorithm=alg --keyfile=file " \
    "--hash_file= file --input_file=file --output_file=file",
    "--operation=PkcsVerifyWithKey --algorithm=alg --keyfile=file " \
    "--hash_file= file --sig_file= file",
    "--operation=PkcsPubUnsealWithKey --keyfile=file --algorithm=alg " \
    "--input_file=file --output_file=file",
    "--operation=PkcsPubSealWithKey --keyfile=file --algorithm=alg " \
    "--input_file=file --output_file=file",
    "--operation=EncryptWithPassword --algorithm=aes128-ctr-hmacsha256-sympad " \
    "--pass=password --input_file=file --output_file=file",
    "--operation=DecryptWithPassword --algorithm=aes128-ctr-hmacsha256-sympad " \
    "--pass=password --input_file=file --output_file=file",
    "--operation=VerifyMac --algorithm=alg --keyfile=file --input_file=file " \
    "--input2_file=file",
    "--operation=ToHexBuf --direction=[left-right|right-left] --input_file=file " \
    "--output_file=file",
    "--operation=FromHexBuf --direction=[left-right|right-left] --input_file=file " \
    "--output_file=file",
};

const int num_cryptutil_algs = 23;
std::string cryptalgs[] = {
    "aes-128", "aes-256", "rsa-128", "rsa-256", "rsa-512", "rsa-1024",
    "rsa-2048", "rsa-3072", "ecc-256", "sha-1", "sha-256", "sha-3",
    "hmac-sha-256", "PBKDF-128", "aes-128-sha-256-hmac-sha256",
    "rsa-1024-sha-256-pkcs", "rsa-2048-sha-256-pkcs", "twofish-128",
    "twofish-256", "rc4-128", "tea-128", "simon-128", "aes128-gcm128"};

void print_options() {
  printf("Permitted operations:\n");
  for (int i = 0; i < num_cryptutil_ops; i++) {
    printf("  cryptutil.exe %s\n", cryptutil_ops[i].c_str());
  }
  printf("\nAlgs:\n");
  for (int i = 0; i < num_cryptutil_algs; i++) {
    printf("  %s\n", cryptalgs[i].c_str());
  }
  return;
}

DEFINE_string(operation, "", "operations");
DEFINE_string(key_file, "", "Key file name");
DEFINE_string(scheme_file, "", "Scheme file name");
DEFINE_string(key_name, "", "Key name");
DEFINE_string(input_file, "", "Input file name");
DEFINE_string(input2_file, "", "Second input file name");
DEFINE_string(output_file, "", "Output file name");
DEFINE_string(direction, "left-right",
              "string value direction left-right or right-left");
DEFINE_string(algorithm, "sha256", "hash algorithm");
DEFINE_string(duration, "1Y", "duration");
DEFINE_string(pass, "password", "password");
DEFINE_string(purpose, "channel-encryption", "purpose");
DEFINE_string(owner, "NoOne", "purpose");
DEFINE_int32(size, 128, "size");
DEFINE_string(hash_file, "", "file to hash");
DEFINE_string(hash_alg, "sha-256", "hash alg");
DEFINE_string(sig_file, "", "signature");
DEFINE_string(protecedkeyfile, "", "protected key file");
DEFINE_string(unprotecedkeyfile, "", "unprotected key file");

#define BUFSIZE 2048
#define MAXMACSIZE 512

bool calculatefileMac(const char* filename, const char* alg, int key_size,
                      byte* key, int* out_size, byte* out) {
  ReadFile reader;

  if (!reader.Init(filename)) {
    printf("can't open %s\n", filename);
    return false;
  }
  int n;
  byte buf[BUFSIZE];

  if (strcmp("hmac-sha-256", alg) == 0) {
    HmacSha256 the_mac;

    if (*out_size < the_mac.MACBYTESIZE) {
      printf("calculatefileMac: output buffer provided is too small\n");
      return false;
    }
    *out_size = the_mac.MACBYTESIZE;

    the_mac.Init(key_size, key);
    for (;;) {
      n = reader.Read(BUFSIZE, buf);
      the_mac.AddToInnerHash(n, buf);
      if (n <= 0) break;
    }
    the_mac.Final();
    the_mac.GetHmac(*out_size, out);
  } else {
    printf("calculatefileMac: unsupported algorithm\n");
    return false;
  }
  return true;
}

void macFile(const char* filename, const char* alg, int key_size, byte* key,
             const char* out_filename) {
  if (filename == nullptr) {
    printf("macFile: No filename\n");
    return;
  }
  byte out[MAXMACSIZE];
  int out_size = MAXMACSIZE;
  if (!calculatefileMac(filename, alg, key_size, key, &out_size, out)) {
    printf("Can't calculate mac\n");
    return;
  }
  printf("mac: ");
  PrintBytes(out_size, out);
  printf("\n");
  if (out_filename != nullptr) {
    WriteaFile(out_filename, out_size, out);
  }
}

void verifymacFile(const char* filename, const char* alg, int key_size,
                   byte* key, const char* mac_filename) {
  if (mac_filename == nullptr) {
    printf("macFile: No mac filename\n");
    return;
  }
  byte* input_mac = nullptr;
  int input_mac_size = MAXMACSIZE;
  if (!ReadaFile(mac_filename, &input_mac_size, &input_mac)) {
    printf("Can't open input mac file %s\n", mac_filename);
    return;
  }

  if (filename == nullptr) {
    printf("macFile: No filename\n");
    return;
  }

  byte out[MAXMACSIZE];
  int out_size = MAXMACSIZE;

  if (!calculatefileMac(filename, alg, key_size, key, &out_size, out)) {
    printf("verifymacFile: Can't calculate mac\n");
    return;
  }
  printf("input    mac: ");
  PrintBytes(input_mac_size, input_mac);
  printf("\n");
  printf("computed mac: ");
  PrintBytes(out_size, out);
  printf("\n");
  if (input_mac_size == out_size &&
      memcmp(input_mac, out, input_mac_size) == 0) {
    printf("Mac VERIFIES\n");
  } else {
    printf("Mac DOES NOT verify\n");
  }
}

void hashFile(const char* name, const char* alg, int* size_out, byte* hash) {
  if (name == nullptr) {
    printf("hashFile: No filename\n");
    return;
  }
  ReadFile reader;

  if (!reader.Init(name)) {
    printf("can't open %s\n", name);
    return;
  }
  int n;
  byte buf[BUFSIZE];

  if (strcmp("sha-1", alg) == 0) {
    Sha1 the_hash;

    the_hash.Init();
    for (;;) {
      n = reader.Read(BUFSIZE, buf);
      the_hash.AddToHash(n, buf);
      if (n <= 0) break;
    }
    reader.Close();
    the_hash.Final();
    byte out[the_hash.DIGESTBYTESIZE];
    the_hash.GetDigest(the_hash.DIGESTBYTESIZE, out);
    printf("hash: ");
    PrintBytes(the_hash.DIGESTBYTESIZE, out);
    printf("\n");
    if (size_out != nullptr && hash != nullptr && *size_out >= 20) {
      *size_out = 20;
      memcpy(hash, out, *size_out);
    }
  } else if (strcmp("sha-256", alg) == 0) {
    Sha256 the_hash;

    the_hash.Init();
    for (;;) {
      n = reader.Read(BUFSIZE, buf);
      the_hash.AddToHash(n, buf);
      if (n <= 0) break;
    }
    the_hash.Final();
    byte out[the_hash.DIGESTBYTESIZE];
    the_hash.GetDigest(the_hash.DIGESTBYTESIZE, out);
    printf("hash: ");
    PrintBytes(the_hash.DIGESTBYTESIZE, out);
    printf("\n");
    if (size_out != nullptr && hash != nullptr && *size_out >= 32) {
      *size_out = 32;
      memcpy(hash, out, *size_out);
    }
  } else if (strcmp("sha-3", alg) == 0) {
    Sha3 the_hash(1024);

    the_hash.Init();
    for (;;) {
      n = reader.Read(BUFSIZE, buf);
      the_hash.AddToHash(n, buf);
      if (n <= 0) break;
    }
    the_hash.Final();
    byte out[256];
    the_hash.GetDigest(128, out);
    printf("hash: ");
    PrintBytes(128, out);
    printf("\n");
    if (size_out != nullptr && hash != nullptr && *size_out >= 128) {
      *size_out = 128;
      memcpy(hash, out, *size_out);
    }
  } else {
    printf("%s: no such alg\n", alg);
  }
}

bool keysFromPassPhrase(const char* phrase, int* size, byte* key) {
  Sha256 the_hash;

  if (*size < 32) {
    printf("keysFromPassPhrase (%d): buffer too small, %s\n", *size, phrase);
  }
  // TODO: change to hkdf later
  the_hash.Init();
  const char* salt = "JLM1";
  the_hash.AddToHash(strlen(salt), (byte*)salt);
  the_hash.AddToHash(strlen(phrase), (byte*)phrase);
  the_hash.Final();
  the_hash.GetDigest(the_hash.DIGESTBYTESIZE, key);
  *size = the_hash.DIGESTBYTESIZE;
  return true;
}

const char* extractString(int size, byte* in) {
  int i;
  char* out = new char[size + 1];

  memset(out, 0, size + 1);
  for (i = 0; i < size; i++) {
    out[i] = in[i];
    if (in[i] == (byte)'\n' || in[i] == (byte)'\r' || in[i] == (byte)'\t' ||
        in[i] == 0) {
      in[i] = 0;
      char* str = strdup(out);
      delete out;
      return str;
    }
  }
  in[i] = 0;
  char* str = strdup(out);
  delete out;
  return str;
}

double convertDuration(const char* code) {
  double seconds = COMMON_YEAR_SECONDS;
  char dur[16];
  int i;
  int n = 1;

  for (i = 0; i < 10; i++) {
    if (code[i] >= '0' && code[i] <= '9') {
      dur[i] = code[i];
    } else if (code[i] == 'Y') {
      dur[i] = 0;
      n = atoi(dur);
      break;
    } else {
      break;
    }
  }
  return ((double)n) * seconds;
}

bool EncryptKeyWithPassword(const char* pass, int size, byte* in,
                            const char* outFile) {
  bool correct = true;
  int encrypted_size = 2 * size + 64;
  byte* decrypted_key = new byte[encrypted_size];
  byte* encrypted_buf = new byte[encrypted_size];

  if (!keysFromPassPhrase(pass, &encrypted_size, decrypted_key)) return false;
  Aes key_encrypt;
  if (!key_encrypt.Init(128, decrypted_key, Aes::ENCRYPT)) {
    printf("key_encrypt.Init failed in EncryptKeyWithPassword\n");
    correct = false;
  }
  if (correct) {
    key_encrypt.Encrypt(size, in, encrypted_buf);
    WriteaFile(outFile, size, encrypted_buf);
  }
  delete encrypted_buf;
  delete decrypted_key;
  return correct;
}

bool DecryptKeyWithPassword(const char* pass, const char* inFile, int* size,
                            byte** out) {
  bool correct = true;
  int encrypted_size = 0;
  byte* decrypted_key = new byte[2 * encrypted_size];
  byte* encrypted_buf = nullptr;

  if (!ReadaFile(inFile, &encrypted_size, &encrypted_buf)) {
    printf("ReadaFile failed in DecryptKeyWithPassword\n");
    return false;
  }
  int decrypted_size = 2 * encrypted_size;
  byte* decrypted_buf = new byte[decrypted_size];
  if (!keysFromPassPhrase(pass, &decrypted_size, decrypted_key)) {
    printf("keysFromPassPhrase failed\n");
    return false;
  }
  Aes key_decrypt;
  if (!key_decrypt.Init(128, decrypted_key, Aes::DECRYPT)) {
    printf("DecryptKeyWithPassword: Can't Init decrypt\n");
    correct = false;
  }
  if (correct) {
    key_decrypt.Decrypt(encrypted_size, encrypted_buf, decrypted_buf);
  }
  *out = decrypted_buf;
  // delete decrypted_key;
  // delete encrypted_buf;
  return correct;
}

RsaKey* GetRsaKey(int size, byte* in) {
  crypto_key_message* message = new crypto_key_message;
  RsaKey* new_key = new RsaKey();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((CryptoKey*)new_key)->DeserializeKeyFromMessage(*message)) {
    return nullptr;
  }
  return new_key;
}

AesCbcHmac256Sympad* GenAesCbcHmac256SymPad(
    int num_bits, const char* durationStr, const char* keyName,
    const char* ownerStr, const char* purposeStr, int* size, byte** out) {
  AesCbcHmac256Sympad* new_scheme = new AesCbcHmac256Sympad();
  if (!new_scheme->GenerateScheme(keyName, num_bits)) {
    return nullptr;
  }
  crypto_encryption_algorithm_message* message =
      new crypto_encryption_algorithm_message;
  if (!((EncryptionAlgorithm*)new_scheme)
           ->SerializeEncryptionAlgorithmToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_scheme;
}

AesCbcHmac256Sympad* GetAesCbcHmac256SymPad(int size, byte* in) {
  crypto_encryption_algorithm_message* message =
      new crypto_encryption_algorithm_message;
  AesCbcHmac256Sympad* new_scheme = new AesCbcHmac256Sympad();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((EncryptionAlgorithm*)new_scheme)
           ->DeserializeEncryptionAlgorithmFromMessage(*message)) {
    return nullptr;
  }
  return new_scheme;
}

AesCtrHmac256Sympad* GenAesCtrHmac256SymPad(
    int num_bits, const char* durationStr, const char* keyName,
    const char* ownerStr, const char* purposeStr, int* size, byte** out) {
  AesCtrHmac256Sympad* new_scheme = new AesCtrHmac256Sympad();
  if (!new_scheme->GenerateScheme(keyName, num_bits)) {
    return nullptr;
  }
  crypto_encryption_algorithm_message* message =
      new crypto_encryption_algorithm_message;
  if (!((EncryptionAlgorithm*)new_scheme)
           ->SerializeEncryptionAlgorithmToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_scheme;
}

AesCtrHmac256Sympad* GetAesCtrHmac256SymPad(int size, byte* in) {
  crypto_encryption_algorithm_message* message =
      new crypto_encryption_algorithm_message;
  AesCtrHmac256Sympad* new_scheme = new AesCtrHmac256Sympad();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((EncryptionAlgorithm*)new_scheme)
           ->DeserializeEncryptionAlgorithmFromMessage(*message)) {
    return nullptr;
  }
  return new_scheme;
}

AesGcm* GenAesGcm128(
    int num_bits, const char* durationStr, const char* keyName,
    const char* ownerStr, const char* purposeStr, int* size, byte** out) {
  AesGcm* new_scheme = new AesGcm();
  if (!new_scheme->GenerateScheme(keyName, num_bits)) {
    return nullptr;
  }
  crypto_encryption_algorithm_message* message =
      new crypto_encryption_algorithm_message;
  if (!((EncryptionAlgorithm*)new_scheme)
           ->SerializeEncryptionAlgorithmToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_scheme;
}

AesGcm* GetAesGcm128(int size, byte* in) {
  crypto_encryption_algorithm_message* message =
      new crypto_encryption_algorithm_message;
  AesGcm* new_scheme = new AesGcm();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    printf("GetAesGcm128, can't parse message from string\n");
    return nullptr;
  }
  if (!((EncryptionAlgorithm*)new_scheme)
           ->DeserializeEncryptionAlgorithmFromMessage(*message)) {
    printf("GetAesGcm128, can't deserialize\n");
    return nullptr;
  }
printf("Test GetAesGcm128, iv: ");
PrintBytes(16,  new_scheme->GetIv());
printf("\n");
  if (!new_scheme-> Init(128, new_scheme->GetAes()->key_, 128,
            12, new_scheme->GetIv(), Aes::BOTH, false)) {
    printf("GetAesGcm128, can't Init\n");
    return nullptr;
  }
  return new_scheme;
}

RsaKey* GenRsaKey(int num_bits, const char* durationStr, const char* keyName,
                  const char* ownerStr, const char* purposeStr, int* size,
                  byte** out) {
  double duration = convertDuration(FLAGS_duration.c_str());
  RsaKey* new_key = new RsaKey();
  if (!new_key->GenerateRsaKey(keyName, purposeStr, ownerStr, num_bits,
                               duration)) {
    return nullptr;
  }
  crypto_key_message* message = new crypto_key_message;
  if (!((CryptoKey*)new_key)->SerializeKeyToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  printf("GenRsaKey debug string: %s\n", message->DebugString().c_str());
  *size = outstr->size();
  *out = (byte*)outstr->data();
  printf("GenRsaKey outsize %d\n", *size);
  return new_key;
}

SymmetricKey* GetAesKey(int size, byte* in) {
  crypto_key_message* message = new crypto_key_message;
  SymmetricKey* new_key = new SymmetricKey();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((CryptoKey*)new_key)->DeserializeKeyFromMessage(*message)) {
    return nullptr;
  }
  return new_key;
}

SymmetricKey* GenAesKey(int num_bits, const char* durationStr,
                        const char* keyName, const char* ownerStr,
                        const char* purposeStr, int* size, byte** out) {
  double duration = convertDuration(durationStr);
  SymmetricKey* new_key = new SymmetricKey();
  if (!new_key->GenerateAesKey(keyName, purposeStr, ownerStr, num_bits,
                               duration)) {
    return nullptr;
  }
  crypto_key_message* message = new crypto_key_message;
  if (!((CryptoKey*)new_key)->SerializeKeyToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_key;
}

bool RsaVerify(RsaKey* key, const char* hashalg, byte* hash, byte* input) {
  int size_out = 512;
  byte output[512];

  if (!key->Encrypt(128, input, &size_out, output)) return false;
  return PkcsVerify("sha-256", hash, 128, output);
}

bool RsaSign(RsaKey* key, const char* hashalg, byte* hash, byte* output) {
  byte input[512];
  int size_out = 128;
  if (!PkcsEncode("sha-256", hash, 128, input)) return false;
  if (!key->Decrypt(128, input, &size_out, output)) return false;
  return true;
}

bool AesEncrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  Aes the_cipher;

  printf("AesEncrypt bit size is %d\n", key->symmetric_key_bit_size_);
  PrintBytes(key->symmetric_key_bit_size_ / NBITSINBYTE,
             key->symmetric_key_bytes_);
  printf("\n");
  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       Aes::ENCRYPT)) {
    printf("AesEncrypt cipher init: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("AesEncrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesEncrypt: can't open %s\n", outFile);
    return false;
  }

  int n;
  int k;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    n = reader.Read(BUFSIZE, in_buf);
    if (n < 0) {
      printf("AesEncrypt: error reading file\n");
      break;
    }
    if (n < BUFSIZE) {
      memset(&in_buf[n], 0, BUFSIZE - n);
      in_buf[n++] = 0x80;
      final = true;
    }
    k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
    k *= the_cipher.BLOCKBYTESIZE;
    the_cipher.Encrypt(k, in_buf, out_buf);
    writer.Write(k, out_buf);
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool AesDecrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  Aes the_cipher;

  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       the_cipher.DECRYPT)) {
    printf("AesDecrypt: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("AesDecrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesDecrypt: can't open %s\n", outFile);
    return false;
  }
  int k, m, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    k = reader.BytesLeftInFile() - the_cipher.BLOCKBYTESIZE;
    if (k <= 0) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("AesDecrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      for (m = (k - 1); m >= 0; m--) {
        if (out_buf[m] != 0) {
          if (out_buf[--m] != 0x80) {
          }
        }
      }
      if (m > 0) writer.Write(m, out_buf);
      final = true;
    } else {
      if (k > BUFSIZE) {
        m = BUFSIZE;
      } else {
        m = k;
      }

      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("AesDecrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      writer.Write(k, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

SymmetricKey* GetTwofishKey(int size, byte* in) {
  crypto_key_message* message = new crypto_key_message;
  SymmetricKey* new_key = new SymmetricKey();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((CryptoKey*)new_key)->DeserializeKeyFromMessage(*message)) {
    return nullptr;
  }
  return new_key;
}

SymmetricKey* GenTwofishKey(int num_bits, const char* durationStr,
                            const char* keyName, const char* ownerStr,
                            const char* purposeStr, int* size, byte** out) {
  double duration = convertDuration(durationStr);
  SymmetricKey* new_key = new SymmetricKey();
  if (!new_key->GenerateTwofishKey(keyName, purposeStr, ownerStr, num_bits,
                                   duration)) {
    return nullptr;
  }
  crypto_key_message* message = new crypto_key_message;
  if (!((CryptoKey*)new_key)->SerializeKeyToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_key;
}

bool TwoFishEncrypt(SymmetricKey* key, const char* inFile,
                    const char* outFile) {
  Aes the_cipher;

  printf("TwofishEncrypt bit size is %d\n", key->symmetric_key_bit_size_);
  PrintBytes(key->symmetric_key_bit_size_ / NBITSINBYTE,
             key->symmetric_key_bytes_);
  printf("\n");
  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       Twofish::ENCRYPT)) {
    printf("TwofishEncrypt cipher init: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("TwofishEncrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesEncrypt: can't open %s\n", outFile);
    return false;
  }

  int k, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    n = reader.Read(BUFSIZE, in_buf);
    if (n < 0) {
      printf("AesEncrypt: error reading file\n");
      break;
    }
    if (n < BUFSIZE) {
      memset(&in_buf[n], 0, BUFSIZE - n);
      in_buf[n++] = 0x80;
      final = true;
    }
    k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
    k *= the_cipher.BLOCKBYTESIZE;
    the_cipher.Encrypt(k, in_buf, out_buf);
    writer.Write(k, out_buf);
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool TwoFishDecrypt(SymmetricKey* key, const char* inFile,
                    const char* outFile) {
  Aes the_cipher;

  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       the_cipher.DECRYPT)) {
    printf("AesDecrypt: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("AesDecrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesDecrypt: can't open %s\n", outFile);
    return false;
  }

  int k, m, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    k = reader.BytesLeftInFile() - the_cipher.BLOCKBYTESIZE;
    if (k <= 0) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("AesDecrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      for (m = (k - 1); m >= 0; m--) {
        if (out_buf[m] != 0) {
          if (out_buf[--m] != 0x80) {
          }
        }
      }
      if (m > 0) writer.Write(m, out_buf);
      final = true;
    } else {
      if (k > BUFSIZE) {
        m = BUFSIZE;
      } else {
        m = k;
      }

      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("TwofishDecrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      writer.Write(k, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

SymmetricKey* GetSimonKey(int size, byte* in) {
  crypto_key_message* message = new crypto_key_message;
  SymmetricKey* new_key = new SymmetricKey();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((CryptoKey*)new_key)->DeserializeKeyFromMessage(*message)) {
    return nullptr;
  }
  return new_key;
}

SymmetricKey* GenSimonKey(int num_bits, const char* durationStr,
                          const char* keyName, const char* ownerStr,
                          const char* purposeStr, int* size, byte** out) {
  double duration = convertDuration(durationStr);
  SymmetricKey* new_key = new SymmetricKey();
  if (!new_key->GenerateSimonKey(keyName, purposeStr, ownerStr, num_bits,
                                 duration)) {
    return nullptr;
  }
  crypto_key_message* message = new crypto_key_message;
  if (!((CryptoKey*)new_key)->SerializeKeyToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_key;
}

bool SimonEncrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  Simon128 the_cipher;

  printf("SimonEncrypt bit size is %d\n", key->symmetric_key_bit_size_);
  PrintBytes(key->symmetric_key_bit_size_ / NBITSINBYTE,
             key->symmetric_key_bytes_);
  printf("\n");
  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       Simon128::ENCRYPT)) {
    printf("SimonEncrypt cipher init: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("SimonEncrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("Simon128Encrypt: can't open %s\n", outFile);
    return false;
  }

  int k, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    n = reader.Read(BUFSIZE, in_buf);
    if (n < 0) {
      printf("Simon128Encrypt: error reading file\n");
      break;
    }
    if (n < BUFSIZE) {
      memset(&in_buf[n], 0, BUFSIZE - n);
      in_buf[n++] = 0x80;
      final = true;
    }
    k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
    k *= the_cipher.BLOCKBYTESIZE;
    the_cipher.Encrypt(k, in_buf, out_buf);
    writer.Write(k, out_buf);
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool SimonDecrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  Simon128 the_cipher;

  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       the_cipher.DECRYPT)) {
    printf("Simon128Decrypt: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("Simon128Decrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesDecrypt: can't open %s\n", outFile);
    return false;
  }

  int k, m, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    k = reader.BytesLeftInFile() - the_cipher.BLOCKBYTESIZE;
    if (k <= 0) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("Simon128Decrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      for (m = (k - 1); m >= 0; m--) {
        if (out_buf[m] != 0) {
          if (out_buf[--m] != 0x80) {
          }
        }
      }
      if (m > 0) writer.Write(m, out_buf);
      final = true;
    } else {
      if (k > BUFSIZE) {
        m = BUFSIZE;
      } else {
        m = k;
      }

      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("SimonDecrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      writer.Write(k, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

SymmetricKey* GetRc4Key(int size, byte* in) {
  crypto_key_message* message = new crypto_key_message;
  SymmetricKey* new_key = new SymmetricKey();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((CryptoKey*)new_key)->DeserializeKeyFromMessage(*message)) {
    return nullptr;
  }
  return new_key;
}

SymmetricKey* GenRc4Key(int num_bits, const char* durationStr,
                        const char* keyName, const char* ownerStr,
                        const char* purposeStr, int* size, byte** out) {
  double duration = convertDuration(durationStr);
  SymmetricKey* new_key = new SymmetricKey();
  if (!new_key->GenerateRc4Key(keyName, purposeStr, ownerStr, num_bits,
                               duration)) {
    return nullptr;
  }
  crypto_key_message* message = new crypto_key_message;
  if (!((CryptoKey*)new_key)->SerializeKeyToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_key;
}

bool Rc4Encrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  Rc4 the_cipher;

  printf("Rc4Encrypt bit size is %d\n", key->symmetric_key_bit_size_);
  PrintBytes(key->symmetric_key_bit_size_ / NBITSINBYTE,
             key->symmetric_key_bytes_);
  printf("\n");
  if (!the_cipher.Init(key->symmetric_key_bit_size_,
                       key->symmetric_key_bytes_)) {
    printf("Rc4Encrypt cipher init: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("Rc4Encrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("Rc4Encrypt: can't open %s\n", outFile);
    return false;
  }

  int k, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    n = reader.Read(BUFSIZE, in_buf);
    if (n < 0) {
      printf("Rc4Encrypt: error reading file\n");
      break;
    }
    if (n < BUFSIZE) {
      memset(&in_buf[n], 0, BUFSIZE - n);
      in_buf[n++] = 0x80;
      final = true;
    }
    k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
    k *= the_cipher.BLOCKBYTESIZE;
    the_cipher.Encrypt(k, in_buf, out_buf);
    writer.Write(k, out_buf);
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool Rc4Decrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  return Rc4Encrypt(key, inFile, outFile);
}

SymmetricKey* GetTeaKey(int size, byte* in) {
  crypto_key_message* message = new crypto_key_message;
  SymmetricKey* new_key = new SymmetricKey();
  string data(reinterpret_cast<char const*>(in), size);

  if (!message->ParseFromString(data)) {
    return nullptr;
  }
  if (!((CryptoKey*)new_key)->DeserializeKeyFromMessage(*message)) {
    return nullptr;
  }
  return new_key;
}

SymmetricKey* GenTeaKey(int num_bits, const char* durationStr,
                        const char* keyName, const char* ownerStr,
                        const char* purposeStr, int* size, byte** out) {
  double duration = convertDuration(durationStr);
  SymmetricKey* new_key = new SymmetricKey();
  if (!new_key->GenerateTeaKey(keyName, purposeStr, ownerStr, num_bits,
                               duration)) {
    return nullptr;
  }
  crypto_key_message* message = new crypto_key_message;
  if (!((CryptoKey*)new_key)->SerializeKeyToMessage(*message)) {
    return nullptr;
  }
  string* outstr = new string();
  if (!message->SerializeToString(outstr)) {
    return nullptr;
  }
  *size = outstr->size();
  *out = (byte*)outstr->data();
  return new_key;
}

bool TeaEncrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  Tea the_cipher;

  printf("TeaEncrypt bit size is %d\n", key->symmetric_key_bit_size_);
  PrintBytes(key->symmetric_key_bit_size_ / NBITSINBYTE,
             key->symmetric_key_bytes_);
  printf("\n");
  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       Tea::ENCRYPT)) {
    printf("TeaEncrypt cipher init: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("TeaEncrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("Tea.Encrypt: can't open %s\n", outFile);
    return false;
  }

  int k, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    n = reader.Read(BUFSIZE, in_buf);
    if (n < 0) {
      printf("Tea.Encrypt: error reading file\n");
      break;
    }
    if (n < BUFSIZE) {
      memset(&in_buf[n], 0, BUFSIZE - n);
      in_buf[n++] = 0x80;
      final = true;
    }
    k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
    k *= the_cipher.BLOCKBYTESIZE;
    the_cipher.Encrypt(k, in_buf, out_buf);
    writer.Write(k, out_buf);
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool TeaDecrypt(SymmetricKey* key, const char* inFile, const char* outFile) {
  Tea the_cipher;

  if (!the_cipher.Init(key->symmetric_key_bit_size_, key->symmetric_key_bytes_,
                       the_cipher.DECRYPT)) {
    printf("Tea.Decrypt: failed\n");
    return false;
  }
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("Tea.Decrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesDecrypt: can't open %s\n", outFile);
    return false;
  }

  int k, m, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  for (;;) {
    k = reader.BytesLeftInFile() - the_cipher.BLOCKBYTESIZE;
    if (k <= 0) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("AesDecrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      for (m = (k - 1); m >= 0; m--) {
        if (out_buf[m] != 0) {
          if (out_buf[--m] != 0x80) {
          }
        }
      }
      if (m > 0) writer.Write(m, out_buf);
      final = true;
    } else {
      if (k > BUFSIZE) {
        m = BUFSIZE;
      } else {
        m = k;
      }

      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("TeaDecrypt: error reading file\n");
        break;
      }
      k = (n + the_cipher.BLOCKBYTESIZE - 1) / the_cipher.BLOCKBYTESIZE;
      k *= the_cipher.BLOCKBYTESIZE;
      the_cipher.Decrypt(k, in_buf, out_buf);
      writer.Write(k, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool AesGcmEncrypt(AesGcm* scheme, const char* inFile,
                const char* outFile, bool aes_ni) {
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("AesGcmEncrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesGcmEncrypt: can't open %s\n", outFile);
    return false;
  }

  writer.Write(12, scheme->GetIv());
  int k, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;
  int size = 0;

  for (;;) {
    k = reader.BytesLeftInFile();
    if (k < BUFSIZE) {
      n = reader.Read(k, in_buf);
      size = BUFSIZE;
      if (!scheme->FinalPlainIn(n, in_buf, &size, out_buf)) {
        printf("AesGcmEncrypt: encrypt_obj.FinalPlainIn failed\n");
        return false;
      }
      final = true;
    } else {
      n = reader.Read(BUFSIZE, in_buf);
      if (n < 0) {
        printf("AesGcmEncrypt: error reading file\n");
        break;
      }
      size = BUFSIZE;
      scheme->PlainIn(n, in_buf, &size, out_buf);
    }
    writer.Write(size, out_buf);
    if (final) break;
  }
  byte tag[16];
  scheme->GetComputedTag(16, tag);
  writer.Write(16, tag);
  reader.Close();
  writer.Close();
  return true;
}

bool AesGcmDecrypt(AesGcm* scheme, const char* inFile,
                const char* outFile, bool aes_ni) {
  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("AesGcmDecrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesGcmDecrypt: can't open %s\n", outFile);
    return false;
  }

  int k, n;
  int size = 0;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  memset(in_buf, 0, 16);
  n = reader.Read(12, in_buf);
  if (n != 12) {
    printf("AesGcmDecrypt: can't read iv\n");
    return false;
  }
  scheme->ProcessIv(12, in_buf);
  for (;;) {
    k = reader.BytesLeftInFile()-16;
    if (k <= BUFSIZE) {
      n = reader.Read(k, in_buf);
      size = BUFSIZE;
      final = true;
      if (!scheme->FinalCipherIn(n, in_buf, &size, out_buf)) {
        printf("AesGcmDecrypt: decrypt_obj.FinalCipherIn failed\n");
        return false;
      }
    } else {
      n = reader.Read(BUFSIZE, in_buf);
      if (n < 0) {
        printf("AesGcmDecrypt: error reading file\n");
        break;
      }
      size = BUFSIZE;
      scheme->CipherIn(n, in_buf, &size, out_buf);
    }
    writer.Write(size, out_buf);
    if (final) break;
  }
  n = reader.Read(16, in_buf);
  if (n != 16) {
    printf("AesGcmDecrypt: can't read hash\n");
    return false;
  }
  scheme->SetReceivedTag(16, in_buf);
  reader.Close();
  writer.Close();

  if (scheme->MessageValid()) {
    printf("decrypt object valid\n");
  } else {
    printf("decrypt object invalid\n");
  }
  return true;
}

bool CbcEncrypt(AesCbcHmac256Sympad* scheme, const char* inFile,
                const char* outFile, bool aes_ni) {
  AesCbcHmac256Sympad encrypt_obj;

  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("CbcEncrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("CbcEncrypt: can't open %s\n", outFile);
    return false;
  }
  int k, m, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;
  int size = 0;

  if (!encrypt_obj.InitEnc(Aes::BLOCKBYTESIZE, scheme->aesni_obj_.key_,
                           Aes::BLOCKBYTESIZE, scheme->hmac_.key_,
                           Aes::BLOCKBYTESIZE, scheme->iv_, true)) {
    printf("CbcEncrypt: Can't initialize AesCbcHmac256Sympad encrypt object\n");
    return false;
  }
  int encrypt_min_final = encrypt_obj.MinimumFinalEncryptIn();

  for (;;) {
    k = reader.BytesLeftInFile() - encrypt_min_final;
    if (k <= 0) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      size = BUFSIZE;
      if (!encrypt_obj.FinalPlainIn(n, in_buf, &size, out_buf)) {
        printf("CbcEncrypt: encrypt_obj.FinalPlainIn failed\n");
        return false;
      }
      writer.Write(size, out_buf);
      final = true;
    } else {
      if (k < BUFSIZE)
        m = k;
      else
        m = BUFSIZE;
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("CbcEncrypt: error reading file\n");
        break;
      }
      size = BUFSIZE;
      encrypt_obj.PlainIn(n, in_buf, &size, out_buf);
      writer.Write(size, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool CbcDecrypt(AesCbcHmac256Sympad* scheme, const char* inFile,
                const char* outFile, bool aes_ni) {
  AesCbcHmac256Sympad decrypt_obj;

  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("CbcDecrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("AesEncrypt: can't open %s\n", outFile);
    return false;
  }

  int k, m, n;
  int size = 0;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  if (!decrypt_obj.InitDec(Aes::BLOCKBYTESIZE, scheme->aesni_obj_.key_,
                           Aes::BLOCKBYTESIZE, scheme->hmac_.key_, true)) {
    printf("Can't initialize AesCbcHmac256Sympad decrypt object\n");
    return false;
  }
  int decrypt_min_final = decrypt_obj.MinimumFinalDecryptIn();

  for (;;) {
    k = reader.BytesLeftInFile() - decrypt_min_final;
    if (k < Aes::BLOCKBYTESIZE) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      size = BUFSIZE;
      if (!decrypt_obj.FinalCipherIn(n, in_buf, &size, out_buf)) {
        printf("CbcDecrypt: decrypt_obj.FinalCipherIn failed\n");
        return false;
      }
      writer.Write(size, out_buf);
      final = true;
    } else {
      if (k < BUFSIZE)
        m = k;
      else
        m = BUFSIZE;
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("CbcDecrypt: error reading file\n");
        break;
      }
      size = BUFSIZE;
      decrypt_obj.CipherIn(n, in_buf, &size, out_buf);
      writer.Write(size, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();

  if (decrypt_obj.MessageValid()) {
    printf("decrypt object valid\n");
  } else {
    printf("decrypt object invalid\n");
  }
  return true;
}

bool CtrEncrypt(AesCtrHmac256Sympad* scheme, const char* inFile,
                const char* outFile, bool aes_ni) {
  printf("CtrEncrypt %s %s\n", inFile, outFile);

  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("CtrEncrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("CtrEncrypt: can't open %s\n", outFile);
    return false;
  }

  int k, m, n;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;
  int size = 0;
  int encrypt_min_final = scheme->MinimumFinalEncryptIn();

  for (;;) {
    k = reader.BytesLeftInFile() - encrypt_min_final;
    if (k < Aes::BLOCKBYTESIZE) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      size = BUFSIZE;
      final = true;
      if (!scheme->FinalPlainIn(n, in_buf, &size, out_buf)) {
        printf("CtrEncrypt: FinalPlainIn failed\n");
        return false;
      }
      writer.Write(size, out_buf);
    } else {
      if (k < BUFSIZE) {
        m = (k / Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;
      } else {
        m = BUFSIZE;
      }
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("CtrEncrypt: error reading file\n");
        break;
      }
      size = BUFSIZE;
      scheme->PlainIn(n, in_buf, &size, out_buf);
      writer.Write(size, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();
  return true;
}

bool CtrDecrypt(AesCtrHmac256Sympad* scheme, const char* inFile,
                const char* outFile, bool aes_ni) {
  printf("CtrDecrypt %s %s\n", inFile, outFile);

  ReadFile reader;
  WriteFile writer;

  if (!reader.Init(inFile)) {
    printf("CtrDecrypt: can't open %s\n", inFile);
    return false;
  }
  if (!writer.Init(outFile)) {
    printf("CtrDecrypt: can't open %s\n", outFile);
    return false;
  }

  int k, m, n;
  int size = 0;
  byte in_buf[BUFSIZE];
  byte out_buf[BUFSIZE];
  bool final = false;

  int decrypt_min_final = scheme->MinimumFinalDecryptIn();

  for (;;) {
    k = reader.BytesLeftInFile() - decrypt_min_final;
    if (k < Aes::BLOCKBYTESIZE) {
      m = reader.BytesLeftInFile();
      n = reader.Read(m, in_buf);
      size = BUFSIZE;
      final = true;
      if (!scheme->FinalCipherIn(n, in_buf, &size, out_buf)) {
        printf("CtrDecrypt: decrypt_obj.FinalCipherIn failed\n");
        return false;
      }
      writer.Write(size, out_buf);
    } else {
      if (k < BUFSIZE) {
        m = (k / Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;
      } else {
        m = BUFSIZE;
      }
      n = reader.Read(m, in_buf);
      if (n < 0) {
        printf("CtrDecrypt: error reading file\n");
        break;
      }
      size = BUFSIZE;
      scheme->CipherIn(n, in_buf, &size, out_buf);
      writer.Write(size, out_buf);
    }
    if (final) break;
  }
  reader.Close();
  writer.Close();

  if (scheme->MessageValid()) {
    printf("decrypt object valid\n");
  } else {
    printf("decrypt object invalid\n");
  }
  return true;
}

int main(int an, char** av) {
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
  num_cryptutil_ops = sizeof(cryptutil_ops) / sizeof(std::string);

  if (FLAGS_operation == "") {
    std::cout << "No operation specified.\n\n";
    print_options();
    return 1;
  }
  printf("operation flag: %s\n", FLAGS_operation.c_str());
  if (!InitUtilities("cryptutil.log")) {
    printf("InitUtilities() failed\n");
    return 1;
  }

  if ("ToBase64" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;
    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return 1;
    }
    if (out == nullptr) {
      printf("bad buffer\n");
      return 1;
    }
    if (FLAGS_direction == "left-right") {
      string* str = ByteToBase64LeftToRight(size, out);
      printf("Base64 left-to-right: %s\n", str->c_str());
      WriteaFile(FLAGS_output_file.c_str(), strlen(str->c_str()),
                 (byte*)str->c_str());
      delete str;
    } else {
      string* str = ByteToBase64RightToLeft(size, out);
      printf("Base64 right-to-left: %s\n", str->c_str());
      WriteaFile(FLAGS_output_file.c_str(), strlen(str->c_str()),
                 (byte*)str->c_str());
      delete str;
    }
    if (out != nullptr) delete out;
  } else if ("ToDecimal" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return 1;
    }
    if (out == nullptr) {
      printf("bad buffer\n");
      return 1;
    }
    BigNum a(2 + size / sizeof(uint64_t));
    memcpy(a.value_, out, size);
    a.Normalize();
    string* str = BigConvertToDecimal(a);
    printf("Decimal: %s\n", str->c_str());
    delete out;
    if (str != nullptr) delete str;
  } else if ("ToHex" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return 1;
    }
    if (out == nullptr) {
      printf("bad buffer\n");
      return 1;
    }
    BigNum a(2 + size / sizeof(uint64_t));
    memcpy(a.value_, out, size);
    a.Normalize();
    string* str = BigConvertToHex(a);
    WriteaFile(FLAGS_output_file.c_str(), strlen(str->c_str()),
               (byte*)str->c_str());
    printf("Decimal: %s\n", str->c_str());
    delete out;
    if (str != nullptr) delete str;
  } else if ("FromHexBuf" == FLAGS_operation) {
    int size = 0;
    byte* in = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &in)) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return 1;
    }
    if (in == nullptr) {
      printf("bad buffer\n");
      return 1;
    }
    const char* str = extractString(size, in);
    byte* out = new byte [strlen(str) / 2];
    byte b1, b2;
    const char* p = str;
    int i = 0;
    while (*p != '\0' && *p != '\n') {
      b1 = HexToValue(*(p++));
      b2 = HexToValue(*(p++));
      out[i++] = (b1 << 4) | b2;
    }
    WriteaFile(FLAGS_output_file.c_str(), i, out);
    delete in;
    delete out;
  } else if ("ToHexBuf" == FLAGS_operation) {
  } else if ("FromHex" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return 1;
    }
    if (out == nullptr) {
      printf("bad buffer\n");
      return 1;
    }

    if (FLAGS_direction == "right-to-left") {
      byte* tmp = new byte[size];
      memset(tmp, 0, size);
      if (out[size-1] =='\n') {
        ReverseCpy(size-1, out, tmp);
        tmp[size-1]= '\n';
      } else
        ReverseCpy(size, out, tmp);
      memcpy(out, tmp, size);
      delete tmp;
    }

    const char* str = extractString(size, out);
    BigNum* n = BigConvertFromHex(str);
    n->Normalize();
    WriteaFile(FLAGS_output_file.c_str(), sizeof(uint64_t) * n->size_,
               (byte*)n->value_);
    delete n;
  } else if ("FromDecimal" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return 1;
    }
    if (out == nullptr) {
      printf("bad buffer\n");
      return 1;
    }
    const char* str = extractString(size, out);
    BigNum* n = BigConvertFromDecimal(str);
    n->Normalize();
    WriteaFile(FLAGS_input_file.c_str(), sizeof(uint64_t) * n->size_,
               (byte*)n->value_);
    delete n;
    delete out;
  } else if ("FromBase64" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return 1;
    }
    if (out == nullptr) {
      printf("bad buffer\n");
      return 1;
    }
    const char* str = extractString(size, out);
    if (str == nullptr) {
      printf("Can't extract string\n");
      return 1;
    }
    int n = strlen(str);
    int out_size = (n * 6 + 7) / 8 + 4;
    byte* out_buf = new byte[out_size];
    if (FLAGS_direction == "left-right") {
      int k = Base64ToByteLeftToRight((char*)str, out_size, out_buf);
      if (k < 0) return 1;
      WriteaFile(FLAGS_output_file.c_str(), k, out_buf);
    } else {
      int k = Base64ToByteRightToLeft((char*)str, out_size, out_buf);
      if (k < 0) return 1;
      WriteaFile(FLAGS_output_file.c_str(), k, out_buf);
    }
    printf("Out: ");
    PrintBytes(out_size, out_buf);
    printf("\n");
    delete out_buf;
    delete out;
  } else if ("Hash" == FLAGS_operation) {
    hashFile(FLAGS_input_file.c_str(), FLAGS_algorithm.c_str(), nullptr,
             nullptr);
  } else if ("Mac" == FLAGS_operation) {
    byte* key = nullptr;
    int size = 0;
    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &key)) {
      printf("Can't open %s\n", FLAGS_key_file.c_str());
      return 1;
    }
    macFile(FLAGS_input_file.c_str(), FLAGS_algorithm.c_str(), size, key,
            FLAGS_output_file.c_str());
    if (key != nullptr) delete key;
  } else if ("VerifyMac" == FLAGS_operation) {
    byte* key = nullptr;
    int size = 0;
    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &key)) {
      printf("Can't open %s\n", FLAGS_key_file.c_str());
      return 1;
    }
    verifymacFile(FLAGS_input_file.c_str(), FLAGS_algorithm.c_str(), size, key,
                  FLAGS_input2_file.c_str());
    if (key != nullptr) delete key;
  } else if ("EncryptWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;
    SymmetricKey* new_key = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
    if (out == nullptr) {
      printf("EncryptWithKey: bad buffer\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes-128") {
      new_key = GetAesKey(size, out);
      if (new_key == nullptr) {
        printf("Encrypt: can't get key\n");
        return 1;
      }
      if (!AesEncrypt(new_key, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str())) {
        printf("Encryption failed\n");
        CloseUtilities();
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "twofish-128" ||
               FLAGS_algorithm == "twofish-256") {
      new_key = GetTwofishKey(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!TwoFishEncrypt(new_key, FLAGS_input_file.c_str(),
                          FLAGS_output_file.c_str())) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }

    } else if (FLAGS_algorithm == "rc4-128") {
      new_key = GetRc4Key(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!Rc4Encrypt(new_key, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str())) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "simon-128") {
      new_key = GetSimonKey(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!SimonEncrypt(new_key, FLAGS_input_file.c_str(),
                        FLAGS_output_file.c_str())) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "tea-128") {
      new_key = GetTeaKey(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!TeaEncrypt(new_key, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str())) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else {
      printf("unknown encryption alg %s\n", FLAGS_algorithm.c_str());
    }

  } else if ("DecryptWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;
    SymmetricKey* new_key = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
    if (out == nullptr) {
      printf("DecryptWithKey: bad buffer\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes-128") {
      new_key = GetAesKey(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!AesDecrypt(new_key, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str())) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "twofish-128" ||
               FLAGS_algorithm == "twofish-256") {
      new_key = GetTwofishKey(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!TwoFishDecrypt(new_key, FLAGS_input_file.c_str(),
                          FLAGS_output_file.c_str())) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "simon-128") {
      new_key = GetSimonKey(size, out);
      if (new_key == nullptr) {
        printf("DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!SimonDecrypt(new_key, FLAGS_input_file.c_str(),
                        FLAGS_output_file.c_str())) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "rc4-128") {
      new_key = GetRc4Key(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!Rc4Decrypt(new_key, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str())) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "tea-128") {
      new_key = GetTeaKey(size, out);
      if (new_key == nullptr) {
        printf("Encrypt/DecryptWithKey: can't get key\n");
        return 1;
      }
      if (!TeaDecrypt(new_key, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str())) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else {
      printf("Decrypt: Unknown encryption alg\n");
    }
  } else if ("DecryptWithScheme" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
    if (out == nullptr) {
      printf("DecryptWithScheme: bad buffer\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      AesCbcHmac256Sympad* new_scheme = GetAesCbcHmac256SymPad(size, out);
      if (new_scheme == nullptr) {
        printf("DecryptWithScheme: can't get scheme\n");
        return 1;
      }
      if (!CbcDecrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
      AesCtrHmac256Sympad* new_scheme = GetAesCtrHmac256SymPad(size, out);
      if (new_scheme == nullptr) {
        printf("DecryptWithScheme: can't get scheme\n");
        return 1;
      }
      if (!CtrDecrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "aes128-gcm128") {
      AesGcm* new_scheme = GetAesGcm128(size, out);
      if (new_scheme == nullptr) {
        printf("DecryptWithScheme: can't get scheme\n");
        return 1;
      }
      if (!AesGcmDecrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), false)) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else {
      printf("DecryptWithScheme: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      return 1;
    }
  } else if ("EncryptWithScheme" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
    if (out == nullptr) {
      printf("EncryptWithScheme: bad buffer\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      AesCbcHmac256Sympad* new_scheme = GetAesCbcHmac256SymPad(size, out);
      if (new_scheme == nullptr) {
        printf("EncryptWithScheme: can't get scheme\n");
        return 1;
      }
      if (!CbcEncrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
      AesCtrHmac256Sympad* new_scheme = GetAesCtrHmac256SymPad(size, out);
      if (new_scheme == nullptr) {
        printf("Encrypt/Decrypt With Scheme: can't get scheme\n");
        return 1;
      }
      if (!CtrEncrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "aes128-gcm128") {
      AesGcm* new_scheme = GetAesGcm128(size, out);
      if (new_scheme == nullptr) {
        printf("Encrypt/Decrypt With Scheme: can't get scheme\n");
        return 1;
      }
      if (!AesGcmEncrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), false)) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else {
      printf("EncryptWithScheme: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      return 1;
    }
  } else if ("GenerateScheme" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      AesCbcHmac256Sympad* new_scheme = GenAesCbcHmac256SymPad(
          128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
          FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_scheme == nullptr || out == nullptr) return 1;
      new_scheme->PrintEncryptionAlgorithm();
    } else if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
      AesCtrHmac256Sympad* new_scheme = GenAesCtrHmac256SymPad(
          128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
          FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_scheme == nullptr || out == nullptr) return 1;
      new_scheme->PrintEncryptionAlgorithm();
    } else if (FLAGS_algorithm == "aes128-gcm128") {
      AesGcm* new_scheme = GenAesGcm128(
          128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
          FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_scheme == nullptr || out == nullptr) return 1;
      new_scheme->PrintEncryptionAlgorithm();
    } else {
      return 1;
    }
    WriteaFile(FLAGS_output_file.c_str(), size, out);
  } else if ("GenerateKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    printf("GenerateKey\n");
    if (FLAGS_algorithm == "aes-128") {
      SymmetricKey* new_key =
          GenAesKey(128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
                    FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm == "twofish-128") {
      SymmetricKey* new_key = GenTwofishKey(
          128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
          FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm == "twofish-256") {
      SymmetricKey* new_key = GenTwofishKey(
          256, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
          FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm == "simon-128") {
      SymmetricKey* new_key =
          GenSimonKey(128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
                      FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm == "rc4-128") {
      SymmetricKey* new_key =
          GenRc4Key(128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
                    FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm =="tea-128") {
      SymmetricKey* new_key =
          GenTeaKey(128, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
                    FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm == "rsa-256") {
      int size = 0;
      byte* out = nullptr;
      RsaKey* new_key =
          GenRsaKey(256, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
                    FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm == "rsa-1024") {
      int size = 0;
      byte* out = nullptr;
      RsaKey* new_key =
          GenRsaKey(1024, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
                    FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else if (FLAGS_algorithm == "rsa-2048") {
      int size = 0;
      byte* out = nullptr;
      RsaKey* new_key =
          GenRsaKey(2048, FLAGS_duration.c_str(), FLAGS_key_name.c_str(),
                    FLAGS_owner.c_str(), FLAGS_purpose.c_str(), &size, &out);
      if (new_key == nullptr) {
        return 1;
      }
      ((CryptoKey*)new_key)->PrintKey();
      WriteaFile(FLAGS_output_file.c_str(), size, out);
    } else {
      return 1;
    }
  } else if ("ReadKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      return 1;
    }
    if (FLAGS_algorithm == "aes-128") {
      SymmetricKey* new_key = GetAesKey(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else if (FLAGS_algorithm == "twofish-128") {
      SymmetricKey* new_key = GetTwofishKey(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else if (FLAGS_algorithm == "simon-128") {
      SymmetricKey* new_key = GetSimonKey(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else if (FLAGS_algorithm == "rc4-128") {
      SymmetricKey* new_key = GetRc4Key(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else if (FLAGS_algorithm == "tea-128") {
      SymmetricKey* new_key = GetTeaKey(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else if (FLAGS_algorithm == "rsa-256") {
      RsaKey* new_key = GetRsaKey(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else if (FLAGS_algorithm == "rsa-1024") {
      RsaKey* new_key = GetRsaKey(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else if (FLAGS_algorithm == "rsa-2048") {
      RsaKey* new_key = GetRsaKey(size, out);
      ((CryptoKey*)new_key)->PrintKey();
    } else {
      printf("GenerateKey: no such key type\n");
      return 1;
    }
  } else if ("GetRandom" == FLAGS_operation) {
    int size = FLAGS_size;
    if (size > 64000) return 1;
    int num_bytes = size / NBITSINBYTE;
    byte* rand_bytes = new byte[num_bytes];

    if (rand_bytes == nullptr) return 1;
    if (!GetCryptoRand(size, rand_bytes)) {
      delete rand_bytes;
      return 1;
    }
    WriteaFile(FLAGS_output_file.c_str(), size, rand_bytes);
    printf("%d random bytes: ", num_bytes);
    PrintBytes(num_bytes, rand_bytes);
    printf("\n");
    delete rand_bytes;
  } else if ("ReadScheme" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_input_file.c_str(), &size, &out)) {
      return 1;
    }
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      AesCbcHmac256Sympad* new_scheme = GetAesCbcHmac256SymPad(size, out);
      if (new_scheme == nullptr) {
        printf("No scheme\n");
        return 1;
      }
      new_scheme->PrintEncryptionAlgorithm();
    } else if (FLAGS_algorithm == "aes128-gcm128") {
      AesGcm* new_scheme = GetAesGcm128(size, out);
      if (new_scheme == nullptr) {
        printf("No scheme\n");
        return 1;
      }
      new_scheme->PrintEncryptionAlgorithm();
    } else if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
      AesCtrHmac256Sympad* new_scheme = GetAesCtrHmac256SymPad(size, out);
      if (new_scheme == nullptr) {
        printf("No scheme\n");
        return 1;
      }
      new_scheme->PrintEncryptionAlgorithm();
    } else {
      return 1;
    }
  } else if ("EncryptWithPassword" == FLAGS_operation) {
    int size = 64;
    byte out[64];
    byte iv[64];

    if (!keysFromPassPhrase(FLAGS_pass.c_str(), &size, out)) {
      printf("EncryptWithPassword: can't get key from password\n");
      return 1;
    }
    if (!GetCryptoRand(128, iv)) {
      printf("EncryptWithPassword: can't get iv\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      AesCbcHmac256Sympad* new_scheme = new AesCbcHmac256Sympad();
      if (new_scheme == nullptr) {
        printf("EncryptWithPassword: can't get scheme\n");
        return 1;
      }
      if (!new_scheme->MakeScheme("password-key", 128, out, &out[16], iv)) {
        printf("EncryptWithPassword: can't make scheme\n");
        return 1;
      }
      if (!CbcEncrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Encryption failed\n");
        return 1;
      } else {
        printf("Encryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
      AesCtrHmac256Sympad* new_scheme = new AesCtrHmac256Sympad();
      if (new_scheme == nullptr) {
        printf("EncryptWithPassword: can't get scheme\n");
        return 1;
      }
      if (!new_scheme->MakeScheme("password-key", 128, out, &out[16], iv,
                                  &iv[4])) {
        printf("EncryptWithPassword: can't make scheme\n");
        return 1;
      }
      if (!CtrEncrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Encryption failed\n");
        return 1;
      } else {
        return 0;
      }
    } else {
      printf("EncryptWithPassword: unknown scheme\n");
      return 1;
    }
  } else if ("DecryptWithPassword" == FLAGS_operation) {
    int size = 64;
    byte out[64];
    byte iv[64];

    if (!keysFromPassPhrase(FLAGS_pass.c_str(), &size, out)) {
      printf("DecryptWithPassword: can't get key from password\n");
      return 1;
    }
    if (!GetCryptoRand(128, iv)) {
      printf("DecryptWithPassword: can't get iv\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      AesCbcHmac256Sympad* new_scheme = new AesCbcHmac256Sympad();
      if (new_scheme == nullptr) {
        printf("EncryptWithPassword: can't get scheme\n");
        return 1;
      }
      if (!new_scheme->MakeScheme("password-key", 128, out, &out[16], iv)) {
        printf("DecryptWithPassword: can't make scheme\n");
        return 1;
      }
      if (!CbcDecrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Decryption failed\n");
        return 1;
      } else {
        printf("Decryption succeeded\n");
        return 0;
      }
    } else if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
      AesCtrHmac256Sympad* new_scheme = new AesCtrHmac256Sympad();
      if (new_scheme == nullptr) {
        printf("DecryptWithPassword: can't get scheme\n");
        return 1;
      }
      if (!new_scheme->MakeScheme("password-key", 128, out, &out[16], iv,
                                  &iv[4])) {
        printf("EncryptWithPassword: can't make scheme\n");
        return 1;
      }
      if (!CtrDecrypt(new_scheme, FLAGS_input_file.c_str(),
                      FLAGS_output_file.c_str(), true)) {
        printf("Decryption failed\n");
        return 1;
      } else {
        return 0;
      }
    } else {
      return 1;
    }
  } else if ("PkcsSignWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
    RsaKey* key = GetRsaKey(size, out);
    if (key == nullptr) {
      printf("Can't new rsa-key\n");
      return 1;
    }
    int size_hash = 64;
    byte hash[64];
    if ("rsa-1024-sha-256-pkcs" == FLAGS_algorithm ||
        "rsa-2048-sha-256-pkcs" == FLAGS_algorithm) {
      hashFile(FLAGS_hash_file.c_str(), "sha-256", &size_hash, hash);
      Signature sig_obj;
      sig_obj.encryption_alg_ = strdup(FLAGS_algorithm.c_str());

      sig_obj.signature_ = new byte[256];
      if (FLAGS_algorithm == "rsa-2048-sha-256-pkcs") {
        sig_obj.size_signature_ = 256;
      } else {
        sig_obj.size_signature_ = 128;
      }
      if (!RsaSign(key, "sha-256", hash, sig_obj.signature_)) {
        printf("signature fails\n");
        return 1;
      }
      sig_obj.signer_name_ = strdup(key->key_name_->c_str());
      crypto_signature sig;
      if (!sig_obj.Serialize(sig)) {
      }
      string* outstr = new string();
      if (!sig.SerializeToString(outstr)) {
        return 1;
      }
      sig_obj.PrintSignature();
      if (!WriteaFile(FLAGS_output_file.c_str(), outstr->size(),
                      (byte*)outstr->data())) {
        printf("couldn't write outputfile\n");
        return 1;
      }
    } else {
      printf("Unsupported signature alg\n");
    }
  } else if ("PkcsVerifyWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;
    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
    RsaKey* key = GetRsaKey(size, out);
    if (key == nullptr) {
      printf("Can't new rsa-key\n");
      return 1;
    }

    int size_input;
    byte* input = nullptr;
    int size_hash = 64;
    byte hash[64];
    if ("rsa-2048-sha-256-pkcs" == FLAGS_algorithm ||
        "rsa-1024-sha-256-pkcs" == FLAGS_algorithm) {
      hashFile(FLAGS_hash_file.c_str(), "sha-256", &size_hash, hash);
      if (!ReadaFile(FLAGS_sig_file.c_str(), &size_input, &input)) {
        printf("Can't read %s\n", FLAGS_sig_file.c_str());
        return 1;
      }
      Signature sig_obj;
      crypto_signature sig;
      string data(reinterpret_cast<char const*>(input), size_input);

      if (!sig.ParseFromString(data)) {
        printf("Can't parse from string\n");
        return 1;
      }
      if (!sig_obj.Deserialize(sig)) {
        printf("Can't deserialize from string\n");
        return 1;
      }
      sig_obj.PrintSignature();
      if (!RsaVerify(key, "sha-256", hash, sig_obj.signature_)) {
        printf("verification fails\n");
      } else {
        printf("verification succeeds\n");
      }
    } else {
      printf("Unsupported signature alg\n");
    }
  } else if ("PkcsPubSealWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
    if (FLAGS_algorithm == "rsa-1024" ||
        FLAGS_algorithm == "rsa-2048") {
      RsaKey* key = GetRsaKey(size, out);
      if (key == nullptr) {
        printf("Can't new rsa-key\n");
        return 1;
      }
      int size_input = 0;
      int size_output = 512;
      byte* input = nullptr;
      byte buffer[512];
      byte output[512];
      int size_key = key->bit_size_modulus_ / NBITSINBYTE;

      if (!ReadaFile(FLAGS_input_file.c_str(), &size_input, &input)) {
        printf("PkcsPubSealWithKey can't read %s\n", FLAGS_input_file.c_str());
        return 1;
      }
      if (!PkcsEmbed(size_input, input, size_key, buffer)) {
        printf("can't pkcs embed\n");
        return 1;
      }
      if (!key->Decrypt(size_key, buffer, &size_output, output)) {
        printf("can't RsaDecrypt\n");
        return 1;
      }
      if (!WriteaFile(FLAGS_output_file.c_str(), size_output, output)) {
        printf("couldn't write outputfile\n");
        return 1;
      }
    } else {
      printf("unsupported algorithm");
      return 1;
    }
  } else if ("PkcsPubUnsealWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      printf("PkcsPubUnsealWithKey can't read %s\n", FLAGS_key_file.c_str());
      return 1;
    }
    if (FLAGS_algorithm == "rsa-1024" || FLAGS_algorithm == "rsa-2048") {
      RsaKey* key = GetRsaKey(size, out);
      if (key == nullptr) {
        printf("Can't new rsa-key\n");
        return 1;
      }

      int input_size = 0;
      byte* input = nullptr;
      if (!ReadaFile(FLAGS_input_file.c_str(), &input_size, &input)) {
        printf("PkcsPubUnsealWithKey can't read %s\n",
               FLAGS_input_file.c_str());
        return 1;
      }
      int size_output = 512;
      byte buffer[512];
      byte output[512];
      int size_key = key->bit_size_modulus_ / NBITSINBYTE;
      if (!key->Encrypt(size_key, input, &size_output, buffer)) {
        printf("Can't RsaEncrypt\n");
        return 1;
      }
      if (!PkcsExtract(size_key, buffer, &size_output, output)) {
        printf("can't pkcs extract\n");
        return 1;
      }
      if (!WriteaFile(FLAGS_output_file.c_str(), size_output, output)) {
        printf("couldn't write outputfile\n");
        return 1;
      }
    } else {
      printf("unsupported alg\n");
    }
  } else if ("SignDigestWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;
    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }
  } else if ("VerifyDigestWithKey" == FLAGS_operation) {
    int size = 0;
    byte* out = nullptr;

    if (!ReadaFile(FLAGS_key_file.c_str(), &size, &out)) {
      return 1;
    }

    // bool RsaVerify(RsaKey* key, const char* hashalg, byte* hash, byte* input)
  } else {
    printf("%s: unsupported operation\n", FLAGS_operation.c_str());
  }
  CloseUtilities();

  return 0;
}
