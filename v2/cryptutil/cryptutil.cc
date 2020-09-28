// Copyright 2014-2020, John Manferdelli, All Rights Reserved.
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
// File: cryptutil.cc

#include <gflags/gflags.h>
#include "crypto_support.h"
#include "aes.h"
#include "crypto_names.h"
#include "ecc.h"
#include "hmac_sha256.h"
#include "pbkdf.h"
#include "rsa.h"
#include "sha3.h"
#include "tea.h"
#include "big_num_functions.h"
#include "encryption_scheme.h"
#include "intel_digit_arith.h"
#include "pkcs.h"
#include "sha1.h"
#include "simonspeck.h"
#include "twofish.h"
#include "big_num.h"
#include "ecc_curve_data.h"
#include "hash.h"
#include "lattice.h"
#include "rc4.h"
#include "sha256.h"
#include "symmetric_cipher.h"


int num_cryptutil_ops = 28;
std::string cryptutil_ops[] = {
    "--operation=tobase64 --direction=[left-right|right-left] " \
    "--input_file=file --output_file=file",
    "--operation=frombase64 --direction=[left-right|right-left] " \
    "--input_file=file --output_file=file",
    "--operation=tohex --direction=[left-right|right-left] --input_file=file " \
    "--output_file=file",
    "--operation=fromhex--direction=[left-right|right-left] --input_file=file " \
    "--output_file=file",
    "--operation=todecimal --direction=[left-right|right-left] " \
    "--input_file=file --output_file=file",
    "--operation=fromdecimal --direction=[left-right|right-left] " \
    "--input_file=file --output_file=file",
    "\n",
    "--operation=get_random --size=num-bits --output_file=file",
    "--operation=read_key --input_file=file",
    "--operation=generate_key --algorithm=alg --key_name=name " \
    "--purpose=pur --owner=own --duration=dur --output_file=file" \
    "\n",
    "--operation=hash --algorithm=alg --input_file=file",
    "--operation=generate_mac --algorithm=alg --key_file=file --input_file=file " \
    "--output_file=file",
    "--operation=verify_mac --algorithm=alg --keyfile=file --input_file=file " \
    "--input2_file=file" \
    "\n",
    "--operation=encrypt_with_key --key_file=key_file --algorithm=alg " \
    "--input_file=file --output_file=file",
    "--operation=decrypt_with_key --key_file=key_file --algorithm=alg " \
    "--input_file=file --output_file=file"
    "\n",
    "--operation=generate_scheme --algorithm=alg --key_name=name " \
    "--duration=dur --output_file=file",
    "--operation=read_scheme --algorithm=alg --key_name=name" \
    " --duration=dur --input_file=file" \
    "\n",
    "--operation=scheme_encrypt --scheme_file=scheme_file " \
    "--algorithm=alg --input_file=file --output_file=file",
    "--operation=schem_decrypt --scheme_file=scheme_file" \
    " --algorithm=alg --input_file=file --output_file=file" \
    "\n",
    "--operation=pkcs_sign_with_key --algorithm=alg --keyfile=file " \
    "--hash_file= file --input_file=file --output_file=file",
    "--operation=pkcs_verify_with_key --algorithm=alg --keyfile=file " \
    "--hash_file= file --sig_file= file",
    "--operation=pkcs_seal_with_key--keyfile=file --algorithm=alg " \
    "--input_file=file --output_file=file",
    "--operation=pkcs_unseal_with_key--keyfile=file --algorithm=alg " \
    "--input_file=file --output_file=file",
};

int num_cryptutil_algs = 23;
std::string cryptalgs[] = {
    "aes", "rsa", "ecc", "sha-1", "sha-256", "sha-3",
    "hmac-sha-256", "pbdkf", "twofish", "tea", "simon"};

void print_options() {
  printf("Permitted operations:\n\n");
  for (int i = 0; i < num_cryptutil_ops; i++) {
    printf("  cryptutil.exe %s\n", cryptutil_ops[i].c_str());
  }
  printf("\nCryptographic algorithms:\n");
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
DEFINE_int32(size, 128, "size");
DEFINE_string(hash_file, "", "file to hash");
DEFINE_string(hash_alg, "sha-256", "hash alg");
DEFINE_string(sig_file, "", "signature");
DEFINE_string(proteced_key_file, "", "protected key file");
DEFINE_string(unproteced_key_file, "", "unprotected key file");

DEFINE_bool(print_all, false, "printall flag");


int main(int an, char** av) {
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
  num_cryptutil_ops = sizeof(cryptutil_ops) / sizeof(std::string);
  num_cryptutil_algs =  sizeof(cryptalgs) / sizeof(std::string);

  if (FLAGS_operation == "") {
    std::cout << "No operation specified.\n\n";
    print_options();
    return 1;
  }
  printf("operation flag: %s\n", FLAGS_operation.c_str());

  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  if ("tobase64" == FLAGS_operation) {
  } else if ("todecimal" == FLAGS_operation) {
  } else if ("tohex" == FLAGS_operation) {
  } else if ("fromhex" == FLAGS_operation) {
  } else if ("fromdecimal" == FLAGS_operation) {
  } else if ("frombase64" == FLAGS_operation) {
  } else if ("hash" == FLAGS_operation) {
  } else if ("encrypt_with_key" == FLAGS_operation) {
    if (FLAGS_algorithm == "aes") {
    } else if (FLAGS_algorithm == "twofish") {
    } else if (FLAGS_algorithm == "rc4") {
    } else if (FLAGS_algorithm == "simon") {
    } else if (FLAGS_algorithm == "tea") {
    } else {
      printf("unknown encryption alg %s\n", FLAGS_algorithm.c_str());
    }
  } else if ("decrypt_with_key" == FLAGS_operation) {
    if (FLAGS_algorithm == "aes") {
    } else if (FLAGS_algorithm == "twofish") {
    } else if (FLAGS_algorithm == "simon") {
    } else if (FLAGS_algorithm == "rc4") {
    } else if (FLAGS_algorithm == "tea") {
    } else {
      printf("Decrypt: Unknown encryption alg\n");
    }
  } else if ("scheme_decrypt" == FLAGS_operation) {
    if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
    } else {
      printf("scheme_decrypt: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      return 1;
    }
  } else if ("scheme_encrypt" == FLAGS_operation) {
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
    } else if (FLAGS_algorithm == "aes128-ctr-hmacsha256-sympad") {
    } else {
      printf("scheme_encrypt: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      return 1;
    }
  } else if ("generate_scheme" == FLAGS_operation) {
  } else if ("generate__key" == FLAGS_operation) {
  } else if ("read_key" == FLAGS_operation) {
  } else if ("get_random" == FLAGS_operation) {
  } else if ("read_scheme" == FLAGS_operation) {
  } else if ("encrypt_with_scheme" == FLAGS_operation) {
  } else if ("decrypt_with_password" == FLAGS_operation) {
  } else if ("pkcs_sign_with_key" == FLAGS_operation) {
  } else if ("pkcs_verify_with_key" == FLAGS_operation) {
  } else if ("pkcs_seal_with_key" == FLAGS_operation) {
  } else if ("pkcs_unseal_with_key" == FLAGS_operation) {
  } else if ("sign_digest_with_key" == FLAGS_operation) {
  } else if ("verify_digest_with_key" == FLAGS_operation) {
  } else {
    printf("%s: unsupported operation\n", FLAGS_operation.c_str());
  }

  close_crypto();

  return 0;
}
