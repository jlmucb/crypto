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


int num_cryptutil_ops;
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
    "encrypt_key_size=size --mac_key_size=size --duration=dur --output_file=file",
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

int num_cryptutil_algs;
std::string cryptalgs[] = {
    "aes", "rsa", "ecc", "sha-1", "sha-256", "sha-3",
    "hmac-sha-256", "pbdkf", "twofish", "tea", "simon",
    "aes-hmac-sha256-ctr", "aes-hmac-sha256-cbc",};

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
DEFINE_int32(encrypt_key_size, 128, "encrypt-key-size-in-bits");
DEFINE_int32(mac_key_size, 128, "mac-key-size-in-bits");
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
  int ret = 0;

  if ("tobase64" == FLAGS_operation) {
    file_util in_file;
    file_util out_file;

    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    int size_in = in_file.bytes_in_file();
    byte in_buf[size_in];
    in_file.close();
    if (in_file.read_file(FLAGS_input_file.c_str(), size_in, in_buf) < size_in) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    string bytes;
    string base64;
    bytes.assign((const char*) in_buf, (size_t) size_in);
    if (!bytes_to_base64(bytes, &base64)) {
      printf("Can't convert to base64\n");
      ret = 1;
      goto done;
    }
    if (!out_file.write_file(FLAGS_output_file.c_str(), (int) base64.size(),
            (byte*) base64.data())) {
      printf("Can't write %s\n", FLAGS_output_file.c_str());
      ret = 1;
      goto done;
    }
    goto done;
  } else if ("frombase64" == FLAGS_operation) {
    // base64_to_bytes(string& b64, string* b);
  } else if ("todecimal" == FLAGS_operation) {
    // digit_convert_to_decimal(int size_a, uint64_t* n, string* s);
  } else if ("fromdecimal" == FLAGS_operation) {
    // digit_convert_from_decimal(string& s, int size_n, uint64_t* n);
  } else if ("tohex" == FLAGS_operation) {
    // bytes_to_hex(string& b, string* h);
  } else if ("fromhex" == FLAGS_operation) {
    // hex_to_bytes(string& h, string* b);
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
  } else if ("generate_scheme" == FLAGS_operation) {
    // scheme_message* make_scheme(const char* alg, const char* id_name,
    //   const char* mode, const char* pad, const char* purpose,
    //   const char* not_before, const char* not_after,
    //   const char* enc_alg, int size_enc_key, string& enc_key,
    //   const char* enc_key_name, const char* hmac_alg,
    //   int size_hmac_key,  string& hmac_key, int size_nonce,
    //   string& nonce);
    if (FLAGS_algorithm == "aes-hmac-sha256-ctr") {
    } else if (FLAGS_algorithm == "aes-hmac-sha256-cbc") {
    } else {
      printf("scheme_decrypt: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      ret = 1;
      goto done;
    }
  } else if ("read_scheme" == FLAGS_operation) {
    // scheme_message scheme_msg;
  } else if ("scheme_encrypt" == FLAGS_operation) {
    if (FLAGS_algorithm == "aes-hmac-sha256-ctr") {

      // bool init(const char* alg, const char* id_name,
      // const char* mode, const char* pad, const char* purpose,
      // const char* not_before, const char* not_after,
      // const char* enc_alg, int size_enc_key, string& enc_key,
      // const char* enc_key_name, const char* hmac_alg,
      // int size_hmac_key,  string& hmac_key, int size_nonce,
      // string& nonce);
      // bool encrypt_message(int size_in, byte* in, int size_out, byte* out);
      // bool decrypt_message(int size_in, byte* in, int size_out, byte* out);
    } else if (FLAGS_algorithm == "aes-hmac-sha256-cbc") {
    } else {
      printf("scheme_encrypt: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      ret = 1;
      goto done;
    }
  } else if ("scheme_decrypt" == FLAGS_operation) {
    // encryption_scheme
    if (FLAGS_algorithm == "aes-hmac-sha256-ctr") {
    } else if (FLAGS_algorithm == "aes-hmac-sha256-cbc") {
    } else {
      printf("scheme_decrypt: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      ret = 1;
      goto done;
    }
  } else if ("generate_key" == FLAGS_operation) {
  } else if ("read_key" == FLAGS_operation) {
  } else if ("get_random" == FLAGS_operation) {
    // int crypto_get_random_bytes(int num_bytes, byte* buf);
  } else if ("encrypt_with_scheme" == FLAGS_operation) {
  } else if ("decrypt_with_password" == FLAGS_operation) {
  } else if ("pkcs_sign_with_key" == FLAGS_operation) {
  } else if ("pkcs_verify_with_key" == FLAGS_operation) {
    if (FLAGS_algorithm == "aes-hmac-sha256-ctr") {
    } else if (FLAGS_algorithm == "aes-hmac-sha256-cbc") {
    } else {
      printf("scheme_decrypt: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      ret = 1;
      goto done;
    }
  } else if ("pkcs_seal_with_key" == FLAGS_operation) {
  } else if ("pkcs_unseal_with_key" == FLAGS_operation) {
  } else if ("sign_digest_with_key" == FLAGS_operation) {
  } else if ("verify_digest_with_key" == FLAGS_operation) {
  } else {
    printf("%s: unsupported operation\n", FLAGS_operation.c_str());
    ret = 1;
    goto done;
  }

done:
  close_crypto();
  return ret;
}
