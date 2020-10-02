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
    "--operation=tobase64 " \
    "--input_file=file --output_file=file",
    "--operation=frombase64" \
    "--input_file=file --output_file=file",
    "--operation=tohex --input_file=file " \
    "--output_file=file",
    "--operation=fromhex  --input_file=file " \
    "--output_file=file",
    "--operation=todecimal " \
    "--input_file=file --output_file=file",
    "--operation=fromdecimal " \
    "--input_file=file --output_file=file",
    "\n",
    "--operation=generate_scheme --algorithm=alg --key_name=name " \
    "--encrypt_key_size=size --mac_key_size=size --duration=dur --scheme_file=file",
    "--operation=read_scheme --algorithm=alg --key_name=name" \
    " --duration=dur --scheme_file=file" \
    "\n",
    "--operation=scheme_encrypt --scheme_file=scheme_file " \
    "--algorithm=alg --input_file=file --output_file=file",
    "--operation=scheme_decrypt --scheme_file=scheme_file" \
    " --algorithm=alg --input_file=file --output_file=file" \
    "\n",
    "--operation=hash --algorithm=sha256 --input_file=in --output_file=out",
    "--operation=generate_mac --algorithm=alg --key_file=file --mac_key_size=256 " \
    "--input_file=file --output_file=file  --mac_key_size=256",
    "--operation=verify_mac --algorithm=alg --keyfile=file --input_file=file " \
    "--hash_file=file" \
    "\n",
    "--operation=get_random --size=num-bits --output_file=file",
    "--operation=read_key --input_file=file",
    "--operation=generate_key --algorithm=alg --key_name=name " \
    "--purpose=pur --owner=own --duration=dur --output_file=file" \
    "\n",
    "--operation=encrypt_with_key --key_file=key_file " \
    "--input_file=file --output_file=file",
    "--operation=decrypt_with_key --key_file=key_file " \
    "--input_file=file --output_file=file"
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
DEFINE_int32(random_size, 128, "random-size-in-bits");
DEFINE_int32(encrypt_key_size, 128, "encrypt-key-size-in-bits");
DEFINE_int32(mac_key_size, 128, "mac-key-size-in-bits");
DEFINE_int32(key_size, 128, "key-size-in-bits");
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

const int size_of_64_bit_unsigned = 7;
const int max_hash = 256;

bool read_key(key_message* km) {
  file_util in_file;
    if (!in_file.open(FLAGS_key_file.c_str())) {
      printf("Can't open %s\n", FLAGS_key_file.c_str());
      return false;
    }
    int size_in = in_file.bytes_in_file();
    in_file.close();
    byte in[size_in];
    if (!in_file.read_file(FLAGS_key_file.c_str(), size_in, in)) {
      printf("Can't read %s\n", FLAGS_key_file.c_str());
      return false;
    }
   string s;
   s.assign((char*)in, size_in);
   km->ParseFromString(s);
  return true;
}


bool read_scheme(scheme_message* msg) {
  file_util in_file;
  printf("File: %s\n", FLAGS_scheme_file.c_str());

  if (!in_file.open(FLAGS_scheme_file.c_str())) {
    printf("Can't open %s\n", FLAGS_scheme_file.c_str());
    return false;
  }
  int size_in = in_file.bytes_in_file();
  byte in_buf[size_in];
  in_file.close();
  if (in_file.read_file(FLAGS_scheme_file.c_str(), size_in, in_buf) < size_in) {
    printf("Can't read %s\n", FLAGS_scheme_file.c_str());
    return false;
  }
  string serialized;
  serialized.assign( (char*)in_buf, (size_t)size_in);
  msg->ParseFromString(serialized);
  return true;
}

bool keys_from_pass_phrase(const char* phrase, int* size, byte* key) {
  sha256 h;
  memset(key,0, *size);

  if ((*size) < h.DIGESTBYTESIZE) {
    printf("keys_from_pass_phrase(%d): buffer too small, %s\n", *size, phrase);
    return false;
  }
  int num_passes = (*size) / h.DIGESTBYTESIZE;
  byte salt_buf[32];
  for (int i = 0; i < num_passes; i++) {
    h.init();
    sprintf((char*)salt_buf, "JLM_salt_%d", i + 3);
    h.add_to_hash(strlen((char*)salt_buf), (byte*)salt_buf);
    h.add_to_hash(strlen(phrase), (byte*)phrase);
    h.add_to_hash(strlen((char*)salt_buf), (byte*)salt_buf);
    h.finalize();
    h.get_digest(h.DIGESTBYTESIZE, &key[i * h.DIGESTBYTESIZE]);
  }
  *size = num_passes * h.DIGESTBYTESIZE;
  return true;
}


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

    file_util out_file;
    if (!out_file.write_file(FLAGS_output_file.c_str(), (int) base64.size(),
            (byte*) base64.data())) {
      printf("Can't write %s\n", FLAGS_output_file.c_str());
      ret = 1;
      goto done;
    }
    goto done;
  } else if ("frombase64" == FLAGS_operation) {
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
    base64.assign((const char*) in_buf, (size_t) size_in);
    if (!base64_to_bytes(base64, &bytes)) {
      printf("Can't convert from base64\n");
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
  } else if ("to_decimal" == FLAGS_operation) {
    file_util in_file;
    printf("Input file: %s, ", FLAGS_input_file.c_str());
    printf("output file: %s\n", FLAGS_output_file.c_str());

    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return false;
    }
    int size_in = in_file.bytes_in_file();

    byte in_buf[size_in];
    in_file.close();
    if (in_file.read_file(FLAGS_input_file.c_str(), size_in, in_buf) < size_in) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }

    int size_n = (size_in + size_of_64_bit_unsigned - 1) / size_of_64_bit_unsigned;
    big_num n(size_n);

    string bytes;
    bytes.assign((char*)in_buf, size_in);
    printf("bytes in: "); print_bytes((int)bytes.size(), (byte*)bytes.data());

    if (bytes_to_u64_array(bytes, n.capacity(), n.value_ptr()) < 0) {
      printf("Can't convert to uint array\n");
      ret = 1;
      goto done;
    }
    n.normalize();

    string decimal;
    if (!digit_convert_to_decimal(n.capacity(), n.value_ptr(), &decimal)) {
      printf("Can't convert to decimal\n");
      ret = 1;
      goto done;
    }
    printf("number: "); n.print();printf("\n");
    printf("decimal: ");
    if (n.is_negative())
      printf("-");
    printf("%s\n", decimal.c_str());
    goto done;

  } else if ("from_decimal" == FLAGS_operation) {
    printf("Input file: %s, ", FLAGS_input_file.c_str());
    printf("output file: %s\n", FLAGS_output_file.c_str());

    file_util in_file;
    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return false;
    }
    int size_in = in_file.bytes_in_file();
    in_file.close();

    byte in_buf[size_in + 1];
    in_buf[size_in] = 0;
    if (in_file.read_file(FLAGS_input_file.c_str(), size_in, in_buf) < size_in) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    printf("decimal string: %s\n", (const char*) in_buf);

    string bytes;
    string decimal;

    bool sign = false;
    char* in = (char*)in_buf;
    char* p = in;
    while (*p != '\0') {
      if (*p == ' ') {
        p++;
        in = p;
        continue;
      } else if (*p == '-') {
        sign = true;
        p++;
        in = p;
        continue;
      } else if (*p < '0' || *p > '9') {
        *p = 0;
        break;
      }
      p++;
    }
    decimal.assign((const char*)in);
    
    big_num* n = big_convert_from_decimal(decimal);
    if (n == nullptr) {
      printf("Can't convert to big_num\n");
      ret = 1;
      goto done;
    }
    n->normalize();
    int size_out = u64_array_to_bytes(n->size(), n->value_ptr(), &bytes);
    if (size_out < 0) {
      printf("Can't convert u64 to bytes\n");
      ret = 1;
      goto done;
    }

    file_util out_file;
    if (!out_file.write_file(FLAGS_output_file.c_str(), (int) bytes.size(),
            (byte*) bytes.data())) {
      printf("Can't write %s\n", FLAGS_output_file.c_str());
      ret = 1;
      goto done;
    }
    if (sign)
      n->toggle_sign();
    printf("number :"); n->print(); printf("\n");
    printf("bytes  :"); print_bytes((int) bytes.size(), (byte*)bytes.data());
    delete n;
    goto done;
  } else if ("tohex" == FLAGS_operation) {
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
    string hex;
    bytes.assign((const char*) in_buf, (size_t) size_in);
    if (!bytes_to_hex(bytes, &bytes)) {
      printf("Can't convert to hex\n");
      ret = 1;
      goto done;
    }
    if (!out_file.write_file(FLAGS_output_file.c_str(), (int) hex.size(),
            (byte*) hex.data())) {
      printf("Can't write %s\n", FLAGS_output_file.c_str());
      ret = 1;
      goto done;
    }
    goto done;
  } else if ("fromhex" == FLAGS_operation) {
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
    string hex;
    hex.assign((const char*) in_buf, (size_t) size_in);
    if (!hex_to_bytes(hex, &bytes)) {
      printf("Can't convert to base64\n");
      ret = 1;
      goto done;
    }
    if (!out_file.write_file(FLAGS_output_file.c_str(), (int) bytes.size(),
            (byte*) bytes.data())) {
      printf("Can't write %s\n", FLAGS_output_file.c_str());
      ret = 1;
      goto done;
    }
    goto done;
  } else if ("encrypt_with_key" == FLAGS_operation ||
             "decrypt_with_key" == FLAGS_operation) {
    key_message* km = new key_message;
    if (!read_key(km)) {
      printf("Can't read %s\n", FLAGS_key_file.c_str());
      ret = 1;
      goto done;
    }
    int block_size;
    print_key_message(*km);

    if (!km->has_key_size() || !km->has_secret() ||
        !km->has_algorithm_type()) {
      printf("Can't get keys\n");
      ret = 1;
      goto done;
    }
    const char* alg = km->algorithm_type().c_str();
    int key_size_bit = km->key_size();
    int key_size_byte =  key_size_bit / NBITSINBYTE;
    byte* key = (byte*)km->secret().data();

    if (strcmp(alg, "aes") == 0) {
      block_size = aes::BLOCKBYTESIZE;
    } else if (strcmp(alg,  "twofish") == 0) {
      block_size = two_fish::BLOCKBYTESIZE;
    } else if (strcmp(alg,  "rc4") == 0) {
      block_size = 1;  // its a stream cipher
    } else if (strcmp(alg,  "simon") == 0) {
      block_size = simon128::BLOCKBYTESIZE;
    } else if (strcmp(alg,  "tea") == 0) {
      block_size = tea::BLOCKBYTESIZE;
    } else {
      printf("unknown encryption alg %s\n", FLAGS_algorithm.c_str());
    }

    file_util in_file;

    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    int size_in = in_file.bytes_in_file();
    in_file.close();
    int in_out_size = (size_in + block_size - 1) / block_size;;
    in_out_size *= block_size;
    byte in[in_out_size];
    byte out[in_out_size];
    memset(in, 0, in_out_size);
    memset(out, 0, in_out_size);

    if (in_file.read_file(FLAGS_input_file.c_str(), size_in, in) < size_in) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }

    if (strcmp(alg, "aes") == 0) {
      aes t;
      if (!t.init(key_size_bit, key, aes::BOTH)) {
        printf("Can't init aes\n");
        ret = 1;
        goto done;
      }
      if ("encrypt_with_key" == FLAGS_operation) {
        t.encrypt(in_out_size, in, out);
      } else {
        t.decrypt(in_out_size, in, out);
      }
    } else if (strcmp(alg, "twofish") == 0) {
    } else if (strcmp(alg, "rc4") == 0) {
    } else if (strcmp(alg, "simon") == 0) {
    } else if (strcmp(alg, "tea") == 0) {
    } else {
      printf("unknown encryption alg %s\n", FLAGS_algorithm.c_str());
    }

    printf("in       : "); print_bytes(in_out_size, in);
    printf("out      : "); print_bytes(in_out_size, out);

    file_util out_file;
    out_file.write_file(FLAGS_output_file.c_str(), in_out_size, out);
  } else if ("generate_scheme" == FLAGS_operation) {
    int size_nonce = 128 / NBITSINBYTE;
    int size_enc_key = FLAGS_encrypt_key_size / NBITSINBYTE;
    int size_hmac_key = FLAGS_mac_key_size / NBITSINBYTE;
    byte e_key[size_enc_key];
    byte m_key[size_hmac_key];
    byte n_key[size_enc_key];
    string enc_key;
    string mac_key;
    string nonce;

    // make keys and nonces and set them in strings
    if (crypto_get_random_bytes(size_nonce, n_key) < size_nonce) {
      printf("Can't generate nonce\n");
      ret = 1;
      goto done;
    }
    if (crypto_get_random_bytes(size_enc_key, e_key) < size_enc_key) {
      printf("Can't generate enc key\n");
      ret = 1;
      goto done;
    }
    if (crypto_get_random_bytes(size_hmac_key, m_key) < size_hmac_key) {
      printf("Can't generate enc key\n");
      ret = 1;
      goto done;
    }
    nonce.assign((const char*) n_key, (size_t) size_nonce);
    enc_key.assign((const char*) e_key, (size_t) size_enc_key);
    mac_key.assign((const char*) m_key, (size_t) size_hmac_key);

    // notbefore, notafter
    time_point t1, t2;
    t1.time_now();
    string s1, s2;
    if (!t1.encode_time(&s1)) {
      ret = 1;
      goto done;
    }
    t2.add_interval_to_time(t1, 5 * 365 * 86400.0);
    if (!t2.encode_time(&s2)) {
      ret = 1;
      goto done;
    }

    char* mode;
    const char* pad = "sym-pad";
    char* enc_alg;
    char* hmac_alg;

    if (FLAGS_algorithm == "aes-hmac-sha256-ctr") {
      mode = (char*)"ctr";
      enc_alg = (char*)"aes";
      hmac_alg = (char*)"hmac-sha256";
    } else if (FLAGS_algorithm == "aes-hmac-sha256-cbc") {
      mode = (char*)"cbc";
      enc_alg = (char*)"aes";
      hmac_alg = (char*)"hmac-sha256";
    } else {
      printf("scheme_decrypt: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      ret = 1;
      goto done;
    }
    scheme_message* msg = make_scheme(FLAGS_algorithm.c_str(),
          FLAGS_key_name.c_str(), mode, pad, "", s1.c_str(),
          s2.c_str(), enc_alg, FLAGS_encrypt_key_size, enc_key,
          FLAGS_key_name.c_str(), hmac_alg, FLAGS_mac_key_size, mac_key);
    if ( msg == nullptr) {
      printf("Can't create scheme message\n");
      ret = 1;
      goto done;
    }
    string serialized;
    msg->SerializeToString(&serialized);
    file_util out_file;
     if (!out_file.write_file(FLAGS_scheme_file.c_str(), (int) serialized.size(),
          (byte*) serialized.data())) {
      printf("Can't write %s\n", FLAGS_scheme_file.c_str());
      ret = 1;
      goto done;
    }
    print_scheme_message(*msg);
    goto done;
  } else if ("read_scheme" == FLAGS_operation) {
    scheme_message msg;
    if (!read_scheme(&msg)) {
      ret = 1;
      goto done;
    }
    print_scheme_message(msg);
  } else if ("scheme_encrypt" == FLAGS_operation ||
      "scheme_decrypt" == FLAGS_operation) {
    encryption_scheme scheme;
    scheme.scheme_msg_ = new scheme_message;
    if (scheme.scheme_msg_ == nullptr) {
      ret = 1;
      goto done;
    }
    if (!read_scheme(scheme.scheme_msg_)) {
      ret = 1;
      goto done;
    }
    print_scheme_message(*scheme.scheme_msg_);
    if (!scheme.recover_encryption_scheme_from_message()) {
      ret = 1;
      goto done;
    }
    if (!scheme.recover_encryption_scheme_from_message()) {
      printf("Can't recover encryption scheme\n");
      ret = 1;
      goto done;
    }
    if (!scheme.init()) {
      printf("Can't init encryption scheme\n");
      ret = 1;
      goto done;
    }

    file_util in_file;
    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    int size_in = in_file.bytes_in_file();
    in_file.close();
    byte in[size_in];
    if (!in_file.read_file(FLAGS_input_file.c_str(), size_in, in)) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }

    if ("scheme_encrypt" == FLAGS_operation) {
      int size_out = size_in + 3 * scheme.get_block_size() + scheme.get_mac_size();
      byte out[size_out];
      printf("\nPlain (%d): ", size_in);
      print_bytes(size_in, in);
      printf("\n");
      if (!scheme.encrypt_message(size_in, in, size_out, out)) {
        printf("Scheme encrypt failed\n");
        ret = 1;
        goto done;
      }
      file_util out_file;
      out_file.write_file(FLAGS_output_file.c_str(), scheme.get_total_bytes_output(), out);
      printf("Encrypted (%d): ", scheme.get_total_bytes_output());
      print_bytes(scheme.get_total_bytes_output(), out);
      printf("\n");
    } else {
      int size_out = size_in;
      byte out[size_out];
      printf("\nCipher (%d): ", size_in);
      print_bytes(size_in, in);
      printf("\n");
      if (!scheme.decrypt_message(size_in, in, size_out, out)) {
        printf("Scheme decrypt failed\n");
        ret = 1;
        goto done;
      }
      file_util out_file;
      out_file.write_file(FLAGS_output_file.c_str(), scheme.get_bytes_encrypted(), out);
      printf("Decrypted (%d): ", scheme.get_bytes_encrypted());
      print_bytes(scheme.get_bytes_encrypted(), out);
      printf("\n");
    }
  } else if ("get_random" == FLAGS_operation) {
    byte buf[FLAGS_random_size];
    int byte_size = (FLAGS_random_size + NBITSINBYTE - 1) / NBITSINBYTE;
    if (crypto_get_random_bytes(byte_size, buf) < byte_size) {
      printf("Can't generate random\n");
      ret = 1;
      goto done;
    }
    file_util out_file;
    out_file.write_file(FLAGS_output_file.c_str(), byte_size, buf);
    printf("Random bytes (%d): ", byte_size);
    print_bytes(byte_size, buf);
    printf("\n");
    goto done;
  } else if ("encrypt_with_password" == FLAGS_operation ||
             "decrypt_with_password" == FLAGS_operation) {
    encryption_scheme scheme;
    scheme.scheme_msg_ = new scheme_message;
    if (scheme.scheme_msg_ == nullptr) {
      ret = 1;
      goto done;
    }
    char* enc_alg;
    char* hmac_alg;
    char* mode;
    char* pad;

    if (FLAGS_algorithm == "aes-hmac-sha256-ctr") {
      mode = (char*)"ctr";
      pad = (char*)"sym-pad";
      enc_alg = (char*)"aes";
      hmac_alg = (char*)"hmac-sha256";
    } else if (FLAGS_algorithm == "aes-hmac-sha256-cbc") {
      pad = (char*)"sym-pad";
      mode = (char*)"cbc";
      enc_alg = (char*)"aes";
      hmac_alg = (char*)"hmac-sha256";
    } else {
      printf("password: unsupported algorithm %s\n",
              FLAGS_algorithm.c_str());
      ret = 1;
      goto done;
    }
    int size_enc_key_bytes = FLAGS_encrypt_key_size / NBITSINBYTE;
    int size_hmac_key_bytes = FLAGS_mac_key_size / NBITSINBYTE;
    string enc_key;
    string mac_key;

    int tmp_key_size = size_enc_key_bytes + size_hmac_key_bytes + 16;
    byte tmp_key[tmp_key_size];
    const char* salt_str = "jlm ucb math"; 
    const int num_iter = 100;
    if (!pbkdf2(FLAGS_pass.c_str(), strlen(salt_str), (byte*)salt_str,
                num_iter, tmp_key_size, tmp_key)) {
        printf("Password derivation failed\n");
        ret = 1;
        goto done;
    }
    printf("Pass phrase: %s, tmp key size: %d\n", FLAGS_pass.c_str(), tmp_key_size);
    enc_key.assign((char*)tmp_key, (size_t)size_enc_key_bytes);
    mac_key.assign((char*)&tmp_key[size_enc_key_bytes], (size_t)size_hmac_key_bytes);
    if (!scheme.init(FLAGS_algorithm.c_str(), "",
          mode, pad, "", "now", "later", enc_alg, FLAGS_encrypt_key_size, enc_key,
          "tmpkey", hmac_alg, FLAGS_mac_key_size,  mac_key)) {
      printf("password: can't init scheme\n");
        ret = 1;
      goto done;
    }

    file_util in_file;
    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    int size_in = in_file.bytes_in_file();
    in_file.close();
    byte in[size_in];
    if (!in_file.read_file(FLAGS_input_file.c_str(), size_in, in)) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }

    printf("Derived encryption key: "); print_bytes((int)enc_key.size(), (byte*)enc_key.data());
    printf("Derived mac key: "); print_bytes((int)mac_key.size(), (byte*)mac_key.data());

    if ("encrypt_with_password" == FLAGS_operation) {
      int size_out = size_in + 3 * scheme.get_block_size() + scheme.get_mac_size();
      byte out[size_out];
      printf("\nPlain (%d): ", size_in);
      print_bytes(size_in, in);
      printf("\n");
      if (!scheme.encrypt_message(size_in, in, size_out, out)) {
        printf("Scheme encrypt failed\n");
        ret = 1;
        goto done;
      }
      file_util out_file;
      out_file.write_file(FLAGS_output_file.c_str(), scheme.get_total_bytes_output(), out);
      printf("Encrypted (%d): ", scheme.get_total_bytes_output());
      print_bytes(scheme.get_total_bytes_output(), out);
      printf("\n");
    } else {
      int size_out = size_in;
      byte out[size_out];
      printf("\nCipher (%d): ", size_in);
      print_bytes(size_in, in);
      printf("\n");
      if (!scheme.decrypt_message(size_in, in, size_out, out)) {
        printf("Scheme decrypt failed\n");
        ret = 1;
        goto done;
      }
      file_util out_file;
      out_file.write_file(FLAGS_output_file.c_str(), scheme.get_bytes_encrypted(), out);
      printf("Decrypted (%d): ", scheme.get_bytes_encrypted());
      print_bytes(scheme.get_bytes_encrypted(), out);
      printf("\n");
    }
    goto done;
  } else if ("hash" == FLAGS_operation) {

    file_util in_file;
    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    int size_in = in_file.bytes_in_file();
    in_file.close();
    byte in[size_in];
    if (!in_file.read_file(FLAGS_input_file.c_str(), size_in, in)) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      ret = 1;
      goto done;
    }
    byte hash[max_hash];
    int hash_size_bytes = 0;

    if (strcmp("sha1", FLAGS_algorithm.c_str()) == 0) {
      sha1 h;
 
      hash_size_bytes = h.DIGESTBYTESIZE; 
      h.init();
      h.add_to_hash(size_in, in);
      h.finalize();
      h.get_digest(hash_size_bytes, hash);
    } else if (strcmp("sha256", FLAGS_algorithm.c_str()) == 0) {
      sha256 h;
 
      hash_size_bytes = h.DIGESTBYTESIZE; 
      h.init();
      h.add_to_hash(size_in, in);
      h.finalize();
      h.get_digest(hash_size_bytes, hash);
    } else if (strcmp("sha3", FLAGS_algorithm.c_str()) == 0) {
      sha3 h(512);
 
      hash_size_bytes = h.DIGESTBYTESIZE; 
      h.init();
      h.add_to_hash(size_in, in);
      h.finalize();
      h.get_digest(hash_size_bytes, hash);
    } else {
      printf("%s: unsupported algorithm\n", FLAGS_algorithm.c_str());
    }

    printf("to hash : "); print_bytes(size_in, in);
    printf("hash    : "); print_bytes(hash_size_bytes, hash);
    goto done;
  } else if ("generate_key" == FLAGS_operation) {

    // notbefore, notafter
    time_point t1, t2;
    t1.time_now();
    string s1, s2;
    if (!t1.encode_time(&s1)) {
      ret = 1;
      goto done;
    }
    t2.add_interval_to_time(t1, 5 * 365 * 86400.0);
    if (!t2.encode_time(&s2)) {
      ret = 1;
      goto done;
    }
    key_message* km = nullptr;
    int byte_size =  (FLAGS_key_size + NBITSINBYTE - 1) / NBITSINBYTE;

    if (strcmp(FLAGS_algorithm.c_str(), "aes") == 0 ||
          strcmp(FLAGS_algorithm.c_str(), "twofish") == 0 ||
          strcmp(FLAGS_algorithm.c_str(), "tea") == 0 ||
          strcmp(FLAGS_algorithm.c_str(), "rc4") == 0) {
        byte key[byte_size];
        memset(key, 0, byte_size);

      if (crypto_get_random_bytes(byte_size, key) < byte_size) {
        printf("Can't generate random key\n");
        ret = 1;
        goto done;
      }
      string bytes;
      bytes.assign((char*)key, byte_size);
      km = make_symmetrickey(FLAGS_algorithm.c_str(), FLAGS_key_name.c_str(),
              FLAGS_key_size, "", s1.c_str(), s2.c_str(), bytes);
    } else if (strcmp(FLAGS_algorithm.c_str(), "rsa") == 0) {
    } else if (strcmp(FLAGS_algorithm.c_str(), "ecc") == 0) {
    } else {
      printf("Unknown key type\n");
      ret = 1;
      goto done;
    }
    if (km == nullptr) {
      printf("Can't print key message\n");
      ret = 1;
      goto done;
    }
    string s;
    km->SerializeToString(&s);
    file_util out_file;
    if (!out_file.write_file(FLAGS_key_file.c_str(), (int) s.size(), (byte*) s.data())) {
      printf("Can't write %s\n", FLAGS_key_file.c_str());
      ret = 1;
      goto done;
    }
    print_key_message(*km);
    delete km;
    goto done;
  } else if ("read_key" == FLAGS_operation) {
    key_message km;
    if (!read_key(&km)) {
      printf("Can't read key message\n");
      ret = 1;
      goto done;
    }
    print_key_message(km);
    goto done;
  } else if ("generate_mac" == FLAGS_operation ||
             "verify_mac" == FLAGS_operation) {

    file_util in_file;

    int byte_size = (FLAGS_key_size + NBITSINBYTE - 1) / NBITSINBYTE;
    byte hmac_key[byte_size];
    if (!in_file.read_file(FLAGS_key_file.c_str(), byte_size, hmac_key)) {
      printf("Can't read %s\n", FLAGS_key_file.c_str());
      return false;
    }

    if (!in_file.open(FLAGS_input_file.c_str())) {
      printf("Can't open %s\n", FLAGS_input_file.c_str());
      return false;
    }
    int size_in = in_file.bytes_in_file();
    in_file.close();

    byte in[size_in];
    if (!in_file.read_file(FLAGS_input_file.c_str(), size_in, in)) {
      printf("Can't read %s\n", FLAGS_input_file.c_str());
      return false;
    }
    byte hmac[max_hash];
    int mac_size;

    if (strcmp(FLAGS_algorithm.c_str(), "hmac-sha256") == 0) {
      hmac_sha256 m;

      mac_size = m.MACBYTESIZE;
      if (!m.init(byte_size, hmac_key)) {
        ret = 1;
        goto done;
      }
      m.add_to_inner_hash(size_in, in);
      m.finalize();
      if (!m.get_hmac(mac_size, hmac)) {
        ret = 1;
        goto done;
      }
    } else {
      printf("unsupported algorithm %s\n", FLAGS_algorithm.c_str());
      ret = 1;
      goto done;
    }
    printf("hmac key (%d): ", FLAGS_key_size); print_bytes(byte_size, hmac_key);
    printf("input (%d)   : ", size_in); print_bytes(size_in, in);
    printf("computed hmac: "); print_bytes(mac_size, hmac);

    if ("generate_mac" == FLAGS_operation) {

      file_util out_file;
      if (!out_file.write_file(FLAGS_output_file.c_str(), byte_size, hmac)) {
        printf("Can't write %s\n", FLAGS_output_file.c_str());
        ret = 1;
        goto done;
      }
    } else {
      byte recovered_hmac[mac_size];
      if (!in_file.read_file(FLAGS_input2_file.c_str(), byte_size, recovered_hmac)) {
        printf("Can't read %s\n", FLAGS_input2_file.c_str());
        return false;
      }
      if (memcmp(hmac, recovered_hmac, byte_size) == 0) {
        printf("mac verified\n");
      } else {
        printf("mac does not verify\n");
        print_bytes(byte_size, recovered_hmac);
      }
    }
    goto done;
  } else if ("pkcs_sign_with_key" == FLAGS_operation) {
  } else if ("pkcs_verify_with_key" == FLAGS_operation) {
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
