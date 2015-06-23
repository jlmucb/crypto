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
// File: pwutil.cc

#include <gflags/gflags.h>
#include <stdio.h>
#include <string>
#include "pwutil.pb.h"
#include "cryptotypes.h"
#include "util.h"
#include <cmath>
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
#include "pkcs.h"
#include "pbkdf.h"
#include "bignum.h"

DEFINE_string(operation, "", "operation");
DEFINE_string(key, "", "key-file");
DEFINE_string(input, "", "input");
DEFINE_string(output, "", "output");
DEFINE_string(log_file, "pwutil_log_file", "log file");
DEFINE_string(algorithm, "aes128-cbc-hmacsha256-sympad", "algorithm");


AesCbcHmac256Sympad* GetAesCbcHmac256SymPad(int size, byte* in) {
printf("GetAesCbcHmac256SymPad\n");
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

#define BUFSIZE 8192

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
  int m;
  int n;
  int k;
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

  int m;
  int n;
  int k;
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


bool ToText(const pw_message& pw_data, const string& out_file) {
  return true;
}

bool FromText(const string& in_file, const pw_message* pw_data) {
  return true;
}

void WriteTextFile(const string& out_file, pw_message& pw_proto) {
  string name = pw_proto.pw_name();
  int epoch = pw_proto.pw_epoch();
  string status = pw_proto.pw_status();
  string secret = pw_proto.pw_value();

  FILE* out= fopen(out_file.c_str(), "w");

  fprintf(out, "name: %s\nepoch: %d\nstatus: %s\nsecret: %s\n", name.c_str(),
         epoch, status.c_str(), secret.c_str());
  pw_time* time_ptr = pw_proto.mutable_pw_time_point();
  int year = time_ptr->year();
  int month = time_ptr->month();
  int day = time_ptr->day();
  int hour = time_ptr->hour();
  int minutes = time_ptr->minutes();
  double seconds = time_ptr->seconds();
  fprintf(out, "time: %02d/%02d/%04d %02d:%02d.%6.2f\n", day,
         month, year, hour, minutes, seconds);
  fclose(out);
}

bool ReadTextFile(const string& in_file, pw_message* pw_proto) {
  const string name("/manferdelli/test1");
  const string status("active");
  const string secret("secret");
  TimePoint time_now;

  pw_proto->set_pw_name(name);
  pw_proto->set_pw_epoch(1);
  pw_proto->set_pw_status(status);
  pw_proto->set_pw_value(secret);
  pw_time* time_ptr = pw_proto->mutable_pw_time_point();
  time_now.TimePointNow();
  time_ptr->set_year(time_now.year_);
  time_ptr->set_month(time_now.month_);
  time_ptr->set_day(time_now.day_in_month_);
  time_ptr->set_hour(time_now.hour_);
  time_ptr->set_minutes(time_now.minutes_);
  time_ptr->set_seconds(time_now.seconds_);
  return true;
}

// pwutil.exe --operation=[wrap|unwrap|seal|unseal|to-text|from-text]
//   --key=keyfile --input=infile --output=outfile
int main(int an, char** av) {

#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif

  if (FLAGS_operation == "") {
    std::cout << "No operation specified.\n\n";
    printf("pwutil --action=[wrap|unwrap|seal|unseal|to-text|from-text] \\");
    printf("  [--key=keyfile] --input=infile --output=outfile\n");
    return 1;
  }
  if (FLAGS_input == "") {
    printf("no input file\n");
    return 1;
  }
  if (FLAGS_output == "") {
    printf("no output file\n");
    return 1;
  }
  if (FLAGS_operation == "to-text") {
    int proto_size = 0;
    byte* proto_buf = nullptr;

    if (!ReadaFile(FLAGS_input.c_str(), &proto_size, &proto_buf)) {
      printf("Can't read %s\n", FLAGS_input.c_str());
      return 1;
    }

    pw_message pw_proto;
    string proto_string;
    proto_string.assign((const char*)proto_buf, proto_size);
    pw_proto.ParseFromString(proto_string);

    WriteTextFile(FLAGS_output.c_str(), pw_proto);
  } else if (FLAGS_operation == "from-text") {
    pw_message pw_proto;

    if (!ReadTextFile(FLAGS_input, &pw_proto)) {
      printf("Can't read %s\n", FLAGS_input.c_str());
      return 1;
    }
    string out;
    pw_proto.SerializeToString(&out);
    WriteaFile(FLAGS_output.c_str(), out.length(), (byte*)out.data());
  } else if (FLAGS_operation == "wrap") {
    int proto_size = 0;
    byte* proto_buf = nullptr;

    if (!ReadaFile(FLAGS_input.c_str(), &proto_size, &proto_buf)) {
      printf("Can't read %s\n", FLAGS_input.c_str());
      return 1;
    }

    // get key and encrypt
    if (FLAGS_key == "") {
      printf("no key file\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      int scheme_size = 0;
      byte* scheme_out = nullptr;

      if (!ReadaFile(FLAGS_key.c_str(), &scheme_size, &scheme_out)) {
        printf("Can't read %s\n", FLAGS_key.c_str());
        return 1;
      }

      std::unique_ptr<AesCbcHmac256Sympad>
	  scheme(GetAesCbcHmac256SymPad(scheme_size, scheme_out));
      if (scheme == nullptr) {
        printf("No scheme\n");
        return 1;
      }
      scheme->PrintEncryptionAlgorithm();
      if (!CbcEncrypt(scheme.get(), FLAGS_input.c_str(),
                      FLAGS_output.c_str(), true)) {
	// delete out;
	printf("can't encrypt\n");
        return 1;
      }
      // delete out;
    } else if (FLAGS_algorithm !=
                   "aes128-ctr-hmacsha256-sympad") {
      // AesCtrHmac256Sympad* new_scheme = GetAesCtrHmac256SymPad(size, out);
    } else {
      printf("unsupported encryption scheme\n");
      return 1;
    }
  } else if (FLAGS_operation == "unwrap") {
    int encrypted_proto_size = 0;
    byte* encrypted_proto_buf = nullptr;

    if (!ReadaFile(FLAGS_input.c_str(), &encrypted_proto_size,
                   &encrypted_proto_buf)) {
      printf("Can't read %s\n", FLAGS_input.c_str());
      return 1;
    }

    // get key and decrypt
    if (FLAGS_key == "") {
      printf("no key file\n");
      return 1;
    }
    if (FLAGS_algorithm == "aes128-cbc-hmacsha256-sympad") {
      int scheme_size = 0;
      byte* scheme_out = nullptr;

      if (!ReadaFile(FLAGS_key.c_str(), &scheme_size, &scheme_out)) {
        printf("Can't read %s\n", FLAGS_key.c_str());
        return 1;
      }

      std::unique_ptr<AesCbcHmac256Sympad>
	  scheme(GetAesCbcHmac256SymPad(scheme_size, scheme_out));
      if (scheme == nullptr) {
        printf("No scheme\n");
        return 1;
      }
      scheme->PrintEncryptionAlgorithm();
      if (!CbcDecrypt(scheme.get(), FLAGS_input.c_str(),
                      FLAGS_output.c_str(), true)) {
	// delete out;
	printf("can't encrypt\n");
        return 1;
      }
      // delete out;
    } else if (FLAGS_algorithm ==
                   "aes128-ctr-hmacsha256-sympad") {
      // AesCtrHmac256Sympad* new_scheme = GetAesCtrHmac256SymPad(size, out);
    } else {
      printf("unsupported encryption scheme\n");
      return 1;
    }
  } else {
    printf("unsupported operation\n");
  }

  return 0;
}
