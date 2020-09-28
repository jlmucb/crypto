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
// File: splitsecret.cc

#include <stdio.h>
#include <string.h>
#include <gflags/gflags.h>
#include <string>
#include <sys/types.h>
#include "gf2_common.h"

#include <memory>
#include <cmath>

using namespace std;

bool Gf2EquationSetup(int size_min_poly, byte* min_poly, gf2_instance* instance,
      gf2_8* x) {
  gf2_8 a[48 * 48];

  if (!generate_invertible_matrix(48, size_min_poly, min_poly, a)) {
    printf("generate_invertible_matrix fails\n");
    return false;
  }

#if 0
  printf("\nGenerated matrix:\n");
  print_array(48, a);
  printf("\n");
#endif

  for (int i = 0; i < 48 * 48; i++) {
    gf2_8_copy(a[i], instance[i / 48].a_[i % 48]);
  }

  for (int j = 0; j < 48; j++) {
    if (!multiply_linear(48, size_min_poly, min_poly, instance[j].a_, x, instance[j].y_)) {
      printf("multiply_linear %d fails\n", j);
      return false;
    }
  }
  return true;
}

bool Generate(string& secretname, string& shardname, string& secretfile, bool generate_secret,
              int size_min_poly, byte* min_poly) {

  gf2_instance instance[48];
  gf2_8 solved_x[48];
  gf2_8 x[48];

  uint16_t u, w;
  int size;
  byte c[16];

  byte secret_to_split[16];
  if (generate_secret) {
    for (int i = 0; i < 16; i++) {
      if (!get_random_byte(false, (byte*)&w)) {
        printf("Can't generate secret\n");
        return false;
      }
      secret_to_split[i] = (byte)w;
    }
    int fd = open(secretfile.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
      printf("Can't create secrets file\n");
      return false;
    }
    write(fd, secret_to_split, 16);
    close(fd);
  } else {
    int fd = open(secretfile.c_str(), O_RDONLY);
    if (fd < 0) {
      printf("Can't open secrets file\n");
      return false;
    }
    read(fd, secret_to_split, 16);
    close(fd);
  }
  for (int i = 0; i < 16; i++) {
    w = (uint16_t)(secret_to_split[i]);
    size = 16;
    if (!to_internal_representation(w, &size, c)) {
      return false;
    }
    byte_8_copy(c, x[i].v_);
  }
  for (int i = 16; i < 48; i++) {
      if (!get_random_byte(false, (byte*)&w)) {
        printf("Can't generate secret 2\n");
        return 1;
      }
    size = 16;
    if (!to_internal_representation(w, &size, c)) {
      return false;
    }
    byte_8_copy(c, x[i].v_);
  }

  split_secret_message shards[5];
  string serialized_shard[5];
  char shard_file_name[256];

  for (;;) {
    if (!Gf2EquationSetup(size_min_poly, min_poly, instance, x)) {
      printf("Gf2EquationSetup failed\n");
      return false;
    }
    fill_shard(secretname, 1, 1, 5, 3, 1, 16, 48, instance, &shards[0]);
    fill_shard(secretname, 1, 1, 5, 3, 2, 16, 48, &instance[16], &shards[1]);
    fill_shard(secretname, 1, 1, 5, 3, 3, 16, 48, &instance[32], &shards[2]);
    if(gaussian_solve(48, size_min_poly, min_poly, instance, solved_x)) {
        break;
    }
  }

  // Serialize shards and write them
  for (int i = 0; i < 3; i++) {
    sprintf(shard_file_name, "%s%02d", shardname.c_str(), i);
    int fd = open(shard_file_name, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
      printf("Can't create shard file %s\n", shard_file_name);
      return false;
    }
    shards[i].SerializeToString(&serialized_shard[i]);
    write(fd, serialized_shard[i].data(), serialized_shard[i].size());
    close(fd);
    printf("shard %d\n", i);
    print_shard(shards[i]);
    printf("\n");
  }

  printf("\nsecret: ");
  for (int i = 0; i < 16; i++) {
    printf("%02x", secret_to_split[i]);
  }
  printf("\n");

  for (int i = 0; i < 48; i++) {
    if(!from_internal_representation(8, x[i].v_, &w)) {
      return false;
    }
    if(!from_internal_representation(8, solved_x[i].v_, &u)) {
      return false;
    }
    printf("x[%2d], solved_x[%2d]:  %02x %02x\n", i, i, w, u);
  }
  return true;
}

bool Recover(string& shardname, string& secretfile, int size_min_poly, byte* min_poly) {
  gf2_instance instance[48];
  gf2_8 solved_x[48];
  string serialized_shard[5];
  split_secret_message shards[5];
  char shard_file_name[256];
  byte serialized_shard_buf[4096];
  int size;
  byte c[16];
  uint16_t w;

  for (int i = 0; i < 3; i++) {
    sprintf(shard_file_name, "%s%02d", shardname.c_str(), i);
    int fd = open(shard_file_name, O_RDONLY);
    if (fd < 0) {
      printf("Can't open %s\n", shard_file_name);
      return false;
    }
    int n = read(fd, serialized_shard_buf, 4096);
    close(fd);
    serialized_shard[i].assign((const char*)serialized_shard_buf, (size_t)n);
    if (!shards[i].ParseFromString(serialized_shard[i])) {
      return false;
    }
    printf("shard %d\n", i);
    print_shard(shards[i]);
    printf("\n");
  }

  for (int i = 0; i < 48; i++) {
    const equation_message& e_msg = shards[i / 16].equations(i % 16);
    for (int j = 0; j < 48; j++) {
      w = (uint16_t) e_msg.coefficients(j);
      size = 16;
      if (!to_internal_representation(w, &size, c)) {
        return false;
      }
      byte_8_copy(c, instance[i].a_[j].v_);
    }
    w = (uint16_t) e_msg.value();
    size = 16;
    if (!to_internal_representation(w, &size, c)) {
      return false;
    }
    byte_8_copy(c, instance[i].y_.v_);
  }

  if(!gaussian_solve(48, size_min_poly, min_poly, instance, solved_x)) {
      return false;
  }

  // Write out secret
  byte split_secret[16];
  for (int i = 0; i < 16; i++) {
    size = 16;
    w = 0;
    if(!from_internal_representation(8, solved_x[i].v_, &w)) {
      return false;
    }
    split_secret[i] = (byte)w;
  }

  int fd = open(secretfile.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    printf("Can't create secret file %s\n", secretfile.c_str());
    return 1;
  }
  write(fd, split_secret, 16);
  close(fd);

  printf("Solved:\n");
  for (int i = 0; i < 48; i++) {
    size = 16;
    w = 0;
    if(!from_internal_representation(8, solved_x[i].v_, &w)) {
      return false;
    }
    printf("solved_x[%2d] = %02x\n", i, w);
  }

  printf("secret: ");
  for (int i = 0; i < 16; i++) {
    printf("%02x", split_secret[i]);
  }
  printf("\n");

  return true;
}

DEFINE_string(operation_name, "generate", "operation");
DEFINE_string(secretname, "JLM_Key", "secret name");
DEFINE_string(shardfilename, "secret_shard", "secret shard name");
DEFINE_string(secretfile, "secret.bin", "secret file name");
DEFINE_bool(generate_secret_flag, true, "generate secret flag");

int main(int an, char** av) {
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif

  printf("Shard secret, secret in %s, shards put in %s[1-5]\n", FLAGS_shardfilename.c_str(),
         FLAGS_secretfile.c_str());

  uint16_t minpoly = 0x11b;
  int size_min_poly = 16;
  byte min_poly[16];

  if (!to_internal_representation(minpoly, &size_min_poly, min_poly)) {
    return false;
  }
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");

  if (FLAGS_operation_name == "recover") {
    if (!Recover(FLAGS_shardfilename, FLAGS_secretfile, size_min_poly, min_poly)) {
      printf("Recover fails\n");
      return 1;
    }
  } else if (FLAGS_operation_name == "generate") {
    if (!Generate(FLAGS_secretname, FLAGS_shardfilename, FLAGS_secretfile,
            FLAGS_generate_secret_flag, size_min_poly, min_poly)) {
      printf("Recover fails\n");
      return 1;
    }
  } else {
    printf("Unsupported operation\n");
    return 1;
  }
  return 0;
}
