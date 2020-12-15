#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

//  M-209 simulator

// Encryption equation:
//   c = k - p (mod 26)
  
#ifndef byte
typedef unsigned char byte;
#endif

byte index_from_lc_letter(char c) {
  return (byte) (c - 'a');
}

char uc_letter_from_index(byte b) {
  return (char) (b + 'A');
}

byte index_from_uc_letter(char c) {
  return (byte) (c - 'A');
}

char lc_letter_from_index(byte b) {
  return (char) (b + 'a');
}

void print_char_array(int n, const char* a) {
  for (int i = 0; i < n; i++) {
    printf("%c", a[i]);
  }
}

void print_byte_array(int n, byte* a) {
  for (int i = 0; i < n; i++) {
    printf("%c", uc_letter_from_index(a[i]));
  }
}

class pair {
public:
  int a_, b_;
};

// six wheels: 26, 25, 23, 21, 19, 17
int wheel_size[] = {
  26, 25, 23, 21, 19, 17,
};
class wheel {
public:
  int num_pins_;
  byte pins_[26];
};

// suffices to list number of lugs for each wheel position
const int n_w = 6;
const int n_b = 27;
class m209 {
public:
  int wheel_positions_[n_w];
  wheel w_[n_w];
  int lug_count_[n_w];

  m209();
  void set_wheel_positions(int* w_p);
  void set_active_pins(unsigned* active_pins);
  void set_lug_count(int* lug_count);
  void forward_state();
  int count_positions();
  void print_state();
  void encrypt(const char* plain, const char* cipher);
};

void m209::set_active_pins(unsigned* active_pins) {
  for (int i = 0; i < n_w; i++) {
    w_[i].num_pins_ = wheel_size[i];
    for (int j = 0; j < w_[i].num_pins_; j++) {
      w_[i].pins_[j] = 0;
    }
  }
  for (int i = 0; i < n_w; i++) {
    unsigned u = active_pins[i];
    for (int j = 0; j < w_[i].num_pins_; j++) {
      w_[i].pins_[j] = u & 1;
      u >>= 1;
    }
  }
}

void m209::set_lug_count(int* lc) {
  int total_lugs = 0;
  for (int i = 0; i < n_w; i++) {
    lug_count_[i] = lc[i];
    total_lugs += lc[i];
  }
  // should be 27 or 54
  printf("Total lugs is %d\n", total_lugs);
}

m209::m209() {
  for (int i = 0; i < n_w; i++) {
    w_[i].num_pins_ = wheel_size[i];
  }
}

void m209::set_wheel_positions(int* w_p) {
  for (int i = 0; i < n_w; i++)
    wheel_positions_[i] = w_p[i];
}

void m209::forward_state() {
  for (int i = 0; i < n_w; i++) {
    wheel_positions_[i] = (wheel_positions_[i] + 1) % w_[i].num_pins_;
  }
}

void m209::print_state() {
  printf("\nMachine state:\n");
  for (int i = 0; i < n_w; i++) {
    printf(" wheel[%d]: ", i);
    for (int j = 0; j < w_[i].num_pins_; j++) {
      printf("%01d", w_[i].pins_[j]);
    }
    printf("\n");
  }
  printf(" lugs on wheel: ");
  for (int i = 0; i < n_w; i++) {
      printf("%02d ", lug_count_[i]);
  }
  printf("\n");
  printf(" wheel positions: ");
  for (int i = 0; i < n_w; i++) {
    printf("%d ", wheel_positions_[i]);
  }
  printf("\n");
  printf("\n");
  
}

int m209::count_positions() {
  int n = 0;

  for (int i = 0; i < n_w; i++) {
    if (w_[i].pins_[wheel_positions_[i]])
        n += lug_count_[i];
  }
  return n;
}

void m209::encrypt(const char* plain, const char* cipher) {
  char* p = (char*)plain;
  char* q = (char*)cipher;

  int k;
  byte l;
  byte t;

  printf("keystream: ");
  while (*p != '\0') {
    l = index_from_uc_letter(*p);
    k = count_positions();
printf("%02d ", k);
    t = (26 + k - l) % 26;
    *q= uc_letter_from_index(t);
    forward_state();
    p++;
    q++;
  }
printf("\n");
  *q = '\0';
}

// ---------------------------------------------------------------------------------------

int main(int an, char** av) {
  int w_p[n_w] = {
    0,0,0,0,0,0,
  };
  unsigned active_pins[n_w] = {
    0x0a2a50aa, 0x03433430, 0x0fcac6c1c, 0x01553575,
    0x0f39a320a, 0x061361a3,
  };
  int l_c[6] = {
    4, 5, 3, 7, 2, 6,
  };

  m209 machine;
  machine.set_wheel_positions(w_p);
  machine.set_lug_count(l_c);
  machine.set_active_pins(active_pins);

  int key_len = 0;
  bool key_stream_only = false;
  for (int i = 0; i < an; i++) {
    if (strcmp(av[i], "-keystream") == 0) {
      if ((an - 1) > i) {
        key_len = atoi(av[i + 1]);
        key_stream_only = true;
      } else {
        return 1;
      }
    }
  }

  if (key_stream_only) {
    int k;
    printf("Keystream only %d letters\n", key_len);
    for (int i = 0; i < key_len; i++) {
      k = machine.count_positions();
      machine.forward_state();
      printf("%2d, ", k % 26);
    }
    return 0;
  }

  const char* test_plain= 
    "HELLOTHERETHISISAMUCHLONGERMESSAGEFORBILLYFRIEDMANABRAHAMSINKOVSOLOMONKULLBACKANDFRANKROWLETT";
  const char* test_cipher = new char[strlen(test_plain) + 1];
  const char* test_decrypted_cipher = new char[strlen(test_plain) + 1];

  printf("M209 simulator\n");

  machine.print_state();
  machine.encrypt(test_plain, test_cipher);
  machine.set_wheel_positions(w_p);
  machine.encrypt(test_cipher, test_decrypted_cipher);
  printf("\nMessage is %d letters long\n", (int)strlen(test_plain));
  printf("Plain    : %s\n", test_plain);
  printf("Cipher   : %s\n", test_cipher);
  printf("Decrypted: %s\n", test_decrypted_cipher);
  machine.print_state();

  delete []test_cipher;
  delete []test_decrypted_cipher;

  return 0;
}

// ---------------------------------------------------------------------------------------

