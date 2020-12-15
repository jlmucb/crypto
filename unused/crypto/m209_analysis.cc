#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

//  M-209 Analysis

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

byte key_stream[] = {
  13, 12, 10,  9, 15, 22,  7, 10, 13,  2, 15,  3, 18, 23, 13,  0, 18, 17, 16,  7,
   9, 14, 13,  7, 11, 20, 10, 14,  2, 16, 11, 19,  2, 20, 16, 11,  5, 15,  9, 15,  
   4, 23, 21,  4, 10,  4,  7, 24, 16,  8, 18, 12, 13,  4, 12, 18,  9,  7, 15, 13,
  17,  0, 12, 12, 13, 16, 11, 21, 13, 19, 2, 14,  8, 20,  7, 13, 13,  6,  0, 21,
   8, 17,  9, 14, 13, 17, 13,  8, 17,  9, 20,  5, 22,  8, 10,  7, 12, 16,  8, 15,
   7,  6, 16, 13, 14, 19,  3, 19,  2, 17, 21, 14,  7, 15,  0, 15, 15, 17, 20,  9,
   6, 11,  5, 13, 11, 14, 18,  8, 10, 12, 12, 13, 13, 13, 12, 15, 18, 15, 12,  7,
   3, 14, 21,  6, 17,  2,  9, 16,  3, 25, 8, 14, 16, 15, 11, 18,  3, 14,  6, 14,
  18, 12,  5, 19,  5, 12, 11, 18, 11,  8, 17,  9, 17, 11, 17, 13,  7, 10, 13,  8,
  17, 11,  3, 12, 15,  9, 16, 18, 23, 11, 0, 14, 11,  9, 20, 16,  4, 15,  3, 18,
   6, 17, 12, 15, 11, 21,  0, 13,  0, 20, 17, 13, 20,  9,  7, 11, 12, 14, 18,  0,
  20, 11, 24,  7,  5,  7, 18,  4, 16, 17, 12,  9,  3, 14,  9, 22,  7, 24, 11, 17,
   5, 21,  5, 16, 10,  8, 10, 12,  9, 15,
};

const int num_wheels = 6;
int num_pins_on_wheel[num_wheels] = {
  26, 25, 23, 21, 19, 17,
};

// ---------------------------------------------------------------------------------------


double decimated_average(int decimation, int offset, int n, byte* letters) {

  int tot = 0;
  int sum = 0;
  for (int i = offset; i < n; i += decimation) {
    tot++;
    sum += letters[i];
  }
  return ((double) sum) / ((double) tot);
}

void graph_averages(int num_pins, double* averages) {
  int count[26];

  for (int i = 0; i < 26; i++)
    count[i] = 0;
  for (int i = 0; i < num_pins; i++) {
    count[(int)averages[i]]++;
  }
  for (int i = 0; i < 26; i++) {
    printf("   %2d: ", i);
    for (int j = 0; j < count[i]; j++)
      printf("x");
    printf("\n");
  }
}

class data {
public:
  int w_;
  int p_;
  double f_;
};

int pin_wheel_index(int w, int p) {
  return w * 26 + p;
}

void swap_data(data* d1, data* d2) {
    int i_w = d1->w_;
    int i_p = d1->p_;
    double x_f = d1->f_;
    d1->w_ = d2->w_;
    d1->p_ = d2->p_;
    d1->f_ = d2->f_;
    d2->w_ = i_w;
    d2->p_ = i_p;
    d2->f_ = x_f;
}

void sort_data(int n, data* d) {
  double largest;

  for (int i = 0; i < n; i++) {
    largest = d[i].f_;
    for (int j = (i + 1); j < n; j++) {
      if (d[j].f_ > d[i].f_)
        swap_data(&d[i], &d[j]);
    }
  }
}

void sorted_shifted_average(double shift, double* pin_wheel_averages) {
  int num_data = 0;
  for (int i = 0; i < num_wheels; i++) {
    num_data += num_pins_on_wheel[i];
  }

  int n = 0;
  data s_d[num_data];
  for (int i = 0; i < num_wheels; i++) {
    for (int j = 0; j < num_pins_on_wheel[i]; j++) {
      s_d[n].w_ = i + 1;
      s_d[n].p_ = j;
      s_d[n].f_ = pin_wheel_averages[pin_wheel_index(i, j)] - shift;
      n++;
    }
  }

  sort_data(n, s_d);

  const int to_print = 16;
  printf("\ntop %d sorted:\n", to_print);
  for (int i = 0; i < to_print; i++) {
    printf("  w: %d, p: %2d, f: %7.3lf\n",
      s_d[i].w_, s_d[i].p_, s_d[i].f_);
  }
  printf("\n");
}

int main(int an, char** av) {
  int key_len = sizeof(key_stream);
  double x;
  int wheel_num;
  int num_pins;
  int offset;
  double pin_wheel_averages[26 * num_wheels];
  double averages[26];

  printf("M209 analysis, key length is %d\n", key_len);

  int global_sum = 0;
  double global_average;
  for (int i = 0; i < key_len; i++) {
    global_sum += key_stream[i];
  }
  global_average= ((double)global_sum) / ((double) key_len);
  printf("\nGlobal average: %7.2f\n", global_average);

  for (wheel_num = 0; wheel_num < num_wheels; wheel_num++) {
    printf("\nWheel %d\n", wheel_num + 1);
    for (offset = 0; offset < num_pins_on_wheel[wheel_num]; offset++) {
      x = decimated_average(num_pins_on_wheel[wheel_num], offset, key_len, key_stream);
      printf("  pin %2d: %7.2lf\n", offset, x);
      averages[offset] = x;
      pin_wheel_averages[pin_wheel_index(wheel_num, offset)] = x;
    }
    printf("\n");
    graph_averages(num_pins_on_wheel[wheel_num], averages);
  }

  sorted_shifted_average(global_average, pin_wheel_averages);

  return 0;
}

// ---------------------------------------------------------------------------------------

