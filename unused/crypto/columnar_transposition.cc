#include "stdio.h"
#include <string>
using std::string;

const char* text =
  "m c g trfttsaocehyhrsayohalolcintTm cgt s ilcdlCtf aunods ng"\
  "c ea  e ts enuuc nnrcog e eam otsliy, ukrsima meuc aUotxgits"\
  "nmotr tad inw  e wafscfuus ttihdea dri d.yptlo in  2rtsatmts"\
  "s tipmCvhc  ecepnhors  oldlwc iin  iids,irornsraaeow acT tcg"\
  "cuemar blte nos ornoaBrstua p eosrsiro skdins eerfn ,nad.Cee"\
  "ae mp onle ,ueouov wf4 e teuiy.ceer Seiimfdi.l ige bbfl ehau"\
  "ndgaoecyi nypseuodii hhtddorn e  nsmone locsehpser c enteiio"\
  "i pml aykaoehbd roasitbsds";

const int num_cribs = 3;
const char* cribs[num_cribs] = {
  "Computer science",
  "UCSB",
  "computer science",
  };

const int N = 446;
const int stride = 6;
const int print_chars_per_line = 40;

const char* line[6] = {
  "Ceeae mp onle ,ueouov wf4 e teuiy.ceer Seiimfdi.l ige bbfl ehaundgaoecyi ny",
  "ornsraaeow acT tcgcuemar blte nos ornoaBrstua p eosrsiro skdins eerfn ,nad.",
  "m c g trfttsaocehyhrsayohalolcintTm cgt s ilcdlCtf aunods ngc ea  e ts enu ",
  "pseuodii hhtddorn e  nsmone locsehpser c enteiioi pml aykaoehbd roasitbsds ",
  "uc nnrcog e eam otsliy, ukrsima meuc aUotxgitsnmotr tad inw  e wafscfuus t ",
  "tihdea dri d.yptlo in  2rtsatmtss tipmCvhc  ecepnhors  oldlwc iin  iids,ir "
};

int char_count(const char* s) {
  int n = 0;
  while (*(s++) != '\0')
    n++;
  return n;
}

void print_long_column_map(int trial_stride, bool* long_col) {
  for (int j = 0; j < trial_stride; j++) {
    if(long_col[j])
      printf("L");
    else
      printf("S");
  }
}

void clear_long_assign(int trial_stride, bool* long_col) {
  for(int j = 0; j < trial_stride; j++)
    long_col[j] = false;
}

// Todo: Need to generalize this.
//   cols 5 and 6
void assign_long_columns(int trial_stride, int num_long_cols, bool* long_col) {
  long_col[3] = true;
  long_col[4] = true;
}

void make_trial_lines(int num_letters, const char* t, int trial_stride, bool* long_col,
      string** test_cols) {
  const char* current_char = t;
  int short_column_len = num_letters / trial_stride;

  for(int j = 0; j < trial_stride; j++)
    test_cols[j]->clear();

  for(int j = 0; j < trial_stride; j++) {
    for(int k = 0; k < short_column_len; k++) {
      *test_cols[j] += *(t++);
    }
    if (long_col[j]) {
      *test_cols[j] += *(t++);
    }
  }
}

void print_string(string& s) {
  printf("%s", s.c_str());
}

void print_test_columns(int num_cols, string** test_cols) {
  printf("\nTest columns:\n");
  for (int j = 0; j < num_cols; j++) {
    printf("  ");
    print_string(*test_cols[j]);
    printf("\n");
  }
  printf("\n");
    
}

bool get_row(int trial_stride, string** test_cols, int row_num, string* row) {

  for (int j = 0; j < trial_stride; j++) {
    if (row_num < test_cols[j]->length()) {
    const char* p = test_cols[j]->c_str();
      *row += p[row_num];
    }
  }
  return true;
}

void clear_rows(int num_rows, string* rows) {
  for (int j = 0; j < num_rows; j++)
    rows[j].clear();
}

bool get_rows(int trial_stride, string** test_cols, int num_rows, int row_num, string* rows) {
  for (int j = 0; j < num_rows; j++) {
    if(!get_row(trial_stride, test_cols, row_num + j, &rows[j]))
      return false;
  }
  return true;
}

void clear_positions(int num_positions, short int* positions) {
  for (int j = 0; j < num_positions; j++)
    positions[j] = 0;
}

int in_string(const char c, string& r) {
  const char* p = r.c_str();
  
  for (int j = 0; j < r.length(); j++)
    if (c == p[j])
      return j;
  return -1;
}

int position_match(int trial_stride, int num_rows, string* rows, const char c, int after) {
  int k;
  int seen_at;

  for (int j = 0; j < num_rows; j++) {
    k = in_string(c, rows[j]);
    if (k >= 0) {
      seen_at = trial_stride * j + k;
      // this could be faster, if it's the same character
      if (seen_at >= after)
        return trial_stride * j + k;
    }
  }
  return -1;
}

bool crib_in_rows(int trial_stride, const char* sorted_crib, int num_rows, string* rows) {

  // Note: the crib is sorted
  const char* p = sorted_crib;
  int m = 0;
  char last_seen = '*';
  int i = 0;
  while (*p != '\0') {
    if (*p == last_seen) {
      m = position_match(trial_stride, num_rows, rows, *p, m); 
    } else {
      m = position_match(trial_stride, num_rows, rows, *p, 0); 
    }
    if (m < 0)
      return false;
    last_seen = *p;
    p++;
    i++;
  }
  return true;
}

bool test_stride_with_crib(const char* t, int trial_stride, const char* original_crib, string& sorted_crib) {

  string** test_cols = new string*[trial_stride];
  for (int j = 0; j < trial_stride; j++) {
    test_cols[j] = new string;
  }

  int num_letters = char_count(t);
  int short_col_len = num_letters / trial_stride;
  int num_long_cols = num_letters - short_col_len * trial_stride;
  int num_short_cols = trial_stride - num_long_cols;
  bool long_col[trial_stride];

  printf("%d letters, trial stride is %d, %d long columns, %d short columns\n",
    num_letters, trial_stride, num_long_cols, num_short_cols); 

  // assign trial lines with short columns
  clear_long_assign(trial_stride, long_col);
  assign_long_columns(trial_stride, num_long_cols, long_col);
  make_trial_lines(num_letters, t, trial_stride, long_col, test_cols);
  print_test_columns(trial_stride, test_cols);
  printf("Long column map: ");
  print_long_column_map(trial_stride, long_col);
  printf("\n");

  int row_span = (strlen(original_crib) + trial_stride - 1) / trial_stride + 1;
  int num_rows = 10;
  string rows[10];
  for (int row_num = 0; row_num < short_col_len; row_num++) {
    clear_rows(row_span, rows);
    if (!get_rows(trial_stride, test_cols, row_span, row_num, rows)) {
      printf("get_rows failed\n");
      return false;
    }
    if (crib_in_rows(trial_stride, sorted_crib.c_str(), num_rows, rows)) {
      printf("Crib %s is in %d rows starting at %d\n", original_crib, row_span, row_num);
      printf("\t");
      for(int j = 0; j < row_span; j++) {
        printf("*");
        print_string(rows[j]);
        printf("*");
      }
      printf("\n");
    }
  }

  for (int j = 0; j < trial_stride; j++) {
    delete test_cols[j];
    test_cols[j] = nullptr;
  }
  return false;
}

bool sort_crib(const char* crib, string* sorted_crib) {
  sorted_crib->clear();

#if 0
  sorted_crib->append(crib);
#else
  int n = strlen(crib);
  char* t_s = new char[n];
  int i = 0;
  const char* p = crib;
  while (*p != '\0') {
    t_s[i++] = *p;
    p++;
  }
  char c;
  for (int i = 0; i < n; i++) {
      for (int j = (i+1); j < n; j++) {
        if (t_s[j] < t_s[i]) {
          c = t_s[j];
          t_s[j] = t_s[i];
          t_s[i] = c;
        }
      }
  }
  for (int i = 0; i < n; i++) {
    *sorted_crib += t_s[i];
  }
  delete []t_s;
#endif
  return true;
}

int main(int an, char** av) {
  int line_num, line_position;
  int num_chars_this_line = 0;
  const char* base;

  int num_chars = char_count(text);
  printf("\nLetters in text: %d\n", num_chars);

  string sorted_crib;
  for (int k = 0; k < num_cribs; k++) {
    if (!sort_crib(cribs[k], &sorted_crib)) {
      printf("Can't sort crib %s\n", cribs[k]);
      continue;
    }
    printf("Crib: %s, Sorted crib: %s\n", cribs[k], sorted_crib.c_str());
    test_stride_with_crib(text, 6, cribs[k], sorted_crib);
  }

  printf("\n\n");
  for (int n = 0; n < N; n++) {
    line_num= n%stride;
    line_position = n / stride;
    base = line[line_num];
    printf("%c", base[line_position]);

    num_chars_this_line++;
    if (num_chars_this_line >= print_chars_per_line && base[line_position]== ' ') {
      printf("\n");
      num_chars_this_line = 0;
    }
  }
  printf("\n\n");

  return 0;
}
