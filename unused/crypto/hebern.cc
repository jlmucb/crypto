#include <stdio.h>
#include <time.h>
#include <string.h>

//  hebern simulator

// Encryption equation:
// (p) KC(i)UC(-i)C(j)VC(-j)C(k)WC(-k)C(l)XC(-l)C(m)YC(-m)L = c
//
//   Rotors 2 and 4 don’t rotate at all. They are “stators”.
//   Rotor 5 moves by 1 position with every step, it is a fast rotor.
//   Rotor 1 moves by 1 position with each complete turn of rotor 5.
//      It is a “semi-fast” rotor.
//   Rotor 3 moves by 1 position with each complete turn of rotor 1.
//     It is a slow rotor.

const char* Input=     "abcdefghijklmnopqrstuvwxyz";
const char* Keyboard=  "xakhszjlywgpmiourdbftnvcqe";
const char* Lampboard= "tyoeumxdfjqvkwbnshcilrzagp";
const char* Rotor1=    "gadboctknuzxiwhfqyjvpmelsr";
const char* Rotor2=    "iznctkudpjevowlfhxsmgqaybr";
const char* Rotor3=    "pjxfwltaugybmhrovnckseqizd";
const char* Rotor4=    "flvargwcmqbxnyiotjupskedhz";
const char* Rotor5=    "fqtgxanwcjoivzphybdrkuslem";

    
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

void compute_inverse(int n, byte* perm, byte* perm_inv) {
  for(int i = 0; i < n; i++) {
    perm_inv[perm[i]] = i;
  }
}

class hebern {
public:
  static const int r5_turnover = 13;
  static const int r1_turnover = 13;
  byte keyboard_[26];
  byte lampboard_[26];
  byte rotor1_[26];
  byte rotor2_[26];
  byte rotor3_[26];
  byte rotor4_[26];
  byte rotor5_[26];
  byte keyboard_inv_[26];
  byte lampboard_inv_[26];
  byte rotor1_inv_[26];
  byte rotor2_inv_[26];
  byte rotor3_inv_[26];
  byte rotor4_inv_[26];
  byte rotor5_inv_[26];
  int rotor_position_[5];

  hebern(const char* keyb, const char* lampb, const char* r1, const char* r2,
         const char* r3, const char* r4, const char* r5);
  void forward_state();
  void set_rotor_position(int r1, int r2, int r3, int r4, int r5);
  void print_state();
  void encrypt(const char* plain, const char* cipher);
  void decrypt(const char* cipher, const char* plain);
};

bool check_inverse(int n, byte* a, byte* b) {
  for (int i = 0; i < n; i++) {
    if (b[a[i]] != i)
      return false;
    if (a[b[i]] != i)
      return false;
  }
  return true;
}

hebern::hebern(const char* keyb, const char* lampb, const char* r1, const char* r2,
        const char* r3, const char* r4, const char* r5) {
  for (int i = 0; i < 26; i++)
    keyboard_[i] = index_from_lc_letter(keyb[i]);
  for (int i = 0; i < 26; i++)
    lampboard_[i] = index_from_lc_letter(lampb[i]);
  for (int i = 0; i < 26; i++)
    rotor1_[i] = index_from_lc_letter(r1[i]);
  for (int i = 0; i < 26; i++)
    rotor2_[i] = index_from_lc_letter(r2[i]);
  for (int i = 0; i < 26; i++)
    rotor3_[i] = index_from_lc_letter(r3[i]);
  for (int i = 0; i < 26; i++)
    rotor4_[i] = index_from_lc_letter(r4[i]);
  for (int i = 0; i < 26; i++)
    rotor5_[i] = index_from_lc_letter(r5[i]);

  compute_inverse(26, keyboard_, keyboard_inv_);
  compute_inverse(26, lampboard_, lampboard_inv_);
  compute_inverse(26, rotor1_, rotor1_inv_);
  compute_inverse(26, rotor2_, rotor2_inv_);
  compute_inverse(26, rotor3_, rotor3_inv_);
  compute_inverse(26, rotor4_, rotor4_inv_);
  compute_inverse(26, rotor5_, rotor5_inv_);

  if (!check_inverse(26, keyboard_, keyboard_inv_))
    printf("KB check failed\n");
  if (!check_inverse(26, lampboard_, lampboard_inv_))
    printf("LB check failed\n");
  if (!check_inverse(26, rotor1_, rotor1_inv_))
    printf("R1 check failed\n");
  if (!check_inverse(26, rotor2_, rotor2_inv_))
    printf("R2 check failed\n");
  if (!check_inverse(26, rotor3_, rotor3_inv_))
    printf("R3 check failed\n");
  if (!check_inverse(26, rotor4_, rotor4_inv_))
    printf("R4 check failed\n\n");
  if (!check_inverse(26, rotor5_, rotor5_inv_))
    printf("R5 check failed\n");
}

byte apply_rotated_perm(int n, byte* perm, byte pt, int rot) {
  int ind = (rot + pt) % n ;
  byte t = perm[ind];
  return (t + n - rot) % n;
}

void hebern::forward_state() {
  int r5 = rotor_position_[4];
  int r1 = rotor_position_[0];
  int r3 = rotor_position_[2];

  rotor_position_[4]= (rotor_position_[4] + 1) % 26;
  if (r5 == r5_turnover)
    rotor_position_[0]= (rotor_position_[0] + 1) % 26;
  if (r1 == r1_turnover)
    rotor_position_[2]= (rotor_position_[2] + 1) % 26;
}

void hebern::set_rotor_position(int r1, int r2, int r3, int r4, int r5) {
  rotor_position_[0] = r1;
  rotor_position_[1] = r2;
  rotor_position_[2] = r3;
  rotor_position_[3] = r4;
  rotor_position_[4] = r5;
}

void hebern::print_state() {
  printf("\nMachine state:\n");
  printf("  Input    : ");
  print_char_array(26, Input);
  printf("\n");
  printf("  Keyboard : ");
  print_byte_array(26, keyboard_);
  printf("\n");
  printf("  Lampboard: ");
  print_byte_array(26, lampboard_);
  printf("\n");
  printf("  Rotor 1  : ");
  print_byte_array(26, rotor1_);
  printf("\n");
  printf("  Rotor 2  : ");
  print_byte_array(26, rotor2_);
  printf("\n");
  printf("  Rotor 3  : ");
  print_byte_array(26, rotor3_);
  printf("\n");
  printf("  Rotor 4  : ");
  print_byte_array(26, rotor4_);
  printf("\n");
  printf("  Rotor 5  : ");
  print_byte_array(26, rotor5_);
  printf("\n");
  
  for (int i = 0; i < 5; i++) {
    printf("  rotor %d in position %d ", i + 1, rotor_position_[i]);
    printf("\n");
  }
  printf("\n");
}

// (p)KC(i)UC(-i)C(j)VC(-j)C(k)WC(-k)C(l)XC(-l)C(m)YC(-m)L = c
void hebern::encrypt(const char* plain, const char* cipher) {
  byte t1, t2;
  char* p = (char*)plain;
  char* q = (char*)cipher;

  while (*p != '\0') {
    t1 = index_from_uc_letter(*p);
    t2 = apply_rotated_perm(26, keyboard_, t1, 0);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor1_, t1, rotor_position_[0]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor2_, t1, rotor_position_[1]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor3_, t1, rotor_position_[2]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor4_, t1, rotor_position_[3]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor5_, t1, rotor_position_[4]);
    t1 = t2;
    t2 = apply_rotated_perm(26, lampboard_, t1, 0);
    *q = uc_letter_from_index(t2);
    forward_state();
    p++;
    q++;
  }
  *q = '\0';
}

// (c)LinvC(m)Yinvc(-m)C(l)XinvC(-l)C(k)WinvC(-k)C(j)VIncC(-j)C(i)UinvC(i)kInv = p
void hebern::decrypt(const char* cipher, const char* plain) {
  byte t1, t2;
  char* p = (char*)cipher;
  char* q = (char*)plain;

  while (*p != '\0') {
    t1 = index_from_uc_letter(*p);
    t2 = apply_rotated_perm(26, lampboard_inv_, t1, 0);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor5_inv_, t1, rotor_position_[4]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor4_inv_, t1, rotor_position_[3]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor3_inv_, t1, rotor_position_[2]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor2_inv_, t1, rotor_position_[1]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor1_inv_, t1, rotor_position_[0]);
    t1 = t2;
    t2 = apply_rotated_perm(26, keyboard_inv_, t1, 0);
    *q = uc_letter_from_index(t2);
    forward_state();
    p++;
    q++;
  }
  *q = '\0';
}

// ---------------------------------------------------------------------------------------

int main(int an, char** av) {
  hebern machine(Keyboard, Lampboard, Rotor1, Rotor2, Rotor3, Rotor4, Rotor5);
  const char* test_plain= 
    "HELLOTHERETHISISAMUCHLONGERMESSAGEFORBILLYFRIEDMANABRAHAMSINKOVSOLOMONKULLBACKANDFRANKROWLETT";
  const char* test_cipher = new char[strlen(test_plain) + 1];
  const char* test_decrypted_cipher = new char[strlen(test_plain) + 1];

  printf("Hebern simulator\n");

  machine.set_rotor_position(1, 0, 7, 0, 9);
  machine.print_state();
  machine.encrypt(test_plain, test_cipher);

  machine.set_rotor_position(1, 0, 7, 0, 9);
  machine.decrypt(test_cipher, test_decrypted_cipher);

  printf("Message is %d letters long\n", (int)strlen(test_plain));
  printf("Plain    : %s\n", test_plain);
  printf("Cipher   : %s\n", test_cipher);
  printf("Decrypted: %s\n", test_decrypted_cipher);
  machine.print_state();

  delete []test_cipher;
  delete []test_decrypted_cipher;

  return 0;
}

// ---------------------------------------------------------------------------------------

