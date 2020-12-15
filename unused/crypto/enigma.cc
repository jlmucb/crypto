#include <stdio.h>
#include <time.h>
#include <string.h>

//  enigma d simulator - three rotors, no plugboard

// Encryption equation:
//   (p)KC(i)WC(-i)C(j)VC(-j)C(k)UC(-k)RC(k)UinvC(-k)C(j)VinvC(-j)C(i)WinvC(-i)Kinv = c
  
const char* Input=     "abcdefghijklmnopqrstuvwxyz";
const char* Keyboard=  "qwertzuioasdfghjkpyxcvbnml";  // Kinv
const char* Rotor1=    "lpgszmhaeoqkvxrfybutnicjdw";  // W
const char* Rotor2=    "slvgbtfxjqohewirzyamkpcndu";  // V
const char* Rotor3=    "cjgdpshkturawzxfmynqobvlie";  // U
const char* Reflector ="imetcfgraysqbzxwlhkdvupojn";  // Reflector

class pair {
public:
  char a, b;
};

int num_pairs = 0;
pair PlugBoard[26];

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

void build_plugboard(int n, int num_plugs, pair* pl, byte* pb_perm) {
  for (int i = 0; i < n; i++)
    pb_perm[i] = i;
  byte t, t1, t2;
  for (int j = 0; j < num_plugs; j++) {
    t1 = index_from_lc_letter(pl[j].a);
    t2 = index_from_lc_letter(pl[j].b);
    t = pb_perm[t1];
    pb_perm[t1] = pb_perm[t2];
    pb_perm[t2] = t;
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

class enigma {
public:
  static const int r3_turnover = 13;
  static const int r2_turnover = 13;
  static const int r1_turnover = 13;
  byte plugboard_[26];
  byte keyboard_[26];
  byte reflector_[26];
  byte reflector_inv_[26];
  byte rotor1_[26];
  byte rotor2_[26];
  byte rotor3_[26];
  byte keyboard_inv_[26];
  byte plugboard_inv_[26];
  byte rotor1_inv_[26];
  byte rotor2_inv_[26];
  byte rotor3_inv_[26];
  int rotor_position_[3];

  enigma(const char* keyb, const char* reflb, const char* r1, const char* r2,
         const char* r3);
  void forward_state();
  void set_rotor_position(int r1, int r2, int r3);
  void print_state();
  void encrypt(const char* plain, const char* cipher);
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

enigma::enigma(const char* keyb, const char* reflb, const char* r1, const char* r2,
        const char* r3) {
  for (int i = 0; i < 26; i++)
    keyboard_[i] = index_from_lc_letter(keyb[i]);
  for (int i = 0; i < 26; i++)
    reflector_[i] = index_from_lc_letter(reflb[i]);
  for (int i = 0; i < 26; i++)
    rotor1_[i] = index_from_lc_letter(r1[i]);
  for (int i = 0; i < 26; i++)
    rotor2_[i] = index_from_lc_letter(r2[i]);
  for (int i = 0; i < 26; i++)
    rotor3_[i] = index_from_lc_letter(r3[i]);

  build_plugboard(26, num_pairs, PlugBoard, plugboard_);

  compute_inverse(26, keyboard_, keyboard_inv_);
  compute_inverse(26, reflector_, reflector_inv_);
  compute_inverse(26, rotor1_, rotor1_inv_);
  compute_inverse(26, rotor2_, rotor2_inv_);
  compute_inverse(26, rotor3_, rotor3_inv_);
  compute_inverse(26, plugboard_, plugboard_inv_);

  if (!check_inverse(26, keyboard_, keyboard_inv_))
    printf("KB check failed\n");
  if (!check_inverse(26, rotor1_, rotor1_inv_))
    printf("R1 check failed\n");
  if (!check_inverse(26, rotor2_, rotor2_inv_))
    printf("R2 check failed\n");
  if (!check_inverse(26, rotor3_, rotor3_inv_))
    printf("R3 check failed\n");
  if (!check_inverse(26, reflector_, reflector_))
    printf("Reflector check failed\n\n");
  if (!check_inverse(26, plugboard_, plugboard_inv_))
    printf("Plugboard check failed\n\n");
}

byte apply_rotated_perm(int n, byte* perm, byte pt, int rot) {
  int ind = (rot + pt) % n ;
  byte t = perm[ind];
  return (t + n - rot) % n;
}

// Fix this
void enigma::forward_state() {
  int r1 = rotor_position_[0];
  int r2 = rotor_position_[1];
  int r3 = rotor_position_[2];

  rotor_position_[2]= (rotor_position_[2] + 1) % 26;
  if (r3 == r3_turnover)
    rotor_position_[1]= (rotor_position_[1] + 1) % 26;
  if (r2 == r2_turnover)
    rotor_position_[0]= (rotor_position_[0] + 1) % 26;
}

void enigma::set_rotor_position(int r1, int r2, int r3) {
  rotor_position_[0] = r1;
  rotor_position_[1] = r2;
  rotor_position_[2] = r3;
}

void enigma::print_state() {
  printf("\nMachine state:\n");
  printf("  Input    : ");
  print_char_array(26, Input);
  printf("\n");
  printf("  Keyboard : ");
  print_byte_array(26, keyboard_);
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
  printf("  Reflector: ");
  print_byte_array(26, reflector_);
  printf("\n");
  printf("  Plugboard: ");
  print_byte_array(26, plugboard_);
  printf("\n");
  
  for (int i = 0; i < 3; i++) {
    printf("  rotor %d in position %d ", i + 1, rotor_position_[i]);
    printf("\n");
  }
  printf("\n");
}

//   (p)KinvC(i)R1C(-i)C(j)R2C(-j)C(k)R3C(-k)RC(k)R3invC(-k)C(j)R2invC(-j)C(i)R1invC(-i)K = c
void enigma::encrypt(const char* plain, const char* cipher) {
  byte t1, t2;
  char* p = (char*)plain;
  char* q = (char*)cipher;

  while (*p != '\0') {
    t1 = index_from_uc_letter(*p);
    t2 = apply_rotated_perm(26, keyboard_inv_, t1, 0);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor1_, t1, rotor_position_[0]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor2_, t1, rotor_position_[1]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor3_, t1, rotor_position_[2]);
    t1 = t2;
    t2 = apply_rotated_perm(26, reflector_, t1, 0);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor3_inv_, t1, rotor_position_[2]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor2_inv_, t1, rotor_position_[1]);
    t1 = t2;
    t2 = apply_rotated_perm(26, rotor1_inv_, t1, rotor_position_[0]);
    t1 = t2;
    t2 = apply_rotated_perm(26, keyboard_, t1, 0);
    *q = uc_letter_from_index(t2);
    forward_state();
    p++;
    q++;
  }
  *q = '\0';
}

// ---------------------------------------------------------------------------------------

int main(int an, char** av) {
  enigma machine(Keyboard, Reflector, Rotor1, Rotor2, Rotor3);
  const char* test_plain= 
    "HELLOTHERETHISISAMUCHLONGERMESSAGEFORBILLYFRIEDMANABRAHAMSINKOVSOLOMONKULLBACKANDFRANKROWLETT";
  const char* test_cipher = new char[strlen(test_plain) + 1];
  const char* test_decrypted_cipher = new char[strlen(test_plain) + 1];

  printf("Enigma D simulator\n");

  machine.set_rotor_position(1, 0, 7);
  machine.print_state();
  machine.encrypt(test_plain, test_cipher);

  machine.set_rotor_position(1, 0, 7);
  machine.encrypt(test_cipher, test_decrypted_cipher);

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

