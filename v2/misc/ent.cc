#include <stdio.h>
#include <math.h>

double H(double p0) {
  if (p0 == 0.0 || p0 == 1.0)
    return 1.0;
  double p1 = 1.0 - p0;
  double x = 0.0;

  x= - p0 * log(p0) - p1 * log(p1);
  return x / log(2.0);
}

int main(int an, char** av) {
  double d = .05;
  double p0 = .05;
  double q0 = .05;
  double r0;

  // H(X^Y)
  printf("H(X^Y):\n");

  for (int i = 0; i < 10; i++) {
    q0 = .05;
    for (int j = 0; j < 10; j++) {
      r0 = p0 * (1.0 - q0) + (1.0 - p0) * q0;
      printf("    H(%4.2lf)= %8.5lf, H(%4.2lf)= %8.5lf, sum: %8.4lf, xored entropy: H(%4.2lf)= %8.5lf\n",
        p0, H(p0), q0, H(q0), H(p0) + H(q0), r0, H(r0));
      q0 += d;
    }
    p0 += d;
  }

  return 0;
}
