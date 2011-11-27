#include "utilities.h"

void mpz_correct_mod(mpz_t result, mpz_t n, mpz_t d) {
  mpz_tdiv_r(result, n, d);
  mpz_t temp;
  mpz_init(temp);
  mpz_fdiv_q_2exp(temp, d, 1);
  if (mpz_cmp(result, temp) > 0) {
	mpz_sub(result, d, result);
  }
  mpz_clear(temp);
}

unsigned long int max(unsigned long int a, unsigned long int b) {
  return (a > b) ? a : b;
}

void textcolor(int attr, int fg) {
  //char command[13];

  /* Command is the control command to the terminal */
  if (COLOR_OUTPUT)
	printf("%c[%d;%dm", 0x1B, attr, fg + 30);
  //printf("%s", command);
}

void resettextcolor() {
  if (COLOR_OUTPUT)
	printf("%c[0m", 0x1B);
}
