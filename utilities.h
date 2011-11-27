#ifndef UTILITIES_H
#define UTILITIES_H
#include <gmp.h>

#define RESET     0
#define BRIGHT 	  1
#define DIM	      2
#define UNDERLINE 3
#define BLINK     4
#define REVERSE	  7
#define HIDDEN	  8

#define BLACK 	  0
#define RED		  1
#define GREEN	  2
#define YELLOW	  3
#define BLUE	  4
#define MAGENTA	  5
#define CYAN	  6
#define	WHITE	  7

#define COLOR_OUTPUT 1

void mpz_correct_mod(mpz_t result, mpz_t n, mpz_t d);
unsigned long int max(unsigned long int a, unsigned long int b);
void textcolor(int attr, int fg);
void resettextcolor();

#endif //UTILITIES_H
