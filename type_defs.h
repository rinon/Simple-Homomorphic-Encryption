#ifndef TYPE_DEFS_H
#define TYPE_DEFS_H

#include <vector>
#include <gmp.h>

/* struct KeyStruct { */
/*   PrivateKey sk; */
/*   PublicKey pk; */
/* }; */

/* typedef struct KeyStruct Key; */

typedef __mpz_struct** mpz_t_arr;

// Indicator vector of elements in public key which
// are part of the private key
typedef unsigned int* PrivateKey;

// Definitions of keys in the somewhat homomorphic scheme
typedef __mpz_struct** SomewhatPublicKey;
typedef mpz_t SomewhatPrivateKey;

struct PublicKeyStruct {
  SomewhatPublicKey old_key;
  SomewhatPublicKey old_key_extra; // Extra elements for optimization from section 3.3.1
  mpz_t_arr y_vector;
};

typedef struct PublicKeyStruct PublicKey;

struct CipherBitStruct {
  mpz_t old_ciphertext;
  unsigned long* z_vector;
};
typedef struct CipherBitStruct CipherBit;


#endif //TYPE_DEFS_H
