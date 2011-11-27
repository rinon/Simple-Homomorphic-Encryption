#ifndef FULLY_HOMOMORPHIC_H
#define FULLY_HOMOMORPHIC_H

#include "type_defs.h"
#include <cstdio>
#include <cmath>
#include <gmp.h>
#include "utilities.h"
#include "circuit.h"
#include "security_settings.h"
#include <cryptopp/osrng.h>
#include <vector>
#include <stack>

class FullyHomomorphic {
 private:
  static unsigned int MAX_SOMEWHAT_PUBLIC_KEY_TRIES;
  // Wanted to make these consts, but I can't since I need to init a bigint in each
  SecuritySettings *sec;
  /*
  unsigned long int lambda;
  unsigned long int gamma;
  unsigned long int eta;
  unsigned long int rho;
  unsigned long int rho_;
  unsigned long int tau;
  unsigned long int kappa;
  unsigned long int theta;
  unsigned long int big_theta;
  */
  gmp_randstate_t rand_state;
  CryptoPP::RandomPool rng;

  /*
  unsigned long int private_key_length;
  unsigned long int public_key_old_key_length;
  unsigned long int public_key_y_vector_length;
  */

  void create_somewhat_private_key(SomewhatPrivateKey private_key);
  void create_somewhat_public_key(SomewhatPublicKey result, SomewhatPrivateKey sk);
  void create_additional_somewhat_public_key(SomewhatPublicKey result, SomewhatPrivateKey sk);
  void choose_random_d(mpz_t result, SomewhatPrivateKey p);
  unsigned int* create_S_vector();
  void create_u_vector(mpz_t_arr result, mpz_t x_p, unsigned int* S);

  void store_cipher_bit(FILE* stream, CipherBit &c);
 public:
  FullyHomomorphic(SecuritySettings *security_settings);
  void key_gen(PrivateKey &sk, PublicKey &pk);
  void print_key(const PrivateKey &sk, const PublicKey &pk);
  void print_cipher_bit(const CipherBit &c);
  void encrypt_bit(CipherBit &result, const PublicKey &pk, const bool m);
  bool decrypt_bit(const CipherBit &c, const PrivateKey &sk);
  void clear_cipher_bit(CipherBit &c);
  CipherBit** encrypt_bit_vector(const PublicKey &pk, const bool* m_vector, const unsigned long int m_vector_length);
  bool* decrypt_bit_vector(const PrivateKey &sk, CipherBit** c_vector, const unsigned long int c_vector_length);
  //std::vector<CipherBit> evaluate(CircuitNode *circuit, std::vector<CipherBit> inputs);
  CipherBit** evaluate(std::vector<Gate*> output_gates, CipherBit** inputs, const PublicKey &pk);
  std::vector<Gate*> create_decryption_cicuit();
  Gate*** create_3_for_2_circuit(Gate** a, Gate** b, Gate** c, unsigned int n);
  void test_decryption_circuit(const PublicKey &pk, const PrivateKey &sk);

  bool is_allowed_circuit(std::vector<Gate*> output_gates);

  /* static CipherBit TRUE; */
  /* static CipherBit FALSE; */

  // For debugging
  mpz_t ssk;
  void old_encrypt_bit(mpz_t result, const PublicKey &pk, const bool m);
};

#endif //FULLY_HOMOMORPHIC_H
