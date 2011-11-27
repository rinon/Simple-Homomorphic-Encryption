#include "fully_homomorphic.h"

int main(int argc, char** argv) {
  CryptoPP::AutoSeededRandomPool rng;
  SecuritySettings *security_settings = new SecuritySettings(5);
  FullyHomomorphic fh(security_settings);
  PrivateKey sk;
  PublicKey pk;
  fh.key_gen(sk, pk);
  //fh.print_key(sk, pk);

  /* Testing somewhat homomorphic scheme
  mpz_t c;
  while (true) {
	mpz_init(c);
	fh.old_encrypt_bit(c, pk, true);
	//mpz_out_str(NULL, 10, c);
	//printf("\n");
	printf("%u", old_decrypt_bit(c, fh.ssk));
	fflush(NULL);
	mpz_clear(c);
  }
  */

  /*
  bool* message = new bool[200];
  for (int i = 0; i < 100; i++) {
	message[2*i] = true;
	message[2*i+1] = true;
  }

  CipherBit** encrypted_message = fh.encrypt_bit_vector(pk, message, 200);
  std::vector<Gate*> gates;
  for (unsigned long int i = 0; i < 100; i++) {
	Gate *input1 = new Gate(Input, 2*i, security_settings);
	Gate *input2 = new Gate(Input, 2*i+1, security_settings);
	Gate *and_gate = new Gate(And, input1, input2, security_settings);
	Gate *output1 = new Gate(Output, and_gate, security_settings);
	input1->add_output(and_gate);
	input2->add_output(and_gate);
	and_gate->add_output(output1);
	gates.push_back(output1);
  }

  //Gate *input1 = new Gate(Input, encrypted_message[0], 4);
  //Gate *output1 = new Gate(Output, input1, 4);
  //input1->add_output(output1);

  CipherBit** evaluated_message = fh.evaluate(gates, encrypted_message, pk);
  bool* decrypted_message = fh.decrypt_bit_vector(sk, evaluated_message, 100);
  // Print out decrypted message, should match plaintext
  for (unsigned int i = 0; i < 100; i++) {
	printf("%u", decrypted_message[i]);
  }
  printf("\n");
  */

  fh.test_decryption_circuit(pk, sk);

  /* Testing circuit degree and norm
  std::vector<Gate*> gates;
  Gate* input1 = new Gate(Input, (unsigned long int) 0, security_settings);
  Gate* input2 = new Gate(Input, 1, security_settings);
  Gate* and_gate = new Gate(And, input1, input2, security_settings);
  input1->add_output(and_gate);
  input2->add_output(and_gate);
  Gate* and_gate2 = new Gate(And, and_gate, input2, security_settings);
  and_gate->add_output(and_gate2);
  input2->add_output(and_gate2);
  Gate* output = new Gate(Output, and_gate2, security_settings);
  and_gate2->add_output(output);
  gates.push_back(output);
  if (fh.is_allowed_circuit(gates))
	printf("Allowed circuit\n");
  else
	printf("NOT ALLOWED CIRCUIT!!\n");
  */
}
