#include "fully_homomorphic.h"
#include "utilities.h"
#include "circuit.h"
#include "security_settings.h"

bool OUTPUT = true;

void test_encrypt_bit(FullyHomomorphic &fh, const PublicKey &pk, const PrivateKey &sk) {
  if (OUTPUT) {
	printf("----- TESTING ENCRYPTION OF A SINGLE BIT -----\n");
	printf("--- ENCRYPTING FALSE ---\n");
  }
  CipherBit c;
  bool result;
  for (int i = 0; i < 100; i++) {
	fh.encrypt_bit(c, pk, false);
	result = fh.decrypt_bit(c, sk);
	if (OUTPUT) {
	  printf("%u", result);
	  fflush(NULL);
	}
	fh.clear_cipher_bit(c);
  }
  if (OUTPUT) {
	printf("\n");
	printf("--- ENCRYPTING TRUE ---\n");
  }
  for (int i = 0; i < 100; i++) {
	fh.encrypt_bit(c, pk, true);
	result = fh.decrypt_bit(c, sk);
	if (OUTPUT) {
	  printf("%u", result);
	  fflush(NULL);
	}
	fh.clear_cipher_bit(c);
  }
  if (OUTPUT) {
	printf("\n");
  }
}

void test_encrypt_bit_vector(FullyHomomorphic &fh, const PublicKey &pk, const PrivateKey &sk) {
  printf("----- TESTING ENCRYPTION OF A BIT VECTOR -----\n");
  printf("--- ENCRYPTING ALTERNATING FALSE AND TRUE ---\n");
  bool* m = new bool[100];
  for (int i = 0; i < 100; i++) {
	m[i] = new bool;
	if (i%2 == 0)
	  m[i] = false;
	else
	  m[i] = true;
  }
  CipherBit** e = fh.encrypt_bit_vector(pk, m, 100);
  bool* d = fh.decrypt_bit_vector(sk, e, 100);
  for (int i = 0; i < 100; i++) {
	printf("%u", d[i]);
  }
  printf("\n");
}

void test_gates(FullyHomomorphic &fh, const PublicKey &pk, const PrivateKey &sk, SecuritySettings *sec) {
  printf("----- TESTING EVALUATION OF GATES -----\n");
  printf("--- AND GATE ---\n");
  bool domain[2];
  domain[0] = false;
  domain[1] = true;
  CipherBit** inputs = new CipherBit*[2];
  inputs[0] = new CipherBit;
  inputs[1] = new CipherBit;
  fh.encrypt_bit(*(inputs[0]), pk, false);
  fh.encrypt_bit(*(inputs[1]), pk, true);
  Gate* input_a;
  Gate* input_b;
  Gate* operation;
  Gate* output;
  std::vector<Gate*> output_vector;
  CipherBit** encrypted_eval_output;
  bool* decrypted_eval_output;
  for (unsigned long int a_index = 0; a_index < 2; a_index++) {
	for (unsigned long int b_index = 0; b_index < 2; b_index++) {
	  input_a = new Gate(Input, a_index, sec);
	  input_b = new Gate(Input, b_index, sec);
	  operation = new Gate(And, input_a, input_b, sec);
	  // input_a->add_output(operation);
	  // input_b->add_output(operation);
	  output = new Gate(Output, operation, sec);
	  // operation->add_output(output);
	  output_vector.push_back(output);
	  encrypted_eval_output = fh.evaluate(output_vector, inputs, pk);
	  decrypted_eval_output = fh.decrypt_bit_vector(sk, encrypted_eval_output, 1);
	  printf("%u x %u = %u\n", domain[a_index], domain[b_index], decrypted_eval_output[0]);
	  output_vector.clear();
	}
  }
  
  printf("--- XOR GATE ---\n");
  for (unsigned long int a_index = 0; a_index < 2; a_index++) {
	for (unsigned long int b_index = 0; b_index < 2; b_index++) {
	  input_a = new Gate(Input, a_index, sec);
	  input_b = new Gate(Input, b_index, sec);
	  operation = new Gate(Xor, input_a, input_b, sec);
	  // input_a->add_output(operation);
	  // input_b->add_output(operation);
	  output = new Gate(Output, operation, sec);
	  // operation->add_output(output);
	  output_vector.push_back(output);
	  encrypted_eval_output = fh.evaluate(output_vector, inputs, pk);
	  decrypted_eval_output = fh.decrypt_bit_vector(sk, encrypted_eval_output, 1);
	  printf("%u + %u = %u\n", domain[a_index], domain[b_index], decrypted_eval_output[0]);
	  output_vector.clear();
	}
  }
}

void test_circuits(FullyHomomorphic &fh, const PublicKey &pk, const PrivateKey &sk, SecuritySettings *sec) {
  printf("----- TESTING EVALUATION OF MORE COMPLEX CIRCUITS -----\n");
  printf("--- CIRCUIT 1 ---\n");
  int INPUT_LENGTH = 6;
  CipherBit** inputs = new CipherBit*[INPUT_LENGTH];
  for (int i = 0; i < INPUT_LENGTH; i++) {
	inputs[i] = new CipherBit;
  }
  fh.encrypt_bit(*(inputs[0]), pk, false);
  fh.encrypt_bit(*(inputs[1]), pk, true);
  fh.encrypt_bit(*(inputs[2]), pk, true);
  fh.encrypt_bit(*(inputs[3]), pk, true);
  fh.encrypt_bit(*(inputs[4]), pk, true);
  fh.encrypt_bit(*(inputs[5]), pk, true);

  Gate* input_a;
  Gate* input_b;
  Gate* input_c;
  Gate* operation1;
  Gate* operation2;
  Gate* operation3;
  Gate* operation4;
  Gate* operation5;
  Gate* output;
  std::vector<Gate*> output_vector;
  CipherBit** encrypted_eval_output;
  bool* decrypted_eval_output;
  input_a = new Gate(Input, (unsigned long int)1, sec);
  input_b = new Gate(InputLiteral, false, sec);
  operation1 = new Gate(And, input_a, input_b, sec);
  // input_a->add_output(operation1);
  // input_b->add_output(operation1);
  operation2 = new Gate(And, operation1, input_a, sec);
  // operation1->add_output(operation2);
  // input_a->add_output(operation2);
  output = new Gate(Output, operation2, sec);
  // operation2->add_output(output);
  output_vector.push_back(output);
  encrypted_eval_output = fh.evaluate(output_vector, inputs, pk);
  decrypted_eval_output = fh.decrypt_bit_vector(sk, encrypted_eval_output, 1);
  printf("1 x 0l x 1 = %u\n", decrypted_eval_output[0]);
  output_vector.clear();

  printf("--- CIRCUIT 2 ---\n");
  input_a = new Gate(Input, (unsigned long int)1, sec);
  input_b = new Gate(Input, (unsigned long int)2, sec);
  input_c = new Gate(Input, (unsigned long int)3, sec);
  operation1 = new Gate(And, input_a, input_b, sec);
  // input_a->add_output(operation1);
  // input_b->add_output(operation1);
  operation2 = new Gate(And, operation1, input_c, sec);
  // operation1->add_output(operation2);
  // input_c->add_output(operation2);
  output = new Gate(Output, operation2, sec);
  // operation2->add_output(output);
  output_vector.push_back(output);
  encrypted_eval_output = fh.evaluate(output_vector, inputs, pk);
  decrypted_eval_output = fh.decrypt_bit_vector(sk, encrypted_eval_output, 1);
  printf("1 x 1 x 1 = %u\n", decrypted_eval_output[0]);
  output_vector.clear();

  printf("--- CIRCUIT 3 ---\n");
  input_a = new Gate(Input, (unsigned long int)1, sec);
  input_b = new Gate(Input, (unsigned long int)1, sec);
  input_c = new Gate(Input, (unsigned long int)0, sec);
  operation1 = new Gate(And, input_a, input_b, sec);
  operation2 = new Gate(And, input_a, input_c, sec);
  operation3 = new Gate(And, input_b, input_c, sec);
  operation4 = new Gate(Xor, operation1, operation2, sec);
  operation5 = new Gate(Xor, operation4, operation3, sec);
  output = new Gate(Output, operation5, sec);
  output_vector.push_back(output);
  fh.is_allowed_circuit(output_vector);
  encrypted_eval_output = fh.evaluate(output_vector, inputs, pk);
  decrypted_eval_output = fh.decrypt_bit_vector(sk, encrypted_eval_output, 1);
  printf("%u\n", decrypted_eval_output[0]);
  output_vector.clear();
}

void benchmark(FullyHomomorphic &fh, PublicKey &pk, PrivateKey &sk, SecuritySettings *sec) {
  OUTPUT = false;
  clock_t start_time = clock();
  fh.key_gen(sk, pk);
  clock_t key_gen_finished = clock();
  printf("Key Generation: %f\n", (double)(key_gen_finished - start_time)/CLOCKS_PER_SEC);
  test_encrypt_bit_vector(fh, pk, sk);
  clock_t test_encrypt_bit_vector_finished = clock();
  printf("Encrypting and decrypting 100 bit vector: %f\n", (double)(test_encrypt_bit_vector_finished - key_gen_finished)/CLOCKS_PER_SEC);
  test_encrypt_bit(fh, pk, sk);
  clock_t test_encrypt_bit_finished = clock();
  printf("Encrypting and decrypting 200 bits: %f\n", (double)(test_encrypt_bit_finished - test_encrypt_bit_vector_finished)/CLOCKS_PER_SEC);
}

int main(int argc, char** argv) {
  CryptoPP::AutoSeededRandomPool rng;
  SecuritySettings *security_settings = new SecuritySettings(atoi(argv[1]));
  FullyHomomorphic fh(security_settings);
  PrivateKey sk;
  PublicKey pk;
  fh.key_gen(sk, pk);

  for (int i = 2; i < argc; i++) {
	if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
	  fh.key_gen(sk, pk);
	  test_encrypt_bit(fh, pk, sk);
	  test_encrypt_bit_vector(fh, pk, sk);
	  //fh.test_decryption_circuit(pk, sk);
	  test_gates(fh, pk, sk, security_settings);
	  test_circuits(fh, pk, sk, security_settings);
	}
	if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--single-bit") == 0) {
	  fh.key_gen(sk, pk);
	  test_encrypt_bit(fh, pk, sk);
	}
	if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--bit-vector") == 0) {
	  fh.key_gen(sk, pk);
	  test_encrypt_bit_vector(fh, pk, sk);
	}
	if (strcmp(argv[i], "-dc") == 0 || strcmp(argv[i], "--decryption-circuit") == 0) {
	  fh.key_gen(sk, pk);
	  fh.test_decryption_circuit(pk, sk);
	}
	if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gates") == 0) {
	  fh.key_gen(sk, pk);
	  test_gates(fh, pk, sk, security_settings);
	}
	if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--circuits") == 0) {
	  fh.key_gen(sk, pk);
	  test_circuits(fh, pk, sk, security_settings);
	}
	if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timing") == 0) {
	  benchmark(fh, pk, sk, security_settings);
	}
  }
}
