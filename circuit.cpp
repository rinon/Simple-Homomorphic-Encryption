#include "circuit.h"

// Input gate
Gate::Gate(GateType gate_type, unsigned long input_index, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input_index(input_index) {
  input1_resolved = true;
  input2_resolved = true;
  unresolved_outputs = 0;

  init_vars();
  degree = 1;
  norm = 1;
}

// Input Literal gate
Gate::Gate(GateType gate_type, bool input, SecuritySettings *sec) : sec(sec), gate_type(gate_type) {
  input1_resolved = true;
  input2_resolved = true;
  unresolved_outputs = 0;

  init_vars();

  mpz_set_ui(output_value->old_ciphertext, input);
  output_value->z_vector = new unsigned long[sec->public_key_y_vector_length];
  for (unsigned int i = 0; i < sec->public_key_y_vector_length; i++) {
	output_value->z_vector[i] = 0;
  }

  degree = 0;
  norm = input;
}

// Output gate
Gate::Gate(GateType gate_type, Gate *input, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input1(input) {
  input1_resolved = false;
  input2_resolved = true;
  unresolved_outputs = 0;

  init_vars();
  degree = input->degree;
  norm = input->norm;
  input->add_output(this);
}

// Logic gate
Gate::Gate(GateType gate_type, Gate *input1, Gate *input2, SecuritySettings *sec) : sec(sec), gate_type(gate_type), input1(input1), input2(input2) {
  input1_resolved = false;
  input2_resolved = false;
  unresolved_outputs = 0;

  init_vars();
  if (gate_type == And) {
	degree = input1->degree + input2->degree;
	norm = max(input1->norm, input2->norm); // Not sure if norm can be computed bottom up
  } else {
	degree = max(input1->degree, input2->degree);
	norm = input1->norm + input2->norm;
  }
  input1->add_output(this);
  input2->add_output(this);
}

void Gate::add_output(Gate *output_gate) {
  outputs.push_back(output_gate);
  unresolved_outputs++;
}

void Gate::init_vars() {
  output_value = new CipherBit;
  mpz_init(output_value->old_ciphertext);
}

void Gate::update_outputs() {
  for (std::vector<Gate*>::iterator i = outputs.begin(); i != outputs.end(); i++) {
	if ((*i)->input1 == this) {
	  (*i)->input1_resolved = true;
	}
	if ((*i)->input2 == this) {
	  (*i)->input2_resolved = true;
	}
  }
}

void Gate::evaluate(const PublicKey &pk) {
  if (input1_resolved && input2_resolved) {
	mpz_t bound; // TODO: Make this static
	switch (gate_type) {
	case Input:
	case InputLiteral:
	  break;
	case Output:
	  output_value = input1->output_value;
	  break;
	case And:
	  mpz_mul(output_value->old_ciphertext, input1->output_value->old_ciphertext, input2->output_value->old_ciphertext);
	  /*
	  printf("input1: ");
	  mpz_out_str(NULL, 10, input1->output_value->old_ciphertext);
	  printf("\n");
	  printf("input2: ");
	  mpz_out_str(NULL, 10, input2->output_value->old_ciphertext);
	  printf("\n");
	  printf("output_value: ");
	  mpz_out_str(NULL, 10, output_value->old_ciphertext);
	  printf("\n");
	  */

	  mpz_init2(bound, sec->gamma+1);
	  mpz_setbit(bound, sec->gamma);
	  if (mpz_cmp(output_value->old_ciphertext, bound) > 0) {
		mod_reduce(pk);
	  }
	  mpz_clear(bound);
	  calc_z_vector(pk);
	  break;
	case Xor:
	  mpz_add(output_value->old_ciphertext, input1->output_value->old_ciphertext, input2->output_value->old_ciphertext);

	  mpz_init2(bound, sec->gamma+1);
	  mpz_setbit(bound, sec->gamma);
	  if (mpz_cmp(output_value->old_ciphertext, bound) > 0) {
		mod_reduce(pk);
	  }
	  mpz_clear(bound);
	  calc_z_vector(pk);
	  break;
	}
	update_outputs();
  } else {
	throw new std::runtime_error("This gate isn't ready to evaluate!");
  }
}

void Gate::mod_reduce(const PublicKey &pk) {
  for (int i = sec->gamma; i >= 0; i--) {
	mpz_mod(output_value->old_ciphertext, output_value->old_ciphertext, pk.old_key_extra[i]);
  }
}


// TODO: This duplicates code in fully_homomorphic.cpp. Split this out into possibly a CipherBit class
void Gate::calc_z_vector(const PublicKey &pk) {
  unsigned int precision = ceil(log2(sec->theta)) + 3;

  output_value->z_vector = new unsigned long[sec->public_key_y_vector_length];

  unsigned long bitmask = (1l << (precision+1)) - 1;

  mpz_t temp;
  mpz_init(temp);
  // unsigned int __gmp_n;
  for (unsigned int i = 0; i < sec->public_key_y_vector_length; i++) {
	mpz_mul(temp, output_value->old_ciphertext, pk.y_vector[i]);
	mpz_fdiv_q_2exp(temp, temp, sec->kappa-precision);
	output_value->z_vector[i] = mpz_get_ui(temp) & bitmask;
// 	__gmp_n = __GMP_ABS (temp->_mp_size);
// #if GMP_NAIL_BITS == 0 || defined (_LONG_LONG_LIMB)
// 	/* limb==long and no nails, or limb==longlong, one limb is enough */
// 	if (__gmp_n != 0) {
// #ifdef __GMP_SHORT_LIMB
// 	  if (__gmp_n == 1) {
// 		memcpy(&output_value.z_vector[i], &temp->_mp_d[0], sizeof(mp_limb_t));
// 	  } else {
// 		memcpy(&output_value.z_vector[i], &temp->_mp_d[0], sizeof(unsigned long int));
// 	  }
// #else
// 	  memcpy(&output_value.z_vector[i], &temp->_mp_d[0], sizeof(unsigned long int));
// #endif
// 	}
// #else
// 	/* limb==long and nails, need two limbs when available */
// 	if (__gmp_n <= 1) {
// 	  if (__gmp_n != 0) {
// #ifdef __GMP_SHORT_LIMB
// 		memcpy(&output_value.z_vector[i], &temp->_mp_d[0], sizeof(mp_limb_t));
// #else
// 		memcpy(&output_value.z_vector[i], &temp->_mp_d[0], sizeof(unsigned long int));
// #endif
// 	  }
// 	} else {
// #ifdef __GMP_SHORT_LIMB
// 	  memcpy(&output_value.z_vector[i], &temp->_mp_d[1], sizeof(mp_limb_t));
// 	  output_value.z_vector[i] <<= GMP_NUMB_BITS;
// 	  memcpy(&output_value.z_vector[i], &temp->_mp_d[0], sizeof(mp_limb_t));
// #else
// 	  memcpy(&output_value.z_vector[i], &temp->_mp_d[1], sizeof(unsigned long int));
// 	  output_value.z_vector[i] <<= GMP_NUMB_BITS;
// 	  memcpy(&output_value.z_vector[i], &temp->_mp_d[0], sizeof(unsigned long int));
// #endif
// 	}
// #endif
// 	output_value.z_vector[i] &= bitmask;
  }
  mpz_clear(temp);
}

void Gate::set_input(CipherBit** inputs) {
  mpz_set(output_value->old_ciphertext, inputs[input_index]->old_ciphertext);
  output_value->z_vector = new unsigned long[sec->public_key_y_vector_length];
  for (unsigned int i = 0; i < sec->public_key_y_vector_length; i++) {
	output_value->z_vector[i] = inputs[input_index]->z_vector[i];
  }
}

