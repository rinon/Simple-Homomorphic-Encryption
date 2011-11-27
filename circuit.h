#ifndef CIRCUIT_H
#define CIRCUIT_H

#include "type_defs.h"
#include "security_settings.h"
#include "utilities.h"
#include <vector>
#include <stdexcept>
#include <cmath>


enum GateTypeEnum {And, Xor, Input, InputLiteral, Output};
typedef enum GateTypeEnum GateType;

class Gate {
 private:
  SecuritySettings *sec;
 public:
  GateType gate_type;
  unsigned int id;
  unsigned long input_index;
  Gate *input1;
  bool input1_resolved;
  Gate *input2;
  bool input2_resolved;
  int unresolved_outputs;
  CipherBit* output_value;
  std::vector<Gate*> outputs;
  void init_vars();
  void calc_z_vector(const PublicKey &pk);

  unsigned long int degree;
  unsigned long int norm;

  // Input gates
  //Gate(GateType gate_type, CipherBit* value, unsigned long lambda);
  Gate(GateType gate_type, unsigned long input_index, SecuritySettings *sec);

  // Input Literal gates
  Gate(GateType gate_type, bool input, SecuritySettings *sec);

  // Output gates
  Gate(GateType gate_type, Gate *input, SecuritySettings *sec);

  // Logic gates
  Gate(GateType gate_type, Gate *input1, Gate *input2, SecuritySettings *sec);

  void add_output(Gate *output_gate);

  void update_outputs();
  void evaluate(const PublicKey &pk);
  void mod_reduce(const PublicKey &pk);
  bool is_input() {return gate_type == Input;}
  void set_input(CipherBit** inputs);

};

#endif //CIRCUIT_H
