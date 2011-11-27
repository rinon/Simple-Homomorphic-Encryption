#ifndef SECURITY_SETTINGS_H
#define SECURITY_SETTINGS_H

#include <cmath>
#include <cstdio>

class SecuritySettings {
 private:
  unsigned long int lambda;
 public:
  unsigned long int gamma;
  unsigned long int eta;
  unsigned long int rho;
  unsigned long int rho_;
  unsigned long int tau;
  unsigned long int kappa;
  unsigned long int theta;
  unsigned long int big_theta;

  unsigned long int private_key_length;
  unsigned long int public_key_old_key_length;
  unsigned long int public_key_y_vector_length;

  SecuritySettings(unsigned long int lambda);
};

#endif //SECURITY_SETTINGS_H
