#include "security_settings.h"

SecuritySettings::SecuritySettings(unsigned long int lambda) : lambda(lambda) {
  gamma = lambda*lambda*lambda*lambda*lambda;
  eta = lambda*lambda * ( ceil( log2( lambda*lambda ) ) );
  rho = lambda;
  rho_ = 2*lambda;
  tau = gamma + lambda;
  //tau = 1000 + lambda;
  kappa = gamma*eta/rho_; // WARNING: This may need to be ceiling instead of floor
  theta = lambda;
  big_theta = kappa*lambda;
  //big_theta = 100*lambda;

  private_key_length = theta;
  public_key_old_key_length = tau+1;
  public_key_y_vector_length = big_theta;

  printf("gamma = %lu\n", gamma);
  printf("eta = %lu\n", eta);
  printf("rho = %lu\n", rho);
  printf("rho_ = %lu\n", rho_);
  printf("tau = %lu\n", tau);
  printf("kappa = %lu\n", kappa);
  printf("theta = %lu\n", theta);
  printf("big_theta = %lu\n", big_theta);
}

