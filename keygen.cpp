#include "turing.h"
#include <stdio.h>

int main() {
  printf("Generating keyset...\n");
  const int minimum_lambda = 110;
  uint32_t seed[] = {314, 1592, 657};
  TFheGateBootstrappingParameterSet *params =
      new_default_gate_bootstrapping_parameters(minimum_lambda);
  tfhe_random_generator_setSeed(seed, sizeof(seed)/sizeof(seed[0]));
  TFheGateBootstrappingSecretKeySet *key =
      new_random_gate_bootstrapping_secret_keyset(params);

  printf("Exporting secret key...\n");
  FILE *secret_key = fopen("secret.key", "wb");
  export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
  fclose(secret_key);

  printf("Exporting public key...\n");
  FILE *cloud_key = fopen("cloud.key", "wb");
  export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
  fclose(cloud_key);
}