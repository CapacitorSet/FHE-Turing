#include "turing.h"
#include <stdio.h>

void setStateFromPlain(LweSample *cipher, state_t plain,
                        TFheGateBootstrappingSecretKeySet *key) {
  for (int i = 0; i < STATE_SIZE; i++)
    bootsSymEncrypt(&cipher[i], (plain >> i) & 1, key);
}

void setSymbolFromPlain(LweSample *cipher, symbol_t plain,
                        TFheGateBootstrappingSecretKeySet *key) {
  for (int i = 0; i < SYMBOL_SIZE; i++)
    bootsSymEncrypt(&cipher[i], (plain >> i) & 1, key);
}

int main() {
  printf("Generating keyset...\n");
  // generate a keyset
  const int minimum_lambda = 110;
  TFheGateBootstrappingParameterSet *params =
      new_default_gate_bootstrapping_parameters(minimum_lambda);

  printf("Generating key...\n");
  // generate a random key
  uint32_t seed[] = {314, 1592, 657};
  tfhe_random_generator_setSeed(seed, 3);
  TFheGateBootstrappingSecretKeySet *key =
      new_random_gate_bootstrapping_secret_keyset(params);

  printf("Exporting secret key...\n");
  // export the secret key to file for later use
  FILE *secret_key = fopen("secret.key", "wb");
  export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
  fclose(secret_key);

  printf("Exporting public key...\n");
  // export the cloud key to a file (for the cloud)
  FILE *cloud_key = fopen("cloud.key", "wb");
  export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
  fclose(cloud_key);

  instr_t plaininstr[INSTRSIZE];
  LweSample *cipherinstr[INSTRSIZE];
  printf("Initializing plain instruction array...\n");
  for (int i = 0; i < INSTRSIZE; i++)
    plaininstr[i] = (instr_t){0, 0, false, 0, false, 0, STATIONARY};
  plaininstr[0] = {.curSt = 'g',
                   .curSym = '0',
                   .newSt = 'b',
                   .newSym = 'x',
                   .stChanged = true,
                   .symChanged = true,
                   .dir = STATIONARY};
  plaininstr[1] = {.curSt = 'b',
                   .curSym = 'x',
                   .newSt = 'w',
                   .newSym = 'h',
                   .stChanged = true,
                   .symChanged = true,
                   .dir = STATIONARY};
  for (int j = 0; j < INSTRBITLEN; j++)
    printf("%d", getNthBitOfInstr(plaininstr[0], j));
  printf("\n");
  printf("Initializing cipher instruction array...\n");
  for (int i = 0; i < INSTRSIZE; i++) {
    cipherinstr[i] =
        new_gate_bootstrapping_ciphertext_array(INSTRBITLEN, params);
    for (int j = 0; j < INSTRBITLEN; j++) {
      printf("%d", getNthBitOfInstr(plaininstr[i], j));
      bootsSymEncrypt(&(cipherinstr[i])[j], getNthBitOfInstr(plaininstr[i], j),
                      key);
    }
    printf("\n");
  }

  printf("Initializing plain state...\n");
  state_t plainstate = 'g';
  printf("Initializing cipher state...\n");
  LweSample *cipherstate = new_gate_bootstrapping_ciphertext_array(STATE_SIZE, params);
  setStateFromPlain(cipherstate, plainstate, key);

  printf("Initializing plain tape...\n");
  symbol_t plaintape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++)
    plaintape[i] = 0;
  plaintape[0] = '0';

  printf("Initializing cipher tape...\n");
  LweSample *ciphertape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++) {
    ciphertape[i] = new_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, params);
    setSymbolFromPlain(ciphertape[i], plaintape[i], key);
  }

  FILE *cloud_data = fopen("cloud.data", "wb");

  exportToFile(cloud_data, cipherstate, STATE_SIZE, params);
  for (int i = 0; i < TAPESIZE; i++)
    exportToFile(cloud_data, ciphertape[i], SYMBOL_SIZE, params);
  for (int i = 0; i < INSTRSIZE; i++)
    exportToFile(cloud_data, cipherinstr[i], INSTRBITLEN, params);
  fclose(cloud_data);

  // clean up all pointers
  delete_gate_bootstrapping_ciphertext_array(STATE_SIZE, cipherstate);

  // clean up all pointers
  delete_gate_bootstrapping_secret_keyset(key);
  delete_gate_bootstrapping_parameters(params);
}