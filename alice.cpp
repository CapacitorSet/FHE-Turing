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
    plaininstr[i] = (instr_t){ .dir = STATIONARY, .stChanged = false, .symChanged = false };
  // A simple program that converts "a" and "b" to "A" and "B", and prints an "X" and halts when unknown characters are found.
  // Note: because instructions are executed top to bottom, the first instruction acts as a fallback: the catch-all ".anyCurSt = true, .anyCurSym = true" only matters if there are no newer instructions that also match.
  plaininstr[0] = {.anyCurSt   = true,
                   .anyCurSym  = true,
                   .stChanged  = false,
                   .newSym     = 'X',
                   .symChanged = true,
                   .dir        = STATIONARY };
  plaininstr[1] = {.anyCurSt   = true,
                   .curSym     = 'a',
                   .anyCurSym  = false,
                   .stChanged  = false,
                   .newSym     = 'A',
                   .symChanged = true,
                   .dir        = RIGHT };
  plaininstr[2] = {.anyCurSt   = true,
                   .curSym     = 'b',
                   .anyCurSym  = false,
                   .stChanged  = false,
                   .newSym     = 'B',
                   .symChanged = true,
                   .dir        = RIGHT };
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
  state_t plainstate = 0;
  printf("Initializing cipher state...\n");
  LweSample *cipherstate = new_gate_bootstrapping_ciphertext_array(STATE_SIZE, params);
  setStateFromPlain(cipherstate, plainstate, key);

  printf("Initializing plain tape...\n");
  symbol_t plaintape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++)
    plaintape[i] = 0;
  plaintape[0] = 'a';
  plaintape[1] = 'b';
  plaintape[2] = 'a';
  plaintape[3] = 'a';
  plaintape[4] = 'b';

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