#include "turing.h"
#include <stdio.h>

int main() {

  // reads the cloud key from file
  FILE *secret_key = fopen("secret.key", "rb");
  TFheGateBootstrappingSecretKeySet *key =
      new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
  fclose(secret_key);

  // if necessary, the params are inside the key
  const TFheGateBootstrappingParameterSet *params = key->params;

  LweSample *cipherstate = new_gate_bootstrapping_ciphertext_array(STATE_SIZE, params);
  LweSample *ciphertape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++)
    ciphertape[i] = new_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, params);
  /*
  LweSample *cipherinstr[INSTRSIZE];
  for (int i = 0; i < INSTRSIZE; i++) {
    cipherinstr[i] =
        new_gate_bootstrapping_ciphertext_array(INSTRBITLEN, params);
  }
  */

  FILE *answer_data = fopen("answer.data", "rb");
  importFromFile(answer_data, cipherstate, STATE_SIZE, params);
  for (int i = 0; i < TAPESIZE; i++)
    importFromFile(answer_data, ciphertape[i], SYMBOL_SIZE, params);
  /*
  for (int i = 0; i < INSTRSIZE; i++)
    importFromFile(answer_data, cipherinstr[i], INSTRBITLEN, params);
  */
  fclose(answer_data);

  state_t plainstate = 0;
  for (int i = 0; i < STATE_SIZE; i++) {
    int ai = bootsSymDecrypt(&cipherstate[i], key);
    plainstate |= (ai << i);
  }

  symbol_t plainfirstcell = 0;
  for (int i = 0; i < STATE_SIZE; i++) {
    int ai = bootsSymDecrypt(&(ciphertape[0])[i], key);
    plainfirstcell |= (ai << i);
  }

  printf("State:\t%d\t(%c)\n", plainstate, plainstate);
  printf("Tape:\t%d\t(%c)\n", plainfirstcell, plainfirstcell);

  // clean up all pointers
  delete_gate_bootstrapping_ciphertext_array(STATE_SIZE, cipherstate);
  delete_gate_bootstrapping_secret_keyset(key);
}
