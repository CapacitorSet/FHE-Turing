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

  LweSample *state = new_gate_bootstrapping_ciphertext_array(STATE_SIZE, params);
  LweSample *tape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++)
    tape[i] = new_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, params);
  /*
  LweSample *instr[INSTRSIZE];
  for (int i = 0; i < INSTRSIZE; i++) {
    instr[i] =
        new_gate_bootstrapping_ciphertext_array(INSTRBITLEN, params);
  }
  */

  FILE *answer_data = fopen("answer.data", "rb");
  importFromFile(answer_data, state, STATE_SIZE, params);
  for (int i = 0; i < TAPESIZE; i++)
    importFromFile(answer_data, tape[i], SYMBOL_SIZE, params);
  /*
  for (int i = 0; i < INSTRSIZE; i++)
    importFromFile(answer_data, instr[i], INSTRBITLEN, params);
  */
  fclose(answer_data);

  state_t plainstate = stateDecrypt(state);
  printf("State: [%c %02x]\n", plainstate, plainstate);

  printf("Tape:\nASCII | Hex\n");
  for (size_t i = 0; i < TAPESIZE; i++) {
    symbol_t current = symbolDecrypt(tape[i]);
    printf("  %c   | %02x\n", current ? current : '_', current);
  }
  printf("\n");

  // clean up all pointers
  delete_gate_bootstrapping_ciphertext_array(STATE_SIZE, state);
  delete_gate_bootstrapping_secret_keyset(key);
}
