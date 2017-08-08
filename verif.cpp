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

  // read the 16 ciphertexts of the result
  LweSample *answer = new_gate_bootstrapping_ciphertext_array(16, params);

  LweSample *cipherstate = new_gate_bootstrapping_ciphertext_array(16, params);
  LweSample *ciphertape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++)
    ciphertape[i] = new_gate_bootstrapping_ciphertext_array(16, params);
  /*
  LweSample *cipherinstr[INSTRSIZE];
  for (int i = 0; i < INSTRSIZE; i++) {
    cipherinstr[i] =
        new_gate_bootstrapping_ciphertext_array(INSTRBITLEN, params);
  }
  */

  // import the 32 ciphertexts from the answer file
  FILE *answer_data = fopen("answer.data", "rb");
  importFromFile(answer_data, answer, 16, params);
  importFromFile(answer_data, cipherstate, 16, params);
  for (int i = 0; i < TAPESIZE; i++)
    importFromFile(answer_data, ciphertape[i], 16, params);
  /*
  for (int i = 0; i < INSTRSIZE; i++)
    importFromFile(answer_data, cipherinstr[i], INSTRBITLEN, params);
  */
  fclose(answer_data);

  // decrypt and rebuild the 16-bit plaintext answer
  int16_t int_answer = 0;
  for (int i = 0; i < 16; i++) {
    int ai = bootsSymDecrypt(&answer[i], key);
    int_answer |= (ai << i);
  }

  state_t plainstate = 0;
  for (int i = 0; i < 16; i++) {
    int ai = bootsSymDecrypt(&cipherstate[i], key);
    plainstate |= (ai << i);
  }

  printf("And the result is: %d, and the state is %d.\ni = ", int_answer,
         plainstate);
  for (int i = 0; i < 16; i++)
    printf("%d", (int_answer >> i) & 1);
  printf("\nI hope you remember what was the question!\n");

  // clean up all pointers
  delete_gate_bootstrapping_ciphertext_array(16, answer);
  delete_gate_bootstrapping_secret_keyset(key);
}
