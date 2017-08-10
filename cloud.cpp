#include "turing.h"
#include <stdio.h>

int numGates = 0;

// result is a bit, high if a == b, low otherwise
void equals(LweSample *result, const LweSample *a, const LweSample *b,
            const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk) {
  LweSample *tmp = new_gate_bootstrapping_ciphertext_array(1, bk->params);

  // result = true;
  bootsCONSTANT(&result[0], 1, bk), numGates++;

  /* for (i < nb_bits) {
   *   tmp = (a[i] == b[i]); // xnor
   *   result &= tmp;
   * }
   */
  for (int i = 0; i < nb_bits; i++) {
    bootsXNOR(&tmp[0], &a[i], &b[i], bk), numGates++;
    bootsAND(&result[0], &result[0], &tmp[0], bk), numGates++;
  }

  delete_gate_bootstrapping_ciphertext_array(1, tmp);
}

// target = source if trigger[0] is high; target = target otherwise
void conditionalCopy(LweSample *target, LweSample *trigger, LweSample *source,
                     const int nb_bits,
                     const TFheGateBootstrappingCloudKeySet *bk) {
  /* for (i < nb_bits) {
   *   target[i] &= trigger ? source[i] : target[i];
   * }
   */
  for (int i = 0; i < nb_bits; i++)
    bootsMUX(&target[i], &trigger[0], &source[i], &target[i], bk), numGates++;
}

int main() {
  // reads the cloud key from file
  FILE *cloud_key = fopen("cloud.key", "rb");
  TFheGateBootstrappingCloudKeySet *bk =
      new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
  fclose(cloud_key);

  // if necessary, the params are inside the key
  const TFheGateBootstrappingParameterSet *params = bk->params;

  LweSample *cipherstate = new_gate_bootstrapping_ciphertext_array(STATE_SIZE, params);
  LweSample *ciphertape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++)
    ciphertape[i] = new_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, params);
  LweSample *cipherinstr_curSt[INSTRSIZE];
  LweSample *cipherinstr_curSym[INSTRSIZE];
  LweSample *cipherinstr_newSt[INSTRSIZE];
  LweSample *cipherinstr_newSym[INSTRSIZE];
  LweSample *cipherinstr_stChanged[INSTRSIZE];
  LweSample *cipherinstr_symChanged[INSTRSIZE];
  LweSample *cipherinstr_dir[INSTRSIZE];
  for (int i = 0; i < INSTRSIZE; i++) {
    cipherinstr_curSt[i] =
        new_gate_bootstrapping_ciphertext_array(CURST_SIZE, params);
    cipherinstr_curSym[i] =
        new_gate_bootstrapping_ciphertext_array(CURSYM_SIZE, params);
    cipherinstr_newSt[i] =
        new_gate_bootstrapping_ciphertext_array(NEWST_SIZE, params);
    cipherinstr_newSym[i] =
        new_gate_bootstrapping_ciphertext_array(NEWSYM_SIZE, params);
    cipherinstr_stChanged[i] =
        new_gate_bootstrapping_ciphertext_array(STCHANGED_SIZE, params);
    cipherinstr_symChanged[i] =
        new_gate_bootstrapping_ciphertext_array(SYMCHANGED_SIZE, params);
    cipherinstr_dir[i] =
        new_gate_bootstrapping_ciphertext_array(DIR_SIZE, params);
  }

  FILE *cloud_data = fopen("cloud.data", "rb");
  importFromFile(cloud_data, cipherstate, STATE_SIZE, params);
  for (int i = 0; i < TAPESIZE; i++)
    importFromFile(cloud_data, ciphertape[i], SYMBOL_SIZE, params);
  for (int i = 0; i < INSTRSIZE; i++) {
    importFromFile(cloud_data, cipherinstr_curSt[i], CURST_SIZE, params);
    importFromFile(cloud_data, cipherinstr_curSym[i], CURSYM_SIZE, params);
    importFromFile(cloud_data, cipherinstr_newSt[i], NEWST_SIZE, params);
    importFromFile(cloud_data, cipherinstr_newSym[i], NEWSYM_SIZE, params);
    importFromFile(cloud_data, cipherinstr_stChanged[i], STCHANGED_SIZE,
                   params);
    importFromFile(cloud_data, cipherinstr_symChanged[i], SYMCHANGED_SIZE,
                   params);
    importFromFile(cloud_data, cipherinstr_dir[i], DIR_SIZE, params);
  }
  fclose(cloud_data);

  LweSample *doesStateMatch =
      new_gate_bootstrapping_ciphertext_array(1, params);
  equals(doesStateMatch, cipherstate, cipherinstr_curSt[0], STATE_SIZE, bk);
  LweSample *doesSymbolMatch =
      new_gate_bootstrapping_ciphertext_array(1, params);
  equals(doesSymbolMatch, ciphertape[0], cipherinstr_curSym[0], SYMBOL_SIZE, bk);

  LweSample *isSuitable =
      new_gate_bootstrapping_ciphertext_array(1, params);
  bootsAND(isSuitable, doesStateMatch, doesSymbolMatch, bk), numGates++;

  // nota: tenere una variabile currentSymbol
  // aggiornarla a ogni loop, scorrendo il nastro e facendo l'AND tra la sua posizione e cipherpos

  // Copy only if isSuitable and stChanged
  LweSample *mustCopyState =
      new_gate_bootstrapping_ciphertext_array(1, params);
  bootsAND(mustCopyState, isSuitable, cipherinstr_stChanged[0], bk), numGates++;
  conditionalCopy(cipherstate, mustCopyState, cipherinstr_newSt[0], STATE_SIZE, bk);

  // Copy only if isSuitable and stChanged
  LweSample *mustCopySymbol =
      new_gate_bootstrapping_ciphertext_array(1, params);
  bootsAND(mustCopySymbol, isSuitable, cipherinstr_symChanged[0], bk), numGates++;
  conditionalCopy(ciphertape[0], mustCopySymbol, cipherinstr_newSym[0], STATE_SIZE, bk);
  // cipherstate = cipherinstr_newSt[0];

  // export the 32 ciphertexts to a file (for the cloud)
  FILE *answer_data = fopen("answer.data", "wb");
  exportToFile(answer_data, cipherstate, STATE_SIZE, params);
  for (int i = 0; i < TAPESIZE; i++)
    exportToFile(answer_data, ciphertape[i], SYMBOL_SIZE, params);
  for (int i = 0; i < INSTRSIZE; i++) {
    // exportToFile(answer_data, cipherinstr[i], INSTRBITLEN, params);
  }
  fclose(answer_data);

  // clean up all pointers
  delete_gate_bootstrapping_ciphertext_array(STATE_SIZE, cipherstate);
  for (int i = 0; i < TAPESIZE; i++)
    delete_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, ciphertape[i]);
  delete_gate_bootstrapping_cloud_keyset(bk);

  printf("%d gates computed.\n", numGates);
}
