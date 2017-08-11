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

// target = source
void bitwiseCopy(LweSample *target, LweSample *source, const int nb_bits,
                 const TFheGateBootstrappingCloudKeySet *bk) {
  /* for (i < nb_bits) {
   *   target[i] &= trigger ? source[i] : target[i];
   * }
   */
  for (int i = 0; i < nb_bits; i++)
    bootsCOPY(&target[i], &source[i], bk);
}

int main() {
  // reads the cloud key from file
  FILE *cloud_key = fopen("cloud.key", "rb");
  TFheGateBootstrappingCloudKeySet *bk =
      new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
  fclose(cloud_key);

  // if necessary, the params are inside the key
  const TFheGateBootstrappingParameterSet *params = bk->params;

  LweSample *state = new_gate_bootstrapping_ciphertext_array(STATE_SIZE, params);
  LweSample *tape[TAPESIZE];
  for (int i = 0; i < TAPESIZE; i++)
    tape[i] = new_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, params);
  LweSample *instr_curSt[INSTRSIZE];
  LweSample *instr_curSym[INSTRSIZE];
  LweSample *instr_newSt[INSTRSIZE];
  LweSample *instr_newSym[INSTRSIZE];
  LweSample *instr_stChanged[INSTRSIZE];
  LweSample *instr_symChanged[INSTRSIZE];
  LweSample *instr_dir[INSTRSIZE];
  for (int i = 0; i < INSTRSIZE; i++) {
    instr_curSt[i] =
        new_gate_bootstrapping_ciphertext_array(CURST_SIZE, params);
    instr_curSym[i] =
        new_gate_bootstrapping_ciphertext_array(CURSYM_SIZE, params);
    instr_newSt[i] =
        new_gate_bootstrapping_ciphertext_array(NEWST_SIZE, params);
    instr_newSym[i] =
        new_gate_bootstrapping_ciphertext_array(NEWSYM_SIZE, params);
    instr_stChanged[i] =
        new_gate_bootstrapping_ciphertext_array(STCHANGED_SIZE, params);
    instr_symChanged[i] =
        new_gate_bootstrapping_ciphertext_array(SYMCHANGED_SIZE, params);
    instr_dir[i] =
        new_gate_bootstrapping_ciphertext_array(DIR_SIZE, params);
  }

  FILE *cloud_data = fopen("cloud.data", "rb");
  importFromFile(cloud_data, state, STATE_SIZE, params);
  for (int i = 0; i < TAPESIZE; i++)
    importFromFile(cloud_data, tape[i], SYMBOL_SIZE, params);
  for (int i = 0; i < INSTRSIZE; i++) {
    importFromFile(cloud_data, instr_curSt[i], CURST_SIZE, params);
    importFromFile(cloud_data, instr_curSym[i], CURSYM_SIZE, params);
    importFromFile(cloud_data, instr_newSt[i], NEWST_SIZE, params);
    importFromFile(cloud_data, instr_newSym[i], NEWSYM_SIZE, params);
    importFromFile(cloud_data, instr_stChanged[i], STCHANGED_SIZE,
                   params);
    importFromFile(cloud_data, instr_symChanged[i], SYMCHANGED_SIZE,
                   params);
    importFromFile(cloud_data, instr_dir[i], DIR_SIZE, params);
  }
  fclose(cloud_data);

  LweSample *stateOutputBuffer = new_gate_bootstrapping_ciphertext_array(STATE_SIZE, params);
  bitwiseCopy(stateOutputBuffer, state, STATE_SIZE, bk);
  LweSample *symbolOutputBuffer = new_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, params);
  bitwiseCopy(symbolOutputBuffer, tape[0], SYMBOL_SIZE, bk);

  /* There are two ways to implement a Turing machine:
   * 
   *   - Moving head: the tape doesn't move, i.e. tape[0] will always be
   *     tape[0] unless its symbol is changed by the Turing machine.
   *     
   *     In this case, I would keep an (encrypted) variable "index" which
   *     stores the position of the head, and the (encrypted) variable
   *     "currentSymbol" representing the symbol under the tape. At each
   *     iteration, the software would have to compare each index on the
   *     tape with the "index" variable before multiplexing it in:
   *     
   *          for (i = 0; i < TAPE_SIZE; i++) {
   *               bitwiseNOR(doesIndexMatch, index, tape[i].index)
   *               conditionalCopy(currentSymbol, doesIndexMatch, tape[i].symbol)
   *          }
   *          // Instruction processing here (modifies symbolBuf, index)
   *          for (i = 0; i < TAPE_SIZE; i++) {
   *               bitwiseNOR(doesIndexMatch, index, tape[i].index)
   *               conditionalCopy(tape[i].symbol, doesIndexMatch, symbolBuf)
   *          }
   *
   *     Such an implementation requires 2 * (2 * TAPE_SIZE * SYMBOL_SIZE)
   *     gate calculations per iteration, plus something more to increment
   *     the index.
   *   - Fixed head: the head doesn't move, the tape moves below it, i.e.
   *     tape[0] might be moved to tape[1] or tape[-1] if the instructions
   *     require it.
   *
   *     In this case, I would simply shift every symbol in the tape by one
   *     (except for overflow/underflow) to the left or to the right if
   *     needed:
   *
   *          bitwiseCopy(currentSymbol, tape[0])
   *          // Instruction processing here (modifies symbolBuf, moveLeft, moveRight)
   *          bitwiseCopy(tape[0], symbolBuf)
   *          for (i = 0; i < TAPE_SIZE; i++) {
   *               // overflow/underflow management skipped for simplicity
   *               conditionalCopy(tape[i + 1], moveLeft, tape[i])
   *               conditionalCopy(tape[i - 1], moveRight, tape[i])
   *          }
   *          bitwiseCopy(tape[0], symbolBuf) // was overwritten by shifting
   *
   *     Such an implementation requires exactly TAPE_SIZE * 2 * SYMBOL_SIZE
   *     + 2 * SYMBOL_SIZE gate calculations per iteration, and uses smaller
   *     data structures (doesn't require us to keep the index of each cell
   *     on the tape).
   */

  for (int iteration = 0; iteration < 2; iteration++) {
    printf("Iteration %d\n", iteration);
    for (int i = 0; i < INSTRSIZE; i++) {
      LweSample *doesStateMatch =
          new_gate_bootstrapping_ciphertext_array(1, params);
      equals(doesStateMatch, state, instr_curSt[i], STATE_SIZE, bk);
      LweSample *doesSymbolMatch =
          new_gate_bootstrapping_ciphertext_array(1, params);
      equals(doesSymbolMatch, tape[0], instr_curSym[i], SYMBOL_SIZE, bk);

      LweSample *isSuitable =
          new_gate_bootstrapping_ciphertext_array(1, params);
      bootsAND(isSuitable, doesStateMatch, doesSymbolMatch, bk), numGates++;

      // Copy only if isSuitable and stChanged
      LweSample *mustCopyState =
          new_gate_bootstrapping_ciphertext_array(1, params);
      bootsAND(mustCopyState, isSuitable, instr_stChanged[i], bk), numGates++;
      conditionalCopy(stateOutputBuffer, mustCopyState, instr_newSt[i], STATE_SIZE, bk);

      // Copy only if isSuitable and stChanged
      LweSample *mustCopySymbol =
          new_gate_bootstrapping_ciphertext_array(1, params);
      bootsAND(mustCopySymbol, isSuitable, instr_symChanged[i], bk), numGates++;
      conditionalCopy(symbolOutputBuffer, mustCopySymbol, instr_newSym[i], STATE_SIZE, bk);

      delete_gate_bootstrapping_ciphertext_array(1, doesStateMatch);
      delete_gate_bootstrapping_ciphertext_array(1, doesSymbolMatch);
      delete_gate_bootstrapping_ciphertext_array(1, isSuitable);
      delete_gate_bootstrapping_ciphertext_array(1, mustCopyState);
      delete_gate_bootstrapping_ciphertext_array(1, mustCopySymbol);
    }
  }
  bitwiseCopy(state, stateOutputBuffer, STATE_SIZE, bk);
  bitwiseCopy(tape[0], symbolOutputBuffer, SYMBOL_SIZE, bk);

  // export the 32 texts to a file (for the cloud)
  FILE *answer_data = fopen("answer.data", "wb");
  exportToFile(answer_data, state, STATE_SIZE, params);
  for (int i = 0; i < TAPESIZE; i++)
    exportToFile(answer_data, tape[i], SYMBOL_SIZE, params);
  for (int i = 0; i < INSTRSIZE; i++) {
    // exportToFile(answer_data, instr[i], INSTRBITLEN, params);
  }
  fclose(answer_data);

  // clean up all pointers
  delete_gate_bootstrapping_ciphertext_array(STATE_SIZE, state);
  for (int i = 0; i < TAPESIZE; i++)
    delete_gate_bootstrapping_ciphertext_array(SYMBOL_SIZE, tape[i]);
  delete_gate_bootstrapping_cloud_keyset(bk);

  printf("%d gates computed.\n", numGates);
}
