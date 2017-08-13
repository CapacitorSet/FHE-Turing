#include <stdint.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#define TAPESIZE (8)
#define INSTRSIZE (3)
#define STATE_SIZE (8)
#define STATE_FORMAT "%02x"
#define SYMBOL_SIZE (8)
#define SYMBOL_FORMAT "%02x"

#define CURST_SIZE      (STATE_SIZE)
#define CURSYM_SIZE     (SYMBOL_SIZE)
#define NEWST_SIZE      (STATE_SIZE)
#define NEWSYM_SIZE     (SYMBOL_SIZE)
#define DIR_SIZE        ( 2)
#define ANYCURST_SIZE   ( 1)
#define ANYCURSYM_SIZE  ( 1)
#define STCHANGED_SIZE  ( 1)
#define SYMCHANGED_SIZE ( 1)

#define CURST_OFFSET      (                    CURST_SIZE)
#define CURSYM_OFFSET     (CURST_OFFSET      + CURSYM_SIZE)
#define NEWST_OFFSET      (CURSYM_OFFSET     + NEWST_SIZE)
#define NEWSYM_OFFSET     (NEWST_OFFSET      + NEWSYM_SIZE)
#define DIR_OFFSET        (NEWSYM_OFFSET     + DIR_SIZE)
#define ANYCURST_OFFSET   (DIR_OFFSET        + ANYCURST_SIZE)
#define ANYCURSYM_OFFSET  (ANYCURST_OFFSET   + ANYCURSYM_SIZE)
#define STCHANGED_OFFSET  (ANYCURSYM_OFFSET  + STCHANGED_SIZE)
#define SYMCHANGED_OFFSET (STCHANGED_OFFSET  + SYMCHANGED_SIZE)

#define INSTRBITLEN (CURST_SIZE + CURSYM_SIZE + NEWST_SIZE + NEWSYM_SIZE + DIR_SIZE + ANYCURST_SIZE + ANYCURSYM_SIZE + STCHANGED_SIZE + SYMCHANGED_SIZE)

#if INSTRBITLEN != SYMCHANGED_OFFSET
  #error WTF
#endif

typedef uint8_t symbol_t;
typedef uint8_t state_t;
typedef enum { STATIONARY, LEFT, RIGHT } dir_t;
typedef struct {
  state_t curSt   : CURST_SIZE;  // State required to execute instruction
  symbol_t curSym : CURSYM_SIZE; // Symbol required to execute instruction

  state_t newSt   : NEWST_SIZE;  // Final state after executing instruction
  symbol_t newSym : NEWSYM_SIZE; // Final symbol after executing instruction

  dir_t dir       : DIR_SIZE;    // LSB = move left, MSB = move right, 11b is undefined

  bool anyCurSt   : ANYCURST_SIZE;   // Ignore curSt, any state will do
  bool anyCurSym  : ANYCURSYM_SIZE;  // Ignore curSym, any symbol will do
  bool stChanged  : STCHANGED_SIZE;  // Ignore newSt, do not change the state
  bool symChanged : SYMCHANGED_SIZE; // Ignore newSym, do not change the symbol
} instr_t;

int getNthBitOfInstr(instr_t instruction, int n) {
  // (instruction >> n) & 1
  if (n < CURST_OFFSET)      return (instruction.curSt  >> (n)) & 1;
  if (n < CURSYM_OFFSET)     return (instruction.curSym >> (n - CURST_OFFSET)) & 1;
  if (n < NEWST_OFFSET)      return (instruction.newSt  >> (n - CURSYM_OFFSET)) & 1;
  if (n < NEWSYM_OFFSET)     return (instruction.newSym >> (n - NEWST_OFFSET)) & 1;
  if (n < DIR_OFFSET)        return (instruction.dir    >> (n - NEWSYM_OFFSET)) & 1;
  if (n < ANYCURST_OFFSET)   return (instruction.anyCurSt)   & 1; // simplified
  if (n < ANYCURSYM_OFFSET)  return (instruction.anyCurSym)  & 1; // simplified
  if (n < STCHANGED_OFFSET)  return (instruction.stChanged)  & 1; // simplified
  if (n < SYMCHANGED_OFFSET) return (instruction.symChanged) & 1; // simplified
  return -1;
}

void importFromFile(FILE *data, LweSample *result, int length,
                    const TFheGateBootstrappingParameterSet *params) {
  for (int i = 0; i < length; i++)
    import_gate_bootstrapping_ciphertext_fromFile(data, &result[i], params);
}

void exportToFile(FILE *data, LweSample *result, int length,
                  const TFheGateBootstrappingParameterSet *params) {
  for (int i = 0; i < length; i++)
    export_gate_bootstrapping_ciphertext_toFile(data, &result[i], params);
}

#define decrypt(x) bootsSymDecrypt(x, key)
symbol_t _symbolDecrypt(LweSample *target, TFheGateBootstrappingSecretKeySet *key) {
  symbol_t ret = 0;
  for (int i = 0; i < SYMBOL_SIZE; i++)
    ret |= decrypt(&target[i]) << i;
  return ret;
}
#define symbolDecrypt(x) _symbolDecrypt(x, key)
state_t _stateDecrypt(LweSample *target, TFheGateBootstrappingSecretKeySet *key) {
  state_t ret = 0;
  for (int i = 0; i < STATE_SIZE; i++)
    ret |= decrypt(&target[i]) << i;
  return ret;
}
#define stateDecrypt(x) _stateDecrypt(x, key)