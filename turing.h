#include <stdint.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#define TAPESIZE (32)
#define INSTRSIZE (8)

#define CURST_SIZE      (16)
#define CURSYM_SIZE     (16)
#define NEWST_SIZE      (16)
#define NEWSYM_SIZE     (16)
#define STCHANGED_SIZE  ( 1)
#define SYMCHANGED_SIZE ( 1)
#define DIR_SIZE        ( 2)

#define CURST_OFFSET      (                    CURST_SIZE)
#define CURSYM_OFFSET     (CURST_OFFSET      + CURSYM_SIZE)
#define NEWST_OFFSET      (CURSYM_OFFSET     + NEWST_SIZE)
#define NEWSYM_OFFSET     (NEWST_OFFSET      + NEWSYM_SIZE)
#define STCHANGED_OFFSET  (NEWSYM_OFFSET     + STCHANGED_SIZE)
#define SYMCHANGED_OFFSET (STCHANGED_OFFSET  + SYMCHANGED_SIZE)
#define DIR_OFFSET        (SYMCHANGED_OFFSET + DIR_SIZE)

#define INSTRBITLEN (CURST_SIZE + CURSYM_SIZE + NEWST_SIZE + NEWSYM_SIZE + STCHANGED_SIZE + SYMCHANGED_SIZE + DIR_SIZE)

#if INSTRBITLEN != DIR_OFFSET
  #error WTF
#endif

typedef uint16_t symbol_t;
typedef uint16_t state_t;
typedef enum { STATIONARY, LEFT, RIGHT } dir_t;
typedef struct {
  state_t curSt   : CURST_SIZE;
  symbol_t curSym : CURSYM_SIZE;

  state_t newSt   : NEWST_SIZE;
  symbol_t newSym : NEWSYM_SIZE;
  bool stChanged  : STCHANGED_SIZE;
  bool symChanged : SYMCHANGED_SIZE;

  dir_t dir       : DIR_SIZE;
} instr_t;

int getNthBitOfInstr(instr_t instruction, int n) {
  // (instruction >> n) & 1
  if (n < CURST_OFFSET)      return (instruction.curSt  >> (n)) & 1;
  if (n < CURSYM_OFFSET)     return (instruction.curSym >> (n - CURST_OFFSET)) & 1;
  if (n < NEWST_OFFSET)      return (instruction.newSt  >> (n - CURSYM_OFFSET)) & 1;
  if (n < NEWSYM_OFFSET)     return (instruction.newSym >> (n - NEWST_OFFSET)) & 1;
  if (n < STCHANGED_OFFSET)  return (instruction.stChanged) & 1; // simplified
  if (n < SYMCHANGED_OFFSET) return (instruction.symChanged) & 1; // simplified
  if (n < DIR_OFFSET)        return (instruction.dir    >> (n - SYMCHANGED_OFFSET)) & 1;
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