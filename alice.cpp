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

size_t getStateID(char *item, char **set, size_t *len) {
  // Gets the id of the given state. Adds it to the state set if it is not present.
  for (size_t i = 0; i < *len; i++)
    if (strcmp(set[i], item) == 0) return i;
  set[(*len)++] = item;
  return (*len) - 1;
}

int main() {
  // reads the cloud key from file
  FILE *secret_key = fopen("secret.key", "rb");
  TFheGateBootstrappingSecretKeySet *key =
      new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
  fclose(secret_key);

  // reads the cloud key from file
  FILE *cloud_key = fopen("cloud.key", "rb");
  TFheGateBootstrappingCloudKeySet *bk =
      new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
  fclose(cloud_key);

  const TFheGateBootstrappingParameterSet *params = bk->params;

  instr_t plaininstr[INSTRSIZE];
  LweSample *cipherinstr[INSTRSIZE];
  printf("Initializing plain instruction array...\n");

  for (int i = 0; i < INSTRSIZE; i++)
    plaininstr[i] = (instr_t){ .dir = STATIONARY, .stChanged = false, .symChanged = false };

  FILE* instrfile = fopen("program.txt", "r");
  char line[256];
  uint16_t instrNum = 0;
  uint16_t lineNum = 1;
  char *stateSet[STATE_SIZE];
  stateSet[0] = (char*) "0"; // initial state
  stateSet[1] = (char*) "*"; // dummy
  size_t stateNum = 2; // Begin from 2, because states 0 and 1 are taken by default
  while (fgets(line, sizeof(line), instrfile)) {
    if (instrNum >= INSTRSIZE) {
      printf("This program supports at most %d instructions, change turing.h to support more.\n", INSTRSIZE);
      return 1;
    }

    char* _curSt = strtok(line, " ");
    if (_curSt[0] == ';' || _curSt[0] == '\r' || _curSt[0] == '\n') continue;
    char* curSt = strdup(_curSt);
    symbol_t curStID = getStateID(curSt, stateSet, &stateNum);
    bool anyCurSt = strcmp(curSt, "*") == 0;

    char* _curSym = strtok(NULL, " ");
    if (_curSym[0] == ';' || _curSym[0] == '\r' || _curSym[0] == '\n') continue;
    if (strlen(_curSym) != 1) {
      printf("Symbol \"%s\" is invalid, must be one character long (at line %d)\n", _curSym, lineNum);
      return 1;
    }
    symbol_t curSym = _curSym[0];
    bool anyCurSym = curSym == '*';

    char* _newSym = strtok(NULL, " ");
    if (_newSym[0] == ';' || _newSym[0] == '\r' || _newSym[0] == '\n') continue;
    if (strlen(_newSym) != 1) {
      printf("Symbol \"%s\" is invalid, must be one character long (at line %d)\n", _newSym, lineNum);
      return 1;
    }
    symbol_t newSym = _newSym[0];
    bool symChanged = (newSym != '*') && (curSym != newSym);

    char* _dirChar = strtok(NULL, " ");
    if (_dirChar[0] == ';' || _dirChar[0] == '\r' || _dirChar[0] == '\n') continue;
    if (strlen(_dirChar) != 1) {
      printf("Direction \"%s\" is invalid, must be 'l', 'r' or '*' (at line %d)\n", _dirChar, lineNum);
      return 1;
    }
    char dirChar = _dirChar[0];
    dir_t dir;
    switch (dirChar) {
      case 'l':
        dir = LEFT;
        break;
      case 'r':
        dir = RIGHT;
        break;
      case '*':
        dir = STATIONARY;
        break;
      default:
        printf("Direction \"%s\" is invalid, must be 'l', 'r' or '*' (at line %d)\n", _dirChar, lineNum);
        return 1;
    }

    char* _newSt = strtok(NULL, " ");
    if (_newSt[0] == ';' || _newSt[0] == '\r' || _newSt[0] == '\n') continue;
    char* newSt = strdup(_newSt);
    symbol_t newStID = getStateID(newSt, stateSet, &stateNum);
    printf("State %s has ID %d\n", newSt, newStID);
    bool stChanged = (strcmp(_newSt, "*") != 0) && (curStID != newStID);

    plaininstr[instrNum] = {
      .curSt      = curStID,
      .anyCurSt   = anyCurSt,
      .curSym     = curSym,
      .anyCurSym  = anyCurSym,
      .dir        = dir,
      .newSt      = newStID,
      .stChanged  = stChanged,
      .newSym     = newSym,
      .symChanged = symChanged
    };
    #if DEBUG
      printf(
        "Emitting instruction: "
        "(" STATE_FORMAT " [any %d] " SYMBOL_FORMAT " [any %d]) -> "
        "(" STATE_FORMAT " [changed %d] " SYMBOL_FORMAT " [changed %d]), direction %c\n",
        curStID, anyCurSt, curSym, anyCurSym,
        newStID, stChanged, newSym, symChanged,
        dir == LEFT ? 'l' : (dir == RIGHT ? 'r' : 'x')
      );
    #endif
    instrNum++;
    lineNum++;
  }

  #if DEBUG
    printf("State map:\n");
    for (size_t i = 0; i < stateNum; i++)
      printf("\t" STATE_FORMAT ": %s\n", i, stateSet[i]);
  #endif

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
    plaintape[i] = '_';
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
  delete_gate_bootstrapping_cloud_keyset(bk);
}