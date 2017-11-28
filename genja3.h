#include <stdint.h>

#define DEBUG     0

extern uint32_t options;

#define PRINT_JA3 1
#define PRINT_DST 2
#define FORCE_DST 4
#define PRINT_SRC 8
#define PRINT_SNI 16
#define PRINT_ALP 32
#define PRINT_RAW 64
#define CREATE_BYTE_ARRAY 128
#define FINGERPRINT_CLASS 256

#define OF_ON(oflag) ((!(options & oflag)) ? (options ^= oflag) : (options))
#define OF_OFF(oflag) ((options & oflag) ? (options ^= oflag) : options)
#define OF(oflag) (options & oflag)

