#include <stdint.h>
#include <cuda.h>

#ifndef _SHA1_H_
#define _SHA1_H_

#ifndef _SHA_enum_
#define _SHA_enum_
enum {
  shaSuccess = 0,
  shaNULL,
  shaInputTooLong,
  shaStateError
};
#endif

typedef struct SHA1Context {
  uint32_t Intermediate_Hash[5];	/* Message Digest */
  
  uint32_t Length_Low;			/* Message length in bits */
  uint32_t Length_High;			/* Message length in bits */
  
  /* Index into message block array   */
  int_least16_t Message_Block_Index;
  uint8_t Message_Block[64];		/* 512-bit message blocks */
  
  int Computed;				/* Is the digest computed? */
  int Corrupted;				/* Is the message digest corrupted?	*/
} SHA1Context;

__global__ void kernel(int iter);

#endif
