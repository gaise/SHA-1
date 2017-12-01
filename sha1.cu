#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cuda.h>
#include "sha1.h"
#include <string.h>

#define SHA1CircularShift(bits,word) \
  (((word) << (bits)) | ((word) >> (32-(bits))))

__device__ void SHA1ProcessMessageBlock(SHA1Context *context) {
  const uint32_t K[] = { /* Constants defined in SHA-1 */
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6
  };
  int t;
  uint32_t tmp; /* Temporary word value */
  uint32_t W[80];  /* Word sequence */
  uint32_t A, B, C, D, E; /* Word buffers */

  /*
   *  Initialize the first 16 words in the array W
   */
  for (t = 0; t < 16; t++) {
    W[t] = context->Message_Block[t * 4] << 24;
    W[t] |= context->Message_Block[t * 4 + 1] << 16;
    W[t] |= context->Message_Block[t * 4 + 2] << 8;
    W[t] |= context->Message_Block[t * 4 + 3];
  }

  for (t = 16; t < 80; t++) {
    W[t] = SHA1CircularShift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];

  for (t = 0; t < 20; t++) {
    tmp =  SHA1CircularShift(5, A) +((B & C) | ((~B) & D)) + E + W[t] + K[0];
    E = D;
    D = C;
    C = SHA1CircularShift(30, B);
    B = A;
    A = tmp;
  }

  for (t = 20; t < 40; t++) {
    tmp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
    E = D;
    D = C;
    C = SHA1CircularShift(30, B);
    B = A;
    A = tmp;
  }

  for (t = 40; t < 60; t++) {
    tmp = SHA1CircularShift(5, A) +
      ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
    E = D;
    D = C;
    C = SHA1CircularShift(30, B);
    B = A;
    A = tmp;
  }

  for (t = 60; t < 80; t++) {
    tmp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
    E = D;
    D = C;
    C = SHA1CircularShift(30, B);
    B = A;
    A = tmp;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;

  context->Message_Block_Index = 0;

  return;
}

__device__ void SHA1PadMessage(SHA1Context *context) {
  if (context->Message_Block_Index > 55) {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while (context->Message_Block_Index < 64) {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }

    SHA1ProcessMessageBlock(context);

    while(context->Message_Block_Index < 56) {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }
  } else {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while (context->Message_Block_Index < 56) {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }
  }

  context->Message_Block[56] = context->Length_High >> 24;
  context->Message_Block[57] = context->Length_High >> 16;
  context->Message_Block[58] = context->Length_High >> 8;
  context->Message_Block[59] = context->Length_High;
  context->Message_Block[60] = context->Length_Low >> 24;
  context->Message_Block[61] = context->Length_Low >> 16;
  context->Message_Block[62] = context->Length_Low >> 8;
  context->Message_Block[63] = context->Length_Low;

  SHA1ProcessMessageBlock(context);

  return;
}

__device__ int SHA1Reset(SHA1Context *context) {
  if (!context)
    return 1;

  context->Length_Low = 0;
  context->Length_High = 0;
  context->Message_Block_Index = 0;

  context->Intermediate_Hash[0] = 0x67452301;
  context->Intermediate_Hash[1] = 0xEFCDAB89;
  context->Intermediate_Hash[2] = 0x98BADCFE;
  context->Intermediate_Hash[3] = 0x10325476;
  context->Intermediate_Hash[4] = 0xC3D2E1F0;

  context->Computed = 0;
  context->Corrupted = 0;

  return 0;
}

__device__ int SHA1Result(SHA1Context *context, uint8_t Message_Digest[20]) {
  int i;

  if (!context || !Message_Digest) return 1;
  if (context->Corrupted) return context->Corrupted;
  if (!context->Computed) {
    SHA1PadMessage(context);
    for (i = 0; i < 64; ++i) {
      context->Message_Block[i] = 0;
    }
    context->Length_Low = 0;
    context->Length_High = 0;
    context->Computed = 1;
  }

  for (i = 0; i < 20; ++i) {
    Message_Digest[i] = context->Intermediate_Hash[i>>2] >> 8*(3 - (i & 0x03));
  }

  return 0;
}


__device__ int SHA1Input(SHA1Context *context, const uint8_t *message_array, unsigned length) {
  if (!length) return 0;
  
  if (!context || !message_array) return 1;

  if (context->Computed) {
    context->Corrupted = 1;
    return 1;
  }

  if (context->Corrupted) return context->Corrupted;

  while(length-- && !context->Corrupted) {
    context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);

    context->Length_Low += 8;
    if (context->Length_Low == 0) {
      context->Length_High++;
      if (context->Length_High == 0) {
	/* Message is too long */
	context->Corrupted = 1;
      }
    }

    if (context->Message_Block_Index == 64) {
      SHA1ProcessMessageBlock(context);
    }

    message_array++;
  }

  return 0;
}


__device__ void input(uint8_t buf[20], int idx, int stride, int i)
{
  int j, k;
  int rem, quo, tmp, fac;

  for (j = 0; j < i; j++) {
    fac = stride;
    for (k = 0; k < 19; k++) {
      rem = fac % 256;
      quo = fac / 256;
      tmp = buf[k] + rem;
      buf[k] = tmp % 256;
      fac = quo + (tmp / 256);
    }
  }

  fac = idx;
  for (k = 0; k < 19; k++) {
    rem = fac % 256;
    quo = fac / 256;
    tmp = buf[k] + rem;
    buf[k] = tmp % 256;
    fac = quo + (tmp / 256);
  }

  return;
}

__device__ size_t my_strlen(const char *s)
{
  size_t n;
  for (n = 0; *s != '\0'; s++, n++);
  return n;
}

__global__ void kernel(int iter)
{
  int i, j;			// loop index
  int idx = threadIdx.x + blockIdx.x * blockDim.x; // threadID
  int stride = blockDim.x * gridDim.x;
  uint8_t buf[20] = {0};
  SHA1Context sha;
  uint8_t Message_Digest[20];

  for (i = 0; i < iter; i++) {
    for (j = 0; j < 20; j++)
      buf[j] = 0;

      input(buf, idx, stride, i);
      SHA1Reset(&sha);
      SHA1Input(&sha, buf, 20);
      SHA1Result(&sha, Message_Digest);
  }

  return;
}
    
