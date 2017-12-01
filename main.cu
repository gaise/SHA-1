#include <iostream>
#include <cuda.h>

#include <chrono>

#include "sha1.h"

#define BLOCK 4096
#define THREAD 256
#define ITER 1024

void checkCudaError(cudaError_t msg, int x)
{
 if (msg != cudaSuccess) {
   fprintf(stderr, "line: %d %s\n", x, cudaGetErrorString(msg));
   exit(1);
 }

 return;
}

int main()
{
  std::chrono::time_point<std::chrono::system_clock> start, end;
  double time;

  start = std::chrono::system_clock::now();

  kernel<<<BLOCK, THREAD>>>(ITER);

  cudaThreadSynchronize();

  end = std::chrono::system_clock::now();

  time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  std::cout << "execution time: " << time / 1000.0 << "s." << std::endl;

  return 0;
}

  
  
  

  
