main: main.cu sha1.cu
	nvcc -std=c++11 -o $@ $^

clean:
	rm -f *.o main
