C = gcc
CXX = g++
C_LIB = net/network.c net/nl.c
C_LINK = net/network.o net/nl.o
MAIN = main.cpp
LD = -std=c++11
OUT = docker-run

all:
	make container
container:
	$(C) -c $(C_LIB)
	$(CXX) $(LD) -o $(OUT) $(MAIN) $(C_LINK)
clean:
	rm *.o $(OUT)
