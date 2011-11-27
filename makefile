CC=g++
CFLAGS=-c -Wall -g -m64
LDFLAGS=-Wl,-Bstatic -lgmp -Wl,-Bdynamic -lcryptopp -lpthread
EXECUTABLE=fully_homomorphic
TEST_EXECUTABLE=test_fully_homomorphic
DEMO_EXECUTABLE=demo_fully_homomorphic

all : $(EXECUTABLE)

test : $(TEST_EXECUTABLE)

demo : $(DEMO_EXECUTABLE)

$(TEST_EXECUTABLE) : test_suite.o fully_homomorphic.o utilities.o circuit.o security_settings.o
	$(CC) -o $@ test_suite.o fully_homomorphic.o utilities.o circuit.o security_settings.o $(LDFLAGS)

$(DEMO_EXECUTABLE) : demo_vote_counter.o fully_homomorphic.o utilities.o circuit.o security_settings.o
	$(CC) -o $@ demo_vote_counter.o fully_homomorphic.o utilities.o circuit.o security_settings.o $(LDFLAGS)

$(EXECUTABLE) : main.o fully_homomorphic.o utilities.o circuit.o security_settings.o
	$(CC) -o $@ main.o fully_homomorphic.o utilities.o circuit.o security_settings.o $(LDFLAGS)

test_suite.o : test_suite.cpp
	$(CC) $(CFLAGS) test_suite.cpp

demo_vote_counter.o : demo_vote_counter.cpp
	$(CC) $(CFLAGS) demo_vote_counter.cpp

main.o : main.cpp
	$(CC) $(CFLAGS) main.cpp

utilities.o : utilities.c
	$(CC) $(CFLAGS) utilities.c

fully_homomorphic.o : fully_homomorphic.cpp fully_homomorphic.h type_defs.h
	$(CC) $(CFLAGS) fully_homomorphic.cpp -lgmp -lcryptopp -lpthreads

circuit.o : circuit.cpp
	$(CC) $(CFLAGS) circuit.cpp

security_settings.o : security_settings.cpp
	$(CC) $(CFLAGS) security_settings.cpp

clean :
	rm -rf *.o fully_homomorphic
