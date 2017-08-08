CPP = clang++

CXXFLAGS += -std=c++11 -Wall -Wextra -pedantic -Wno-c99-extensions
LDFLAGS += -ltfhe-spqlios-fma

all: alice cloud verif

alice: alice.cpp turing.h
	${CPP} alice.cpp -o alice ${CXXFLAGS} ${LDFLAGS}

cloud: cloud.cpp turing.h
	${CPP} cloud.cpp -o cloud ${CXXFLAGS} ${LDFLAGS}

verif: verif.cpp turing.h
	${CPP} verif.cpp -o verif ${CXXFLAGS} ${LDFLAGS}

clean:
	rm -f alice cloud verif *.key *.data