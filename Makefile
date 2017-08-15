CPP = clang++

CXXFLAGS += -std=c++11 -stdlib=libc++ -Wall -Wextra -Wno-c99-extensions
LDFLAGS += -ltfhe-spqlios-avx

all: keygen alice cloud verif

keygen: keygen.cpp turing.h
	${CPP} keygen.cpp -o keygen ${CXXFLAGS} ${LDFLAGS}

alice: alice.cpp turing.h
	${CPP} alice.cpp -o alice ${CXXFLAGS} ${LDFLAGS}

cloud: cloud.cpp turing.h
	${CPP} cloud.cpp -o cloud ${CXXFLAGS} ${LDFLAGS}

verif: verif.cpp turing.h
	${CPP} verif.cpp -o verif ${CXXFLAGS} ${LDFLAGS}

clean:
	rm -f alice cloud verif *.key *.data