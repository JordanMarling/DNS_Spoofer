######################
#  Jordans Makefile  #
######################

EXECUTABLE=../dns_spoofer
#PARAMS=--mitm --config config 192.168.1.1 192.168.1.33
PARAMS=--mitm --config config 192.168.0.100 192.168.0.6

CCPP=g++
CCPP_FLAGS=-c -Wall

CASM=nasm
CASM_FLAGS=-f elf64

LDFLAGS=
LIBS=-lpthread
ASM_SOURCES=$(shell ls | grep ".*\.asm$$")
ASM_OBJECTS=$(ASM_SOURCES:.asm=.ao)
CPP_SOURCES=$(shell ls | grep ".*\.c$$") $(shell ls | grep ".*\.cpp$$")
CPP_OBJECTS=$(CPP_SOURCES:.cpp=.o)
CPP_OBJECTS:=$(CPP_OBJECTS:.c=.o)

#export MAKEFLAGS=-j

all: $(EXECUTABLE)

$(EXECUTABLE): $(ASM_OBJECTS) $(CPP_OBJECTS)
	$(CCPP) $(LDFLAGS) $(ASM_OBJECTS) $(CPP_OBJECTS) -o $@ $(LIBS)

run: $(EXECUTABLE)
	./$(EXECUTABLE) $(PARAMS)

debug: CASM_FLAGS += -g -O0
debug: CCPP_FLAGS += -g -O0
debug: clean $(EXECUTABLE)
	gdb --args $(EXECUTABLE) $(PARAMS)

valgrind: CASM_FLAGS += -g -O0
valgrind: CCPP_FLAGS += -g -O0
valgrind: clean $(EXECUTABLE)
	valgrind --leak-check=full --show-possibly-lost=no ./$(EXECUTABLE) $(PARAMS)

# TODO make this work. It is currently piped into stdout.
disassembly: CCPP_FLAGS += -g -Wa,-alh
disassembly: clean $(CPP_OBJECTS)

clean:
	rm -f $(ASM_OBJECTS) $(CPP_OBJECTS) $(EXECUTABLE)

%.ao: %.asm
	$(CASM) $(CASM_FLAGS) $< -o $@ $(LIBS)

%.o: %.cpp
	$(CCPP) $(CCPP_FLAGS) $< -o $@ $(LIBS)

%.o: %.c
	$(CCPP) $(CCPP_FLAGS) $< -o $@ $(LIBS)
