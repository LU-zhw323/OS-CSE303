# names of .cc files that have a main() function
TARGETS = text_io# TODO: put your file names here, *without a file extension*

# names of .cc files that are used by all of the above targets
CXXFILES = # no common files yet :)

# Let the programmer choose 32 or 64 bits, but default to 64 bits
BITS ?= 64

# Specify the name of the folder where all output will go
ODIR := ./obj$(BITS)

# This line ensures that the above folder will be created before any compiling
# happens.
output_folder := $(shell mkdir -p $(ODIR))

# Generate the names of the .o files and .exe files that we will be creating.
# Note that we name all .o files explicitly, so that we can add them to the
# .PRECIOUS target, which prevents them from being auto-removed.
COMMONOFILES = $(patsubst %, $(ODIR)/%.o, $(CXXFILES)) # NB: These get linked into every executable
ALLOFILES    = $(patsubst %, $(ODIR)/%.o, $(CXXFILES) $(TARGETS))
EXEFILES     = $(patsubst %, $(ODIR)/%.exe, $(TARGETS))

# Generate the names of the dependency files that g++ will generate, so that we
# can include them later in this makefile
DFILES     = $(patsubst %.o, %.d, $(ALLOFILES))

# Basic tool configuration for gcc/g++.  We will create debug symbols, enable
# optimizations, and generate dependency information on-the-fly
CXX      = g++
LD       = g++
CXXFLAGS = -MMD -O3 -m$(BITS) -ggdb -std=c++17 -Wall -Werror
LDFLAGS  = -m$(BITS) -lpthread -lcrypto

# Build 'all' by default, and don't clobber .o files after each build
.DEFAULT_GOAL = all
.PRECIOUS: $(ALLOFILES)
.PHONY: all clean

# Goal is to build all executables
all: $(EXEFILES)

# Rules for building object files
$(ODIR)/%.o: %.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS)

# Rules for building executables... we assume an executable uses *all* of the 
# common OFILES
$(ODIR)/%.exe: $(ODIR)/%.o $(COMMONOFILES)
	@echo "[LD] $^ --> $@"
	@$(CXX) $^ -o $@ $(LDFLAGS)

# clean by clobbering the build folder
clean:
	@echo Cleaning up...
	@rm -rf $(ODIR)

# Include any dependencies we generated previously
-include $(DFILES)