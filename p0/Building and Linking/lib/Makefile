# The name of the library, and the names of the C++ files we use to build it
TARGET = libmylib
CXXFILES = printer printerLib

# Basic tool configuration for a 64-bit build
BITS ?= 64
CXX = g++
LD = g++
CXXFLAGS += -MMD -O3 -m$(BITS) -ggdb -std=c++17 -Wall -Werror -march=native
LDFLAGS += -m$(BITS)

# Special flags for building .so files
CXXFLAGS += -fPIC # cause the code to compile in a "position-independent" way.
LDFLAGS += -shared

# Compute the names of everything that gets built; make the output folder
ODIR := ./obj$(BITS)
out_folder := $(shell mkdir -p $(ODIR))
SOFILES = $(patsubst %, $(ODIR)/%.so, $(TARGET))
OFILES = $(patsubst %, $(ODIR)/%.o, $(CXXFILES))
DFILES = $(patsubst %, $(ODIR)/%.d, $(CXXFILES))

# Build 'all' by default, and do not clobber .o files after each build
.DEFAULT_GOAL = all
.PRECIOUS: $(OFILES)
.PHONY: all clean

# Goal is to build the shared object
all: $(SOFILES)

# Build a .o from a .cc
$(ODIR)/%.o: %.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS)

# Build a .so from all the .o files
$(ODIR)/%.so: $(OFILES)
	@echo "[LD] $^ --> $@"
	@$(LD) $^ -o $@ $(LDFLAGS)
	
# Clean by clobbering the build folder
clean:
	@echo Cleaning up...
	@rm -rf $(ODIR)

# Include the auto-generated dependency files, so that re-making is quick
-include $(DFILES)