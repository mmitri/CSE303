# The name of the exe file, the name of the so file, and the names of the C++
# files we use to build each
EXE_TARGET = demo
SO_TARGET = myso
EXE_CXXFILES = prog menu
SO_CXXFILES = simple_print

# Basic tool config for a 64-bit build
BITS ?= 64
CXX = g++
LD = g++
CXXFLAGS += -MMD -O3 -m$(BITS) -ggdb -std=c++17 -Wall -Werror -march=native
LDFLAGS += -m$(BITS)

# Special flags for linking an executable that uses dlopen
EXE_LDFLAGS += -ldl

# Special flags for building .so files
SO_CXXFLAGS += -fPIC
SO_LDFLAGS += -shared

# Compute the names of everything that gets built; make the output folder
ODIR :=./obj$(BITS)
out_folder := $(shell mkdir -p $(ODIR))
EXEFILES = $(patsubst %, $(ODIR)/%.exe, $(EXE_TARGET))
EXE_OFILES = $(patsubst %, $(ODIR)/%.exe.o, $(EXE_CXXFILES))
SOFILES = $(patsubst %, $(ODIR)/%.so, $(SO_TARGET))
SO_OFILES = $(patsubst %, $(ODIR)/%.so.o, $(SO_CXXFILES))
DEPS = $(patsubst %, $(ODIR)/%.d, $(EXE_CXXFILES)$(SO_CXXFILES))

# Build 'all' by default, and do not clobber .o files after each build
.DEFAULT_GOAL = all
.PRECIOUS: $(SO_FILES) $(EXE_OFILES)
.PHONY: all clean

# Goal is to build all executables and shared objects
all: $(EXEFILES) $(SOFILES)

# Build a .o from a .cc
# NB: We use a two-part suffix to know if we need extra CXXFLAGS or not
$(ODIR)/%.exe.o: %.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS)
$(ODIR)/%.so.o: %.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS) $(SO_CXXFLAGS)

# Build a .exe from its .o files
$(ODIR)/%.exe: $(EXE_OFILES)
	@echo "[LD] $< --> $@"
	@$(LD) $^ -o $@ $(LDFLAGS) $(EXE_LDFLAGS)

# Build a .so from all its .o files
$(ODIR)/%.so: $(SO_OFILES)
	@echo "[LD] $^ --> $@"
	@$(LD) $^ -o $@ $(LDFLAGS) $(SO_LDFLAGS)

# Clean by clobbering the build folder
clean:
	@echo Cleaning up your mess...
	@rm -rf $(ODIR)

# Include the auto-generated dependency files, so that re-making is quick
-include $(DEPS)