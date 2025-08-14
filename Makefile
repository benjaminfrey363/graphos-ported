
# 1. Compiler and Flags
# -----------------------------------------------------------------------------
# Use g++ as the C++ compiler.
CXX        := g++

# Flags for the compiler.
# -g: Adds debugging information for GDB.
# -Wall -Wextra: Enables all major warnings. Highly recommended.
# -std=c++17: Use the C++17 standard.
CXXFLAGS   := -g -Wall -Wextra -std=c++17

# Flags for the preprocessor, specifically for include paths (-I).
# -I.: Allows includes relative to the project root (e.g., #include "include/Common.h").
# -IEnclave: Allows includes relative to the Enclave dir (e.g., #include "include/AES.hpp").
CPPFLAGS   := -I. -IEnclave

# Flags for the linker (e.g., -L/path/to/libs).
LDFLAGS    :=

# Libraries to link against.
# We need -lssl and -lcrypto for the OpenSSL dependency.
LDLIBS     := -lssl -lcrypto


# 2. Project Structure
# -----------------------------------------------------------------------------
# The name of the final executable program.
TARGET     := graphos

# The directory to store all compiled object files (.o).
BUILD_DIR  := build

# List all your .cpp source files here.
# This is generated from the directory structure you provided.
SRCS       := \
	Enclave/AES.cpp \
	Enclave/AVLTree.cpp \
	Enclave/Bid.cpp \
	Enclave/DOHEAP.cpp \
	Enclave/HeapObliviousOperations.cpp \
	Enclave/LocalRAMStore.cpp \
	Enclave/OHeap.cpp \
	Enclave/OMAP.cpp \
	Enclave/ORAM.cpp \
	Enclave/ObliviousOperations.cpp \
	Enclave/PRF.cpp \
	Enclave/enclave.cpp \
	src/AES.cpp \
	src/Bid.cpp \
	src/GraphNode.cpp \
	src/Node.cpp \
	src/RAMStore.cpp \
	src/Utilities.cpp \
	src/main.cpp

# Automatically generate object file names, placing them in the BUILD_DIR
# and preserving the directory structure to avoid name collisions.
# e.g., src/main.cpp becomes build/src/main.o
OBJS       := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SRCS))


# 3. Build Rules
# -----------------------------------------------------------------------------
# The default rule, executed when you just type "make".
.PHONY: all
all: $(TARGET)

# Rule to link the final executable from all the object files.
$(TARGET): $(OBJS)
	@echo "LD   $@"
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Pattern rule to compile .cpp files into .o files in the build directory.
# This is the core rule that handles the out-of-source build and duplicate filenames.
$(BUILD_DIR)/%.o: %.cpp
	@echo "CXX  $<"
	# Create the subdirectory in the build folder if it doesn't exist.
	@mkdir -p $(dir $@)
	# Compile the source file into an object file.
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@


# 4. Utility Rules
# -----------------------------------------------------------------------------
# Rule to clean up all generated files.
.PHONY: clean
clean:
	@echo "CLEAN"
	rm -rf $(BUILD_DIR) $(TARGET)