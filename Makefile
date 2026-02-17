# Compiler
CXX = icpx

# Compiler flags
# -fsycl: Enable SYCL compilation
# -O3: High optimization level
# -std=c++20: Use C++20 standard
CXXFLAGS = -fsycl -O3 -std=c++20 -Wall -Wextra -march=native

# Target executable name
TARGET = sha2_collision

# Source files
SRCS = main.cpp

# Header files
HDRS = sha2.hpp

!IF "$(OS)" == "Windows_NT"
RM = del /Q
EXE = .exe
TARGET_BIN = $(TARGET)$(EXE)
!ELSE
RM = rm -f
EXE =
TARGET_BIN = $(TARGET)
!ENDIF

# Build rule
$(TARGET_BIN): $(SRCS) $(HDRS)
    $(CXX) $(CXXFLAGS) -o $(TARGET_BIN) $(SRCS)

# Run rule
run: $(TARGET_BIN)
    ./$(TARGET_BIN)

# Clean rule
clean:
    $(RM) $(TARGET_BIN)

.PHONY: clean run
