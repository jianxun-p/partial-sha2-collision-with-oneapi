# Compiler
CXX = icpx

# Compiler flags
# -fsycl: Enable SYCL compilation
# -O3: High optimization level
# -std=c++20: Use C++20 standard
CXXFLAGS = -fsycl -O3 -std=c++20 -Wall -Wextra

# Target executable name
TARGET = sha2_collision

# Source files
SRCS = main.cpp

# Header files
HDRS = sha2.hpp

# Build rule
$(TARGET): $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

# Run rule
run: $(TARGET)
	./$(TARGET)

# Clean rule
clean:
	rm -f $(TARGET)

.PHONY: clean run
