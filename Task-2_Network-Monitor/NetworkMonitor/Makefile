# ============================================================
#  Makefile — Network Monitoring & Log Analysis System
#  Compiler: g++ (MinGW/MSYS2 on Windows, or g++ on Linux)
# ============================================================

CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET   = NetworkMonitor
SRC      = main.cpp src/log_processor.cpp src/analyzer.cpp src/report_generator.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)
	@echo ""
	@echo "Build successful! Run with: ./$(TARGET)"

clean:
	rm -f $(TARGET) $(TARGET).exe

# Windows shortcut
win:
	$(CXX) $(CXXFLAGS) -o $(TARGET).exe $(SRC)
	@echo "Windows build done: $(TARGET).exe"
