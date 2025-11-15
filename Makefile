CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2
TARGET = secure_delete
SOURCE = secure_delete.cpp
ENHANCED_TARGET = secure_delete_enhanced
ENHANCED_SOURCE = secure_delete_enhanced.cpp

all: $(TARGET) $(ENHANCED_TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE)

$(ENHANCED_TARGET): $(ENHANCED_SOURCE)
	$(CXX) $(CXXFLAGS) -o $(ENHANCED_TARGET) $(ENHANCED_SOURCE)

clean:
	rm -f $(TARGET) $(ENHANCED_TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install