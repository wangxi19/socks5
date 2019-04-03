CPPFLAGS = -std=c++17

ifneq ($(dbg), 1)
	CPPFLAGS += -O3
else
	CPPFLAGS := $(CPPFLAGS) -g -O0
endif

CXX =g++
SRCS =$(wildcard ./src/*.cpp)
OBJS =$(SRCS:./src/%.cpp=%.o)
LIBS +=

CPPFLAGS += $(LIBS)
CPPFLAGS += -I./src/

TARGET = mysocks5

all: $(TARGET)


$(TARGET): $(filter %.o, $(OBJS))
	$(CXX) $(CPPFLAGS) $^ -o $@	


$(filter %.o, $(OBJS)): %.o: ./src/%.cpp
	$(CXX) -c $(CPPFLAGS) $< -o $@

.PHONY: clean

clean:
	$(RM) $(TARGET) 
	$(RM) $(filter $(wildcard *.o), $(OBJS))
	$(RM) /usr/local/bin/$(TARGET)

install:
	cp $(TARGET) /usr/local/bin


