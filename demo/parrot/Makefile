CC		= g++
CFLAGS		= -g -O0
MODULES		= libparrot.so

.PHONY:         all clean

all:            $(MODULES)

clean:
	rm -f $(OBJECTS) $(MODULES) main


$(MODULES): \
lib%.so:           %.cpp
	$(CC) $(CFLAGS)  -I../../src -I../../../qwebvdom -lstdc++ -L../../../../../sdk/lib -lstdc++ -fPIC -shared -o $@ $<
