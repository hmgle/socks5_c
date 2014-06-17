TARGET = local server

all: $(TARGET)

local: local.o socket_wrap.o

server: server.o socket_wrap.o

clean::
	-rm -f *.o $(TARGET)
