SRCDIR = .
SRC := $(wildcard $(SRCDIR)/*.c)
SRCNAM := $(notdir $(SRC))
ODIR := .
OBJ := $(patsubst %.c, $(ODIR)/%.o, $(SRCNAM))
TARGET = local server
TOBJ := $(addsuffix .o, $(TARGET))
TOBJ := $(addprefix $(ODIR)/, $(TOBJ))
OBJ := $(filter-out $(TOBJ), $(OBJ))

all:: $(TARGET)

local: local.o $(OBJ)

server: server.o $(OBJ)

clean::
	-rm -f *.o $(TARGET)
