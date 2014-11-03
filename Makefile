CFLAGS += -g -Wall -O0 -DDEBUG

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

sinclude $(SRC:.c=.d)

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
		sed 's,\(.*\)\.o[:]*,$(ODIR)/\1.o $@:,' < $@.$$$$ > $@; \
		rm -f $@.$$$$

clean::
	-rm -f *.d *.o $(TARGET)
