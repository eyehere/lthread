REDEFINE_INFO := redefine_syms
MYSQLCLI_ORIGIN := /usr/lib/libmysqlclient.a
MYSQLCLI_LIB := libmysqlclient.a
CFLAGS := -std=gnu99 -O1 -g -Wall -pipe -I../../src/ $(filter -I%, $(shell mysql_config --cflags))
LDFLAGS := $(filter-out -lmysqlclient, $(shell mysql_config --libs)) $(MYSQLCLI_LIB) ../../liblthread.a
SOURCES := $(wildcard *.c)
OBJS := $(patsubst %.c, %.o, $(SOURCES))
TARGET := mysql_lthread

all: $(MYSQLCLI_LIB) $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

$(TARGET): $(SOURCES) $(OBJS)
	$(CC) $(OBJS) -o mysql_lthread $(LDFLAGS)
	@echo [+] $(TARGET) example available

$(MYSQLCLI_LIB):
	@test -f $(MYSQLCLI_ORIGIN) || \
	echo -e "can't find msyql client static library;\ninstall the dev package with libmysqlclient.a, or edit the Makefile to set correct path\n"; \
	test -f $(MYSQLCLI_ORIGIN)
	objcopy --redefine-syms=$(REDEFINE_INFO) $(MYSQLCLI_ORIGIN) $(MYSQLCLI_LIB)
	@echo [+] mysql client library ready

clean:
	rm -f *.o $(TARGET) $(MYSQLCLI_LIB)
