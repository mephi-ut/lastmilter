
LDFLAGS = -lmilter -lresolv $(shell pkg-config --libs sqlite3) -L/usr/lib/libmilter/
INCFLAGS = 
CFLAGS += -pipe -Wall -pedantic -O2 -fstack-protector-all $(shell pkg-config --cflags sqlite3)
DEBUGCFLAGS = -pipe -Wall -pedantic -Werror -ggdb -Wno-error=unused-variable -fstack-protector-all

objs=\
main.o\


all: $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) $(objs) -o to-check-milter

%.o: %.c
	$(CC) -std=gnu11 $(CFLAGS) $(INCFLAGS) $< -c -o $@

debug:
	$(CC) -std=gnu11 $(DEBUGCFLAGS) $(INCFLAGS) $(LDFLAGS) main.c -o to-check-milter-debug

clean:
	rm -f to-check-milter to-check-milter-debug $(objs)


