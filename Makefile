CC = gcc
INCLUDE = -I$(GSOAP_ROOT)
CFLAGS = -DDEBUG
#LDFLAGS = -lpthread -luuid

SERVER_OBJS = gvcpServer.o

all: GvcpServer
GvcpServer: $(SERVER_OBJS) 
	$(CC) -o $@ $(SERVER_OBJS) $(LDFLAGS) 

%.o : %.c
	$(CC) -c  $^ $(CFLAGS)


clean:
	rm -f *.o GvcpServer
