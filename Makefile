CC = gcc
INCLUDE = -I$(GSOAP_ROOT)
CFLAGS = -DDEBUG
#LDFLAGS = -lpthread -luuid

SERVER_OBJS = gvcpServer.o

all: gvcpServer
gvcpServer: $(SERVER_OBJS) 
	$(CC) -o $@ $(SERVER_OBJS) $(LDFLAGS) 

%.o : %.c
	$(CC) -c  $^ $(CFLAGS)


clean:
	rm -f *.o gvcpServer
