
all : aesdsocket

aesdsocket : aesdsocket.o
		$(CC) -o aesdsocket aesdsocket.o -lpthread

aesdsocket.o : aesdsocket.c
		$(CC) -c aesdsocket.c queue.h -Wall 

clean : 
		rm -f aesdsocket aesdsocket.o
