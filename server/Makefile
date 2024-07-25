
all : aesdsocket

aesdsocket : aesdsocket.o
		$(CC) -o aesdsocket aesdsocket.o

aesdsocket.o : aesdsocket.c
		$(CC) -c aesdsocket.c -Wall

clean : 
		rm -f aesdsocket aesdsocket.o
