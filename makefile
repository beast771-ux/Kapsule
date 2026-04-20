CC = gcc
CFLAGS = -Wall -Wextra -g

all: kapsule

kapsule: main.c module1.c module2.c module3.c
	$(CC) $(CFLAGS) -o kapsule main.c module1.c module2.c module3.c

clean:
	rm -f kapsule
	sudo rm -rf container_work/upper/* container_work/work/* container_work/merged/*