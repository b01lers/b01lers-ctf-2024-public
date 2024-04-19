#include <stdio.h>
#include <string.h>

char song[20];
char ticket[40];

void use_ticket(char *ticket) {
	FILE *fp = fopen("flag.txt", "r");
	if (fp == NULL) {
		printf("flag.txt not found");
		return;
	}
	int end = fread(ticket, 1, 39, fp);
	ticket[end] = '\0';
}	

int help_me() {
	char buff[56];
	puts("I was going to go to the eras tour, but something came up :(");
	puts("You can have my ticket! Only thing is... I forgot where I put it...");
	puts("Do you know where it could be?! ");
	fgets(buff, 100, stdin);	
	fflush(stdin);
	return 0;
}

int main() {
	setbuf(stdout, NULL);
	help_me();
	printf("sooo... anyways whats your favorite Taylor Swift song? ");
	fflush(stdout);
	read(0, song, 200); // ype
	printf("Ooohh! ");
	printf(song);
	printf("Thats a good one!\n");
	return 0;
}	
