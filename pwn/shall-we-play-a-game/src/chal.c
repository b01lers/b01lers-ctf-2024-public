#include <stdio.h>
	
void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}


void global_thermo_nuclear_war() {
	char flag[256];
	FILE *fp = fopen("flag.txt", "r");
	if (fp == NULL) {
		puts("flag.txt not found");
		return;
	}
	
	fgets(flag, sizeof(flag), fp);
	puts(flag);
}


int main() {
	setbuf(stdout, NULL);
	char buff[56];
	char first_r[16];
	char second_r[36];
	char third_r[36];
	puts("GREETINGS PROFESSOR FALKEN.");
	fgets(first_r, 19, stdin);

	puts("HOW ARE YOU FEELING TODAY?");
	fgets(second_r, 35, stdin);

	puts("EXCELLENT. IT'S BEEN A LONG TIME. CAN YOU EXPLAIN THE\nREMOVAL OF YOUR USER ACCOUNT ON 6/23/73?");
	fgets(third_r, 35, stdin);

	puts("SHALL WE PLAY A GAME?");
	fgets(buff, 0x56, stdin);

}	
