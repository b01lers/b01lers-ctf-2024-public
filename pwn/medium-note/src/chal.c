#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>


char * chunks[32] = {0};

int get_idx(){
	printf("Where? ");
	int idx;
	scanf("%d", &idx);
	if (idx < 0 || idx >=32){
		printf("Illegal idx");
		return -1;
	}
}

size_t get_size(){
	printf("size? ");
	size_t  size;
	scanf("%ld", &size);
	return size;
}

void alloc(){

	int idx = get_idx();
	if (idx == -1){
		return;
	}
	size_t size = get_size();

	char * chunk = (char*)malloc(size);
	if(!chunk){
		printf("Malloc couldn't alloc chunk of size %ld\n", size);
	}

	chunks[idx] = chunk;
}
void view(){
	int idx = get_idx();
	if (idx == -1){
		return;
	}

	puts(chunks[idx]);

}



void resize(){
	int idx = get_idx();
	if (idx == -1 ){
		return;
	}
	char * target = chunks[idx];
	if(!target){
		printf("Can't realloc ");
		return;
	}
	size_t size = get_size();

	char * new = (char*)realloc(target, size);
	if(!new){
		puts("Realloc failed\n");
		return;
	}
	chunks[idx] = new;
}

void nuke(){
	int idx = get_idx();
	if (idx == -1){
		return;
	}

	free(chunks[idx]);

}

void win(){
	static char *newargv[] = { "/flag.txt","/flag.txt", NULL };
	static char *newenviron[] = { NULL };
	execve("/bin/cat", newargv, newenviron);
}

void mystery(){
	printf("Address: %p\n", &win);
}

void edit(){
	int idx = get_idx();
	if (idx == -1 || idx >= 32){
		return;
	}
	size_t size = malloc_usable_size(chunks[idx]);
	if (size  < 0x20){
		//printf("Rounding up size %zu to 0x20 bc I'm nice :)", size);
		size = 0x20;

	}
	if (size > 0x100){
		size = 0x1000;
	}
	printf("Size for edit is %zu\n", size);
	read(0,chunks[idx], size);

}

void menu(){

	while(1){

		char key = fgetc(stdin);
		int option = key - 0x30;	
		if (key == '\n'){
			continue;
		}

		switch(option){
			case 1:
				alloc();
				break;
			case 2:
				nuke();
				break;
			case 3:
				view();
				break;
			case 4:
				edit();
				break;
			case 5:
				exit(0);
			case 6:
				resize();
				break;
			case 7:
				mystery();
				break;
		}
		printf("-----Options---\n");
		printf("-----Alloc-----\n");
		printf("-----Free------\n");
		printf("-----View------\n");
		printf("-----Edit------\n");
		printf("-----Exit------\n");
		printf("-----Resize----\n");



	}


}

int main(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	printf("-----Options---\n");
	printf("-----Alloc-----\n");
	printf("-----Free------\n");
	printf("-----View------\n");
	printf("-----Edit------\n");
	printf("-----Exit------\n");
	printf("-----Resize----\n");

	menu();
}
