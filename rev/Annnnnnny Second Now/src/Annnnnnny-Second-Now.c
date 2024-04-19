#include <stdio.h>

unsigned long super_optimized_calculation(unsigned int n) {
	if (n == 0) {
		return 0;
	} else if (n == 1) {
		return 1;
	} else {
		return super_optimized_calculation(n - 1) + super_optimized_calculation(n - 2);
	}
}

int main() {
        unsigned int mods[] = {35831, 143, 1061, 877, 29463179, 229, 112, 337, 1061, 47, 29599, 145, 127, 271639, 127, 353, 193, 191, 337, 1061, 193, 353, 269, 487, 245};
        unsigned long base = super_optimized_calculation(90);
        for (int i = 0; i < (sizeof(mods) / sizeof(mods[0])); i++) {
                putc(base % mods[i], stdout);
        }
	putc('\n', stdout);
        return 0;
}
