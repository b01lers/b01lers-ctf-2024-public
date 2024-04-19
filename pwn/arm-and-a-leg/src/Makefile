final:
	aarch64-linux-gnu-gcc chal.c -no-pie -o  chal

clean:
	rm exparm

patch:
	patchelf --set-interpreter ld-linux-aarch64.so.1 --set-rpath . exparm
