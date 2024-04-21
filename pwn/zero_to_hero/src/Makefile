EXE: z2h z2h-unstripped

all: $(EXE)

%-unstripped: %.c
	gcc -o $@ -Wall -O3 $< -Wl,-z,relro,-z,now -masm=intel

%: %-unstripped
	cp -p $< $@
	strip -s $@

.SUFFIXES:
.PHONY: all
