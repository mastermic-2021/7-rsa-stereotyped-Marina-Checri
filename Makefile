ifeq ($(shell uname -s),Darwin)
	SHA:=shasum -a 256
else
	SHA:=sha256sum
endif

check:
	([ -f main.gp ] && ${MAKE} check-gp) || ([ -f main.c ] && ${MAKE} check-c)

main.gp.out: main.gp
	gp -fq < $< > $@

main.c.out: main.c
	gcc -o main $<
	./main > $@

check-%: .%.sum main.%.out
	$(SHA) -c $<
