all: main
	./main | head

dsl: main
	./main > dsl.h

caml: main
	./main > caml.ml

main: main.hs generators.hs parse.hs gen_structs.hs parse_structs.hs
	ghc --make $^ -Wall

.PHONY: clean

clean:
	rm -f *.o *.hi main
