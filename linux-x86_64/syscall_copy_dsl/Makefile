all: main
	./main | head

dsl: main
	./main > dsl.h

main: main.hs generators.hs parse.hs
	ghc --make $^ -Wall

.PHONY: clean

clean:
	rm -f *.o *.hi main
