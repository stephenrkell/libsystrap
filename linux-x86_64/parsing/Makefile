all: main
	./main

main: main.hs generators.hs parse.hs
	ghc --make $^

.PHONY: clean

clean:
	rm -f *.o *.hi main
