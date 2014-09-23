all: main

gen: main
	./main > headers.ml

main: main.hs generator.hs parser.hs
	ghc --make $^ -Wall

.PHONY: clean
clean:
	rm -f *.o *.hi main
