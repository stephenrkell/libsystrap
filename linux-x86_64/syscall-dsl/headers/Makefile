headers.ml: main
	./main | indent > headers.ml

main: main.hs generator.hs parser.hs
	ghc --make $^ -Wall

.PHONY: clean
clean:
	rm -f *.o *.hi main
