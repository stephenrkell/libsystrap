structs.ml: main
	./main | indent > structs.ml

main: main.hs generator.hs parser.hs
	ghc --make $^ -Wall

.PHONY: clean
clean:
	rm -f *.o *.hi main
