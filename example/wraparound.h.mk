export DT_BOOTSTRAP_RELA := 0x6ffffa01
export DT_BOOTSTRAP_RELASZ := 0x6ffffa02
export DT_BOOTSTRAP_RELAENT := 0x6ffffa03
export DT_BOOTSTRAP_REL := 0x6ffffa04
export DT_BOOTSTRAP_RELSZ := 0x6ffffa05
export DT_BOOTSTRAP_RELENT := 0x6ffffa06
wraparound.h:
	( printf '#ifndef WRAPAROUND_H_\n#define WRAPAROUND_H_\n'; \
	 for v in DT_BOOTSTRAP_RELA DT_BOOTSTRAP_RELASZ DT_BOOTSTRAP_RELAENT \
              DT_BOOTSTRAP_REL  DT_BOOTSTRAP_RELSZ  DT_BOOTSTRAP_RELENT; do \
	   printf "#define $$v "; eval printf $$"$${v}\\\n"; done; printf '#endif\n' ) > "$@" || (rm -f "$@"; false)
