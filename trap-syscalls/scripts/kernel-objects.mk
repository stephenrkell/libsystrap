LINUX_ZIMAGE ?= /boot/vmlinuz-$(shell uname -r)
LINUX_IMAGE ?= vmlinux
LINUX_IMAGE_DWARF ?= /usr/lib/debug/$(shell echo $(LINUX_ZIMAGE) | sed 's/vmlinuz/vmlinux/' )
DWARFHPP ?= dwarfhpp

$(LINUX_IMAGE): $(LINUX_ZIMAGE)
	start_row="$$( od -t x1 -A d "$<" | grep "1f 8b 08" | head -n1 )"; \
	octal_row_off="$$( echo "$$start_row" | tr -s '[:blank:]' '\t' | cut -f1 )"; \
	octal_char_off="$$( echo "$$start_row" | sed 's/1f 8b 08.*//' | wc -c )"; \
	octal_byte_off="$$( expr $$( expr $$octal_char_off - 8 ) / 3 )"; \
	echo "octal_row_off is $$octal_row_off" 1>&2; \
	echo "octal_byte_off is $$octal_byte_off" 1>&2; \
	dd if="$<" bs=1 skip=$$( expr $$octal_row_off + $$octal_byte_off ) | ( gunzip > "$@" || true )
	test -s "$@" || rm -f "$@"

linux-syscalls.list: $(LINUX_IMAGE)
	strings "$<" | grep '^sys_' | grep -v 'sys_\(enter\|exit\)_' | sort | uniq

linux-syscalls.h: linux-syscalls.list $(LINUX_IMAGE_DWARF)
	$(DWARFHPP) $(LINUX_IMAGE_DWARF) < linux-syscalls.list > "$@"
