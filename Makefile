
# Can not longer just use rustc to build the project since we have
# external dependencies (sha2 crate). cargo downloads the dependencies
# and builds it for the target platform.
target/debug/fat32: src/main.rs
	cargo build

# Mount the disk image, e.g., for manual inspection.
.PHONY: mount
mount:
	# hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount 128M
	hdiutil attach -imagekey diskimage-class=CRawDiskImage test.img
	# diskutil eraseDisk FAT32 NAME MBRFormat /dev/disk3

# Unmount the disk image.
.PHONY: unmount
unmount:
	hdiutil unmount /Volumes/NAME

# This is just to document some Makefile weirdness I came across.
# 
# The following rule probably does not do what you expect it to
# do. The final line - echo $(shell cat /tmp/a) - produces the same
# output as the very first line - cat /tmp/a, even though the 2nd line
# - date > /tmp/a - writes new data to /tmp/a. Not sure what is going
# on here.
.PHONY: blah
blah:
	cat /tmp/a
	date > /tmp/a
	echo $(shell date)
	echo $(shell sleep 3)
	echo $(shell date)
	echo $(shell cat /tmp/a)

# Create a disk image for testing. Assumes OSX as the platform.
test.img:
	dd if=/dev/zero of=$@ bs=1m count=128
	DEV=`hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount $@` && \
	diskutil eraseDisk FAT32 NAME MBRFormat $$DEV && \
	hdiutil mount $$DEV
	python3 ./fsck.py /Volumes/NAME
	hdiutil detach /Volumes/NAME

# Execute the Rust binary to test the implementation.
.PHONY: check
check: target/debug/fat32 test.img
	$^

.PHONY: clean
clean:
	$(RM) devnode

.PHONY: distclean
distclean: clean
	$(RM) test.img
