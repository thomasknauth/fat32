#!/usr/bin/env python3

# Generate test cases to test FAT implementation.
#
# Generates a file tree. The content of each file is hashed in its
# file name. The name of a directory is the hash of all its children.

# TODO Implement the part where the directory name is a hash of all its children.

import hashlib
import os
import random
import sys

def print_usage():
    print("./fsck.py [path]")

## Compute hash of a file `name`.
## @return Hash as a string.
def hash_file(name):
    sha = hashlib.sha256()
    with open(name, 'rb') as file:
        data = file.read(512)
        while data != b'':
            sha.update(data)
            data = file.read(512)
    return sha.hexdigest()

### @args p path
### @args n level (>= 0)
### @return null
def f(p, n):
    if n != 0:
        for i in range(random.randint(0, 10)):
            name = p + "/" + str(i)
            os.mkdir(name)
            xs = f(name, n-1)
    else:
        for i in range(random.randint(0, 10)):
            name = p + "/" + str(i)
            with open(name, "wb") as file:
                command = 'dd if=/dev/urandom of=%s count=%d'
                count = random.randint(1,10)
                os.system(command % (name, count))
            hash = hash_file(name)
            # Security-wise, truncating the hash is insecure. We use
            # the hash to detect problems in our FAT implemntation, so
            # it should be ok to truncate.
            truncated_hash = hash[0:8]
            newname = p + '/' + truncated_hash
            os.rename(name, newname)

def main():
    path = '.'
    if len(sys.argv) >= 2:
        path = sys.argv[1]
    f(path, 1)

if __name__ == '__main__':
    main()
