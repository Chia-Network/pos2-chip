# This script will add a POS2_ prefix to all public FSE_ functions.
# It's unfortunate, but since rust links everything statically, there's no
# isolation between different C libraries. the zstd rust crate also build libfse
# and makes these symbols available in the top-level link step, causing multiple
# definitions of these symbols. This is a hack to version the ones we use, and
# avoid name clashes with any other crate.
import re

symbols = set()

c_types = ["unsigned", "int", "char", "size_t", "const", "char*", "void", "FSE_CTable*", "FSE_DTable*"]

sumbol_headers = ["fse.h", "huf.h"]

for file in sumbol_headers:
    with open("lib/fse/fse/" + file) as f:

        for line in f:
            l = line.split()
            if len(l) == 0:
                continue
            if line[0] == " ":
                continue
            if l[0] == "FSE_PUBLIC_API":
                l.pop(0)
            elif l[0] == "HUF_PUBLIC_API":
                l.pop(0)
            if l[0] not in c_types:
                continue
            l.pop(0)
            while l[0] in c_types:
                l.pop(0)

            name = l[0].split("(", 1)[0]
            if name.startswith("POS2_"):
                continue
            print(name)
            symbols.add(name)

def replace(filename: str) -> None:
    with open(filename, "r") as f:
        content = f.read()

    for s in symbols:
        content = re.sub(s + "\\b", "POS2_" + s, content)

    with open(filename, "w") as f:
        f.write(content)

source_files = [
    "entropy_common.c",
    "fse_compress.c",
    "fse_decompress.c",
    "fseU16.c",
    "huf_compress.c",
    "huf_decompress.c",
    "hist.c",
    "compiler.h",
    "debug.h",
    "error_private.h",
    "error_public.h",
    "fse.h",
    "fseU16.h",
    "hist.h",
    "huf.h",
    "mem.h",
]

for s in source_files:
    replace("lib/fse/fse/" + s)
