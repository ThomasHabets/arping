#!/usr/bin/env python3

import os
import sys

name_map = {
    'uint8_t': 'uint8',
    
    'int16_t': 'int16',
    'uint16_t': 'uint16',

    'uint32_t': 'uint32',

    'gid_t': 'gid',

    'size_t': 'size',
    'ssize_t': 'ssize',

    'int': 'int',
    'unsigned int': 'uint',

    'long': 'long',
    'unsigned long': 'ulong',

    'long long': 'longlong',
    'unsigned long long': 'ulonglong',
}

def is_unsigned(t):
    if t[0] == 'u':
        return True
    if t in ('size_t', 'gid_t', 'uid_t'):
        return True
    return False

def is_signed(t):
    if t.startswith('int'):
        return True
    if t.startswith('long'):
        return True
    if t in ('ssize_t',):
        return True
    return False

def main():
    d = os.path.dirname(sys.argv[0])
    print(d)
    with open(os.path.join(d, 'cast.c'), 'w') as fc:
        with open(os.path.join(d, 'cast.h'), 'w') as fh:
            codegen(fc, fh)

def codegen(fc, fh):
    # TODO: #define uintmax_t if it doesn't exist
    genheader = """/*
 * GENERATED FILE, DO NOT EDIT. Generated by mkcast.py
 */
"""
    fh.write(genheader)
    fc.write(genheader)
    fh.write("""#include "config.h"
#include <inttypes.h>
#include <stddef.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
void cast_assert(int must, const char* fmt, ...);
""")
    fc.write("""
#include "cast.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
void
cast_assert(int must, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt); 
    if (!must) {
        fprintf(stderr, "arping: runtime check: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\\n");
        exit(1);
    }
    va_end(ap);
}
""")

    for src, dst in [
            # from, to
            ('int16_t', 'uint16_t'),
            #        ('uint16_t', 'int16_t'),
            ('ssize_t', 'size_t'),
            ('size_t', 'ssize_t'),
            ('size_t', 'uint16_t'),
            ('size_t', 'uint32_t'),
            ('unsigned long', 'unsigned int'),
            ('long', 'int16_t'),
            ('int16_t', 'uint8_t'),
            ('int', 'unsigned int'),
            ('int', 'uint16_t'),
            ('long', 'int'),
            ('unsigned long', 'gid_t'),
            ('long long', 'unsigned long long'),
            ('long long', 'unsigned int'),
            ('int', 'int16_t'),
    ]:
        keys = {
            'src': src,
            'dst': dst,
            'src_name':name_map[src],
            'dst_name':name_map[dst],
        }
        assert is_unsigned(src) ^ is_signed(src)
        assert is_unsigned(dst) ^ is_signed(dst)
        from_signed = is_signed(src)
        s2u = is_signed(src) and is_unsigned(dst)
        u2s = is_unsigned(src) and is_signed(dst)

        if from_signed:
            keys['errstr'] = '"cast_{src_name}_{dst_name}(%"PRIdMAX"): %s", (intmax_t)from'.format(**keys)
        else:
            keys['errstr'] = '"cast_{src_name}_{dst_name}(%"PRIuMAX"): %s", (uintmax_t)from'.format(**keys)

        fh.write("{dst} cast_{src_name}_{dst_name}({src} from, const char* fmt, ...);\n".format(**keys))
        fc.write("""
{dst}
cast_{src_name}_{dst_name}({src} from, const char* fmt, ...)
{{
    va_list ap;
    va_start(ap, fmt);
""".format(**keys))

        if s2u:
            fc.write('    cast_assert(from >= 0, {errstr}, "need >= 0");'.format(**keys));

        fc.write("    const {dst} to = ({dst})from;".format(**keys))

        if u2s:
            fc.write('    cast_assert(to >= 0, {errstr}, "wrapped after casting");'.format(**keys));

        fc.write("""    if (from != ({src})to) {{
        fprintf(stderr, "arping: ");
        if (fmt) {{
          vfprintf(stderr, fmt, ap);
          fprintf(stderr, ": value won't fit in {dst}");
        }} else {{
          fprintf(stderr, {errstr}, "value won't fit in {dst}\\n");
        }}
        fprintf(stderr, "\\n");
        exit(1);
    }}
    va_end(ap);
    return to;
}}""".format(**keys))

if __name__ == '__main__':
    main()
