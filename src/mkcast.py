#!/usr/bin/env python3

name_map = {
    'uint8_t': 'uint8',
    
    'int16_t': 'int16',
    'uint16_t': 'uint16',

    'uint32_t': 'uint32',

    'size_t': 'size',
    'ssize_t': 'ssize',

    'int': 'int',
    'unsigned int': 'uint',

    'long': 'long',
    'unsigned long': 'ulong',
}

max_map = {
    'int16_t': 32767,
    'uint16_t': 65535,
}

unsigned = set([
    'uint8_t',
    'uint16_t',
    'uint32_t',
    'size_t',
    'gid_t',
    'uid_t',
    'unsigned long',
    'unsigned int',
])

print("""
static void
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
]:
    keys = {
        'src': src,
        'dst': dst,
        'src_name':name_map[src],
        'dst_name':name_map[dst],
    }
    
    from_signed = not src in unsigned
    s2u = not src in unsigned and dst in unsigned
    u2s = src in unsigned and not dst in unsigned

    if from_signed:
        keys['errstr'] = '"cast_{src_name}_{dst_name}(%"PRIdMAX"): %s", (intmax_t)from'.format(**keys)
    else:
        keys['errstr'] = '"cast_{src_name}_{dst_name}(%"PRIuMAX"): %s", (uintmax_t)from'.format(**keys)
    
    print("""
static {dst}
cast_{src_name}_{dst_name}({src} from, const char* fmt, ...)
{{
    va_list ap;
    va_start(ap, fmt);
""".format(**keys))

    if s2u:
        print('    cast_assert(from >= 0, {errstr}, "need >= 0");'.format(**keys));

    print("    const {dst} to = ({dst})from;".format(**keys))

    if u2s:
        print('    cast_assert(to >= 0, {errstr}, "wrapped after casting");'.format(**keys));

    print("""    if (from != ({src})to) {{
        fprintf(stderr, "arping: ");
        if (fmt) {{
          vfprintf(stderr, fmt, ap);
        }} else {{
          fprintf(stderr, {errstr}, "roundtrip failed\\n");
        }}
        fprintf(stderr, "\\n");
        exit(1);
    }}
    va_end(ap);
    return to;
}}""".format(**keys))
