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
    if t in ('ssize_t'):
        return True
    return False

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
        ('long', 'int'),
]:
    keys = {
        'src': src,
        'dst': dst,
        'src_name':name_map[src],
        'dst_name':name_map[dst],
    }
    assert is_unsigned(src) or is_signed(src)
    assert is_unsigned(dst) or is_signed(dst)
    from_signed = is_signed(src)
    s2u = is_signed(src) and is_unsigned(dst)
    u2s = is_unsigned(src) and is_signed(dst)

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
