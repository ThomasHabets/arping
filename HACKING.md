# Hacking on Arping

## Coding style

* C99 to retain portability for the widest range of platforms
* Approximately [Linux kernel coding style][1], except:
  * Line break before function name, in function definitions.
  * Curly braces are mandatory.
  * Place `*` next to the type, not the name. E.g. `char* p`

Don't make style-only changes, but fix the style on the line you're touching anyway.

[1]: https://github.com/torvalds/linux/blob/master/Documentation/process/coding-style.rst

## Make release
1. Up version in configure.ac. Commit.
2. Run `./extra/mktarball HEAD`
3. Test that tarball.
4. Check `git log --reverse arping-2.oldversion..HEAD` for notable changes.
5. Create tag: `git tag -s arping-2.newversion`
6. Push to github: `git push --tags`
7. Make tarball: `./extra/mktarball arping-2.newversion`
8. Sign archive: `gpg -a -b arping-2.10.tar.gz`
9. Upload to http://www.habets.pp.se/synscan/files/
10. Update webpage.
11. Send email to synscan-announce@googlegroups.com

## Fuzzing

```shell
CC=/path/to/afl-gcc ./configure
make
/path/to/afl-fuzz -i fuzz/pingip/ -o fuzz/out/ ./src/fuzz_pingip
```
