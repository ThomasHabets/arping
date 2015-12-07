# Hacking on Arping

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
