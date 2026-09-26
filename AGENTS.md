# Agent Notes

* One logical change per commit

## Intentional behavior

- `exit_on_drop_fail` is 0 intentionally for now. Don't point it out or change
  that.
- MAC ping accepts replies with sequence numbers other than the most recently
  sent.

## Commit messages

* Max 72 characters per line
* First line short description
* Further commit message elaborates on why with examples where possible

## Presubmits

NEVER skip presubmits. If the user does not have `sudo`, run pre-commit with
env `NO_SUDO=true`.
