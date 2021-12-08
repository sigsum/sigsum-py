**Title**: Update timestamp verification
**Date**: 2021-12-08

# Summary
Update the condition which is used to determine whether a tree head is fresh.

# Description
The current Sigsum API documentation specifies that a witness must not sign a
tree head if its timestamp is older than five minutes.  The current witness
implementation uses an older interval that was looser: +- 12 hours.
