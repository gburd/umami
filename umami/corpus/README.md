# Tokenizer fixtures

reference/structure.tsv and reference/legacy.tsv preserve the unomalycli output
captured in the project's first commit, 5fa3bcf.  They match that commit byte for
byte.  They document provenance, not compatibility requirements.  The legacy
tokenizer no longer exists in umami.

structure.tsv contains the independent detector's regression expectations.
Its starting point comes from release parent 900dd2a, which includes the October
changes to quoted-string tokenization.  Those expectations differ from the
original reference and must not replace it.  inputs.txt contains the shared
419 input lines.

## Reviewed changes for 0.2.0

Only three lines of the independent structure.tsv changed for this release:

* The numeric example now keeps 1,234,567 in one Number token, rather than
  splitting off its final group.
* The URL example now keeps each complete HTTP or HTTPS URL, including its
  query, in one Literal token.  Each URL contributes one dynamic parameter slot.
* The floats example treats 1,2,3,4 as four numbers separated by delimiters.
  Groups after a comma need exactly three digits to belong to one number.

Email addresses, host ports, and long hexadecimal identifiers have focused
unit and signature tests.  Their grouping rules don't change other corpus
renderings.  A Literal token can represent a dynamic parameter; its printed
numeric type alone doesn't determine its signature contribution.

Future changes must review mismatched inputs individually.  Do not regenerate
these expectations merely to make a test pass.
