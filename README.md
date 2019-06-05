# PowerShell Script Code Obfuscator on Python 3

NOTE: This project should be used for authorized testing or educational purposes only. 
You are free to copy, modify and reuse the source code at your own risk. 

### Features
- Completely delete all the comments in the input text:
  - Type 1 comments: "<# ... #>".
  - Type 2 comments: "# ... \n", except for cases when # is surrounded with " or '
  - Most cases with escape characters are handled, but more testing is needed.
- Replace the names of variables in input text with random stuff and return the result with a mapping table. 
