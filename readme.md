# GREP PY
This script will search text files recursively and try to find keywords usually associated 
with sensitive information or possible security breaches (like eval in Python).

Nothing fancy, super efficient or that useful. I just needed a reason to play around with multiprocessing.

## How to use
```shell
python grep_py.py <path to check 1> <path to check 2> <path to check 3> ... <path to check n>
```
Note: Paths containing spaces should be wrapped in quotes.