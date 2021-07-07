# -*- coding: utf-8 -*-
import re
import sys
from pprint import pprint
import multiprocessing
from functools import partial
from pathlib import Path
import mimetypes

TOTAL_WORKERS = 7
PATTERNS_MAP = {
    "crypto": re.compile("(aes|rsa|dsa|des|cbc|ecb|hmac|gcm|privatekey|publickey|md5|sha1|sha256|cipher|crypto|encrypt|decrypt|digest)", re.IGNORECASE),
    "auth": re.compile("(privilege|permissions|capability|role|rbac|policy|authorization|auth|claims|access|login|register|registration|logout)", re.IGNORECASE),
    "code smells": re.compile("(goto|todo|fixme|issue|temporary fix|temporary hack|workaround|be careful|sensitive|legacy|raw|dangerous|insecure|unsafe)", re.IGNORECASE),
    "execs": re.compile("(eval|run|exec|process|system|popen|spawn|dup2)", re.IGNORECASE),
    "jwt": re.compile("(jwt|jks|jwk|jku)", re.IGNORECASE),
    "parsers": re.compile("(parse|open|request|validate|verify)", re.IGNORECASE),
    "secrets": re.compile("(password|private|token|secret|key|authorization|bearer|auth|chave|senha)", re.IGNORECASE),
    "secrets typo": re.compile("(pasword|passsword)", re.IGNORECASE),
    "serialization": re.compile("(pickle|yaml|serialize|marshal|objectinput)", re.IGNORECASE),
    "swear words": re.compile("(fuck|shit|stupid|dumb)", re.IGNORECASE),
    "xml": re.compile("(xml|xerces|sax|etree|xpath|documentbuilder)", re.IGNORECASE),
}


def is_plain_text(file) -> bool:
    return "text/plain" in mimetypes.guess_type(file if isinstance(file, str) else str(file))


def search_file(file, patterns):
    if not is_plain_text(file):
        return None

    line_num = 0
    try:
        file_findings = []
        for line in open(file, "r", encoding="utf-8"):
            line_num += 1
            for pattern_type, pattern in patterns.items():
                if not pattern.search(line):
                    continue

                file_findings.append({
                    "line_num": line_num,
                    "line": line,
                    "pattern_type": pattern_type
                })
        if len(file_findings) == 0:
            return None

        return {
            "file": file,
            "found": file_findings
        }
    except PermissionError:
        print(f"PERMISSION DENIED: {file}")

    except UnicodeDecodeError:
        print(f"NOT A TEXT FILE: {file}")

    return None


def main(args):
    print("Allocating workers...")
    with multiprocessing.Pool(TOTAL_WORKERS) as pool:
        for arg in args:
            path_arg = Path(arg)
            print(f"Working on: {arg}")
            results = pool.map(partial(search_file, patterns=PATTERNS_MAP), path_arg.glob("**/*"))

            print(f"############# Results for: {arg} #############")
            pprint([r for r in results if r is not None])

    print("All done!")


if __name__ == '__main__':
    main(sys.argv[1:])
