import argparse
import fileinput
import re
import requests
import sys

edb_matcher = re.compile(r'\|\s*.*\/([0-9]+)\..*\s*$')
edb_page_verified = re.compile(r'<\s*i[^>]*class\s*=\s*"[^"]*mdi-check[^"]*"')  # Cthulhu awaits
edb_page_unverified = re.compile(r'<\s*i[^>]*class\s*=\s*"[^"]*mdi-close[^"]*"')
banner_matcher = re.compile(r'^([\-\s]+$|^\s*Exploit Title\s*\|\s*Path\s*$)')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filter", help="omit unverified exploits from output",
                    action="store_true")
    args = parser.parse_args()



    for line in sys.stdin:
        line = line.rstrip('\n')
        edb_key = parse_edb_number(line)
        if edb_key is None:
            continue
        resp = requests.get('https://www.exploit-db.com/exploits/{0}'.format(edb_key), headers = {'user-agent': 'curl/7.67.0'})  # firewall blocks default user agent but is OK with curl -- weird
        if edb_page_verified.search(resp.text):
            print("{0} VERIFIED".format(line))
        elif edb_page_unverified.search(resp.text):
            if args.filter:
                pass
            else:
                print("{0} UNVERIFIED".format(line))
        else:
            print("EDB Parse Error: Verification unknown", file=sys.stderr)
            print(resp.status_code, file=sys.stderr)
            print(resp.headers, file=sys.stderr)
            print(resp.text, file=sys.stderr)
        sys.stdout.flush()



def parse_edb_number(line):
    m = banner_matcher.match(line)
    if m:
        return None
    m = edb_matcher.search(line)
    if m:
        return m.group(1)
    else:
        print("error: Could not parse EDB input {0}".format(line), file=sys.stderr)



if __name__ == "__main__":
    main()
