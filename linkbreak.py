#!/usr/bin/env python3
"""
Linkbreak - URL expander and link tracer
Part of Templar Studios | GPL v3.0

Expands shortened URLs and traces the full redirect chain.
Shows every hop, the final destination, and safety info.

Works fully in ish, a-shell, linux, macOS.

Usage:
  linkbreak.py expand <url>              expand a shortened link
  linkbreak.py trace <url>               show full redirect chain
  linkbreak.py batch <file>              expand multiple links from file
  linkbreak.py check <url>               expand and show safety info
"""

import sys
import os
import re
import json
import argparse
import time
from typing import List, Tuple, Dict, Optional
from urllib import request, error
from urllib.parse import urlparse

USER_AGENT = "Linkbreak/1.0 (Templar Studios Open Source)"
TIMEOUT = 15
MAX_REDIRECTS = 20

# known link shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "shorturl.at", "rb.gy", "cutt.ly", "rebrand.ly",
    "tiny.cc", "s.id", "surl.li", "v.gd", "qr.ae", "lnkd.in",
    "amzn.to", "ebay.to", "etsy.me", "fb.me", "wp.me", "youtu.be",
    "git.io", "t.ly", "short.io", "snip.ly", "tiny.cc", "v.gd",
    "lmgtfy.app", "tiny.one", "4ks.one", "soo.gd", "safelinking.net",
}

# suspicious tlds and patterns
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".click", ".download", ".bid", ".loan", ".work", ".date",
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "password", "banking", "paypal",
    "secure", "update", "confirm", "suspicious", "wallet", "gift",
    "free", "bonus", "winner", "prize", "urgent", "limited",
]


class RedirectHandler(request.HTTPRedirectHandler):
    """Track every redirect in the chain."""

    def __init__(self):
        self.redirect_chain = []
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_chain.append({
            "from": req.full_url,
            "to": newurl,
            "code": code,
        })
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def is_shortener(url: str) -> bool:
    """Check if the domain is a known link shortener."""
    domain = urlparse(url).netloc.lower()
    domain = domain.replace("www.", "")
    return domain in SHORTENERS or any(
        domain.endswith("." + s) for s in SHORTENERS
    )


def safety_check(final_url: str) -> List[str]:
    """Run basic safety heuristics on the final url."""
    warnings = []
    parsed = urlparse(final_url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            warnings.append(f"suspicious tld: {tld}")
            break

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain or keyword in path:
            warnings.append(f"suspicious keyword: '{keyword}'")
            break

    if parsed.scheme == "http":
        warnings.append("unencrypted connection (http, not https)")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        warnings.append("raw ip address used as domain")

    subdomain_count = domain.count(".")
    if subdomain_count > 3:
        warnings.append(f"deep subdomain nesting ({subdomain_count + 1} levels)")

    return warnings


def expand_url(url: str, verbose: bool = False) -> Dict:
    """
    Expand a url and return full info.
    """
    result = {
        "original": url,
        "final": url,
        "chain": [],
        "is_shortened": is_shortener(url),
        "warnings": [],
        "elapsed": 0,
    }

    handler = RedirectHandler()
    opener = request.build_opener(handler)
    opener.addheaders = [("User-Agent", USER_AGENT)]

    start = time.time()

    try:
        req = request.Request(url, headers={"User-Agent": USER_AGENT})
        response = opener.open(req, timeout=TIMEOUT)
        result["final"] = response.geturl()

        if handler.redirect_chain:
            result["chain"] = handler.redirect_chain
        else:
            result["chain"] = [{"from": url, "to": response.geturl(), "code": 200}]

        response.close()
    except error.HTTPError as e:
        result["final"] = e.geturl() if e.geturl() else url
        result["chain"] = handler.redirect_chain
        if not result["chain"]:
            result["chain"] = [{"from": url, "to": str(e), "code": e.code}]
    except error.URLError as e:
        result["final"] = url
        result["error"] = str(e.reason)
    except TimeoutError:
        result["error"] = "request timed out"
    except Exception as e:
        result["error"] = str(e)

    result["elapsed"] = time.time() - start
    result["warnings"] = safety_check(result["final"])

    return result


def print_result(result: Dict, show_chain: bool = True) -> None:
    """Print expansion result cleanly."""
    print()
    print("=" * 70)
    print("LINKBREAK — URL Analysis")
    print("=" * 70)

    print(f"original:       {result['original']}")
    if result.get("error"):
        print(f"status:         ERROR: {result['error']}")
        print("=" * 70)
        print()
        return

    print(f"final:          {result['final']}")
    print(f"shortened:      {'yes' if result['is_shortened'] else 'no'}")

    if show_chain and len(result["chain"]) > 0:
        print()
        print("redirect chain:")
        print("-" * 70)
        for i, hop in enumerate(result["chain"], 1):
            print(f"  {i}. {hop['from']}")
            print(f"     → [{hop['code']}] {hop['to']}")
            if i < len(result["chain"]):
                print()

    if result["warnings"]:
        print()
        print("safety warnings:")
        print("-" * 70)
        for warning in result["warnings"]:
            print(f"  [!] {warning}")
    else:
        print()
        print("safety:         no warnings detected")

    print(f"elapsed:        {result['elapsed']:.2f}s")
    print("=" * 70)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="linkbreak",
        description="Linkbreak - url expander by Templar Studios",
    )
    subparsers = parser.add_subparsers(dest="command", help="available commands")

    expand_parser = subparsers.add_parser("expand", help="expand a single url")
    expand_parser.add_argument("url", help="url to expand")
    expand_parser.add_argument("-v", "--verbose", action="store_true",
                               help="show full redirect chain")

    trace_parser = subparsers.add_parser("trace", help="show full redirect chain")
    trace_parser.add_argument("url", help="url to trace")

    check_parser = subparsers.add_parser("check", help="expand and check safety")
    check_parser.add_argument("url", help="url to check")

    batch_parser = subparsers.add_parser("batch", help="expand multiple urls from file")
    batch_parser.add_argument("file", help="file with one url per line")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "expand":
        result = expand_url(args.url, args.verbose)
        print_result(result, show_chain=args.verbose)

    elif args.command == "trace":
        result = expand_url(args.url, True)
        print_result(result, show_chain=True)

    elif args.command == "check":
        result = expand_url(args.url, True)
        print_result(result, show_chain=True)

    elif args.command == "batch":
        try:
            with open(args.file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"[!] could not read file: {e}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] expanding {len(urls)} links...")
        for url in urls:
            result = expand_url(url, False)
            print_result(result, show_chain=False)


if __name__ == "__main__":
    main()