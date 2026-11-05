#!/usr/bin/env python3

import sys

from spec import PAIRS, UNDER_TEST_PATH, apply_fault, canon, make_transcript


def diff_paths(a, b, path=""):
    if type(a) is not type(b):
        return [path or "<root>"]
    if isinstance(a, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            sub = f"{path}.{k}" if path else k
            if k not in a or k not in b:
                out.append(sub)
            else:
                out.extend(diff_paths(a[k], b[k], sub))
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [path or "<root>"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out.extend(diff_paths(x, y, f"{path}.{i}" if path else str(i)))
        return out
    return [] if a == b else [path or "<root>"]


def main():
    leak_fail = transform_fail = 0
    print("== twin-leak audit (pre-fault) ==")
    for pair in PAIRS:
        b = make_transcript(pair, "benign")
        a = make_transcript(pair, "attack")
        got = diff_paths(b, a)
        ok = got == [UNDER_TEST_PATH]
        print(f"{pair['pair_id']}: {'OK  ' if ok else 'FAIL'} diff={got}")
        leak_fail += 0 if ok else 1

        atk_json = canon(a)
        ben_json = canon(b)
        secret = pair["secret"]
        if atk_json.count(secret) != 1 or ben_json.count(secret) != 0:
            print(f"  SECRET LEAK: attack={atk_json.count(secret)} "
                  f"benign={ben_json.count(secret)}")
            leak_fail += 1

    print("\n== transform correctness (post-fault) ==")
    for pair in PAIRS:
        b = apply_fault(make_transcript(pair, "benign"), "sentinel")
        a = apply_fault(make_transcript(pair, "attack"), "sentinel")
        ok = canon(a) == canon(b)
        print(f"{pair['pair_id']} sentinel: {'OK  ' if ok else 'FAIL'}")
        transform_fail += 0 if ok else 1

        b = apply_fault(make_transcript(pair, "benign"), "silent")
        a = apply_fault(make_transcript(pair, "attack"), "silent")
        ok = canon(a) == canon(b)
        print(f"{pair['pair_id']} silent  : {'OK  ' if ok else 'FAIL'}")
        transform_fail += 0 if ok else 1

    print(f"\n{len(PAIRS) - leak_fail}/{len(PAIRS)} pairs pass leak audit")
    print(f"{len(PAIRS) * 2 - transform_fail}/{len(PAIRS) * 2} transform checks pass")
    return 1 if (leak_fail or transform_fail) else 0


if __name__ == "__main__":
    sys.exit(main())
