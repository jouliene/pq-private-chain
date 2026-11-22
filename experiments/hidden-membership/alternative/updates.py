"""Exercise branch appends/rollback using only the public funded digest projection."""
from hashlib import shake_256


def transform(rows):
    k = max(0, (len(rows)-1).bit_length())
    table = rows + [0] * ((1<<k)-len(rows))
    for bit in range(k):
        for m in range(len(table)):
            if (m>>bit)&1:
                table[m] ^= table[m^(1<<bit)]
    return table


def change(coefficients, row_index, delta):
    # The coefficient m contains input value j exactly when j is a subset of m.
    # Enumerating only supersets updates the public ANF table in place.
    free = (len(coefficients)-1) ^ row_index
    sub = free
    while True:
        coefficients[row_index | sub] ^= delta
        if sub == 0:
            return
        sub = (sub-1) & free


def append(coefficients, count, row):
    if count == len(coefficients):
        coefficients += coefficients.copy()
    change(coefficients, count, row)


def pop(coefficients, count, old):
    change(coefficients, count-1, old)
    if count > 1 and count-1 == len(coefficients)//2:
        del coefficients[count-1:]


def test():
    rows, coeff = [], [0]
    def fork(branch, total):
        for i in range(len(rows), total):
            data = shake_256(branch + i.to_bytes(4, "little")).digest(64)
            row = int.from_bytes(data, "little")
            append(coeff, len(rows), row)
            rows.append(row)
            if coeff != transform(rows):
                raise AssertionError("append differs from a full replay")
    fork(b"public-test-branch-A", 130)
    a = list(coeff)
    for _ in range(100):
        pop(coeff, len(rows), rows[-1])
        rows.pop()
        if coeff != transform(rows):
            raise AssertionError("disconnect differs from a full replay")
    fork(b"public-test-branch-B", 130)
    if a == coeff:
        raise AssertionError("alternate branch unexpectedly retained old coefficients")
    print("verified each of 130 appends, 100 disconnects and 100 alternate appends against full replay")


if __name__ == "__main__":
    test()
