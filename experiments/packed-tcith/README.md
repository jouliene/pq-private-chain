# Funded packed TCitH evaluation

[Architecture decision](DECISION.md) · [Two funded encodings and private test setup](encoding/README.md) · [Protocol, calibration and resource model](model/README.md) · [Independent security review](review/REVIEW.md)

Run from the repository root on 64-bit Linux with Python 3.11+, Bash, curl, tar, sha256sum, GNU time, a C++17 compiler with unsigned 128-bit support, and OpenSSL 3 headers and libcrypto. The compact public reproduction rebuilds the funded shape, checks a public authenticated path and controls, reconstructs the packet and archive costs, checks both mathematical exclusion bounds, runs the miniature protocol and times the full-size commitment/degree component. It takes a few minutes and downloads the two pinned public inputs. Private-wallet reproduction on disposable funds has its own instructions and toolchain. [Public entry point](reproduce.sh) · [Fresh private-wallet procedure](encoding/README.md)

```sh
bash experiments/packed-tcith/reproduce.sh
```

The model reports selected parameter geometries and also supplies exact, exhaustive certificates for the decisions about the smallest usable party domain. Regenerating the wider exploratory grid requires NumPy 1.26.4 and SciPy 1.11.4. From the experiment directory use the following command. The default public reproduction checks the decision without those libraries. [Exact certificates](model/certify.py) · [Wider sweep](model/search.py)

```sh
python3 -B model/results.py | cmp - model/RESULTS.json
```
