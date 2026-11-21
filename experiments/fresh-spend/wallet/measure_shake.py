"""Measure bulk SHAKE256 absorption and squeeze on public synthetic input."""
import hashlib
import time


def throughput(label, message, output_bytes, counted_bytes):
    trials = 32
    start = time.process_time()
    for _ in range(trials):
        hashlib.shake_256(message).digest(output_bytes)
    elapsed = time.process_time() - start
    print(f"{label} {counted_bytes * trials / elapsed:.2f}")


if __name__ == "__main__":
    size = 482_000
    throughput("shake256_absorb_B_per_cpu_s", bytes(size), 64, size)
    throughput("shake256_squeeze_B_per_cpu_s", bytes(64), size, size)
