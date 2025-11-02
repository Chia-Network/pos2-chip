import argparse
import os
import random
import statistics
import sys
import time
import math
import fcntl

def disable_fs_cache(fd: int):
    """macOS: disable caching and read-ahead on this fd so reads go to disk."""
    # macOS-specific fcntl operations
    F_NOCACHE = 48     # do not cache data for this fd
    F_RDAHEAD = 45     # read-ahead hint (0 = disable)
    try:
        fcntl.fcntl(fd, F_NOCACHE, 1)
    except Exception as e:
        print(f"warning: failed to set F_NOCACHE: {e}", file=sys.stderr)
    try:
        fcntl.fcntl(fd, F_RDAHEAD, 0)
    except Exception as e:
        print(f"warning: failed to disable read-ahead: {e}", file=sys.stderr)


def ns_to_us(ns):
    return ns / 1000.0

def print_stats(name, durations_ns):
    if not durations_ns:
        print(f"{name}: no samples")
        return
    durs_us = [ns_to_us(d) for d in durations_ns]
    count = len(durs_us)
    mean = statistics.mean(durs_us)
    median = statistics.median(durs_us)
    minv = min(durs_us)
    maxv = max(durs_us)
    if count == 1:
        p95 = durs_us[0]
    else:
        sorted_d = sorted(durs_us)
        idx = min(count - 1, max(0, int(math.ceil(0.95 * count)) - 1))
        p95 = sorted_d[idx]
    total_ms = sum(durations_ns) / 1_000_000.0
    print(f"{name}: samples={count}, mean={mean:.2f}µs, median={median:.2f}µs, min={minv:.2f}µs, max={maxv:.2f}µs, p95≈{p95:.2f}µs, total={total_ms:.2f}ms")

def random_seeks(fd, filesize, count=64, block_size=8192):
    durations = []
    if filesize < block_size:
        raise ValueError("file smaller than block size")
    max_offset = filesize - block_size
    for _ in range(count):
        offset = random.randint(0, max_offset)
        t0 = time.perf_counter_ns()
        os.lseek(fd, offset, os.SEEK_SET)
        data = os.read(fd, block_size)
        t1 = time.perf_counter_ns()
        if len(data) < block_size:
            print(f"warning: short read {len(data)} bytes at offset {offset}", file=sys.stderr)
        durations.append(t1 - t0)
    return durations

def stride_sequence_seeks(fd, filesize, jumps=64, stride=65536, block_size=8192):
    durations = []
    required = block_size + jumps * stride
    if filesize < required:
        raise ValueError(f"file too small for stride pattern (need >= {required} bytes)")
    max_start = filesize - required
    start = random.randint(0, max_start)
    # initial read
    t0 = time.perf_counter_ns()
    os.lseek(fd, start, os.SEEK_SET)
    data = os.read(fd, block_size)
    t1 = time.perf_counter_ns()
    durations.append(t1 - t0)
    # perform jumps
    for i in range(1, jumps + 1):
        offset = start + i * stride
        t0 = time.perf_counter_ns()
        os.lseek(fd, offset, os.SEEK_SET)
        data = os.read(fd, block_size)
        t1 = time.perf_counter_ns()
        if len(data) < block_size:
            print(f"warning: short read {len(data)} bytes at offset {offset}", file=sys.stderr)
        durations.append(t1 - t0)
    return durations

def sequential_large_read(fd, filesize, total_bytes=64*8192):
    """Read one contiguous chunk of total_bytes (default: 64*8192) and time it."""
    if filesize < total_bytes:
        raise ValueError(f"file too small for sequential read (need >= {total_bytes} bytes)")
    max_start = filesize - total_bytes
    start = random.randint(0, max_start)
    t0 = time.perf_counter_ns()
    os.lseek(fd, start, os.SEEK_SET)
    data = os.read(fd, total_bytes)
    t1 = time.perf_counter_ns()
    if len(data) < total_bytes:
        print(f"warning: short sequential read {len(data)} bytes at offset {start}", file=sys.stderr)
    return [t1 - t0]

# New: grouped sequential scan of N chunks of scan_size bytes
def grouped_scan_sequential(fd, filesize, n, scan_size):
    """Do one lseek, then read n sequential chunks of scan_size bytes; return per-read durations."""
    total = n * scan_size
    if filesize < total:
        raise ValueError(f"file too small for grouped sequential read (need >= {total} bytes)")
    start = random.randint(0, filesize - total)
    durations = []
    # first read includes lseek time
    t0 = time.perf_counter_ns()
    os.lseek(fd, start, os.SEEK_SET)
    data = os.read(fd, scan_size)
    t1 = time.perf_counter_ns()
    if len(data) < scan_size:
        print(f"warning: short read {len(data)} bytes at offset {start}", file=sys.stderr)
    durations.append(t1 - t0)
    # subsequent sequential reads (no seeks)
    for _ in range(1, n):
        t0 = time.perf_counter_ns()
        data = os.read(fd, scan_size)
        t1 = time.perf_counter_ns()
        if len(data) < scan_size:
            print(f"warning: short read {len(data)} bytes during grouped scan", file=sys.stderr)
        durations.append(t1 - t0)
    return durations

# New: singles scan = N random seeks of scan_size bytes each
def singles_random_scan(fd, filesize, n, scan_size):
    return random_seeks(fd, filesize, count=n, block_size=scan_size)

def main():
    parser = argparse.ArgumentParser(description="Disk seek/read microbenchmarks")
    parser.add_argument("file", help="path to file to test")
    parser.add_argument("--N", "-n", help="number of plots in group (default 64)", type=int, default=64)
    parser.add_argument("--proof-fragment-scan-size", "-s", help="number of elements to scan in plot (default 8192)", type=int, default=8192)
    parser.add_argument("--no-cache", action="store_true",
                        help="Disable macOS file cache and read-ahead for the benchmark fd")
    parser.add_argument("--num-tests", "-t", help="number of test iterations to run (default 1)", type=int, default=1)
    args = parser.parse_args()

    # 2^28 / proof_fragment_scan_size
    number_of_entries_per_partition = 2**28 // 512
    scan_size = 4 * args.proof_fragment_scan_size  # bytes
    # ensure integer count of jumps across groups
    jumps_across_groups = max(1, number_of_entries_per_partition // args.proof_fragment_scan_size)
    jump_distance_bytes = args.N * scan_size
    # output to console
    print(f"Number of plots in group: {args.N}")
    print(f"Proof fragment scan size: {args.proof_fragment_scan_size} elements")
    print(f"Number of entries per partition: {number_of_entries_per_partition}")
    print(f"Calculated scan size: {scan_size} bytes")
    print(f"Jumps across groups: {jumps_across_groups}")
    print(f"Jump distance between groups: {jump_distance_bytes} bytes")


    # Benchmarks:
    # 1: grouped scan filter test, which reads N * scan_size bytes sequentially
    # 2: singles scan filter test, which does N random seeks and reads scan_size bytes each
    # 3: stride test, which does a random seek and reads scan size bytes, then (jumps_across_groups-1) seek jumps each with scan size bytes reads.
    # 4: large sequential read test, which does random seek and reads N * scan_size * jumps_across_groups bytes
    # 5: single sequential read test, which does random seek and reads scan_size * jumps_across_groups bytes
    
    path = args.file
    try:
        fd = os.open(path, os.O_RDONLY)
        if args.no_cache:
            disable_fs_cache(fd)
    except OSError as e:
        print(f"cannot open file: {e}", file=sys.stderr)
        sys.exit(2)
    try:
        filesize = os.fstat(fd).st_size
        print(f"file: {path}, size={filesize} bytes")
        # 1) Grouped scan: N sequential reads of scan_size
        try:
            grouped_durations = []
            for _ in range(args.num_tests):
                grouped_durations += grouped_scan_sequential(fd, filesize, args.N, scan_size)
            print_stats(f"Grouped scan: N={args.N}, chunk={scan_size}B", grouped_durations)
        except ValueError as e:
            print(f"skipping grouped scan: {e}", file=sys.stderr)

        # 2) Singles scan: N random seeks of scan_size
        try:
            singles_durations = []
            for _ in range(args.num_tests):
                singles_durations += singles_random_scan(fd, filesize, args.N, scan_size)
            print_stats(f"Singles scan: N random seeks, chunk={scan_size}B", singles_durations)
        except ValueError as e:
            print(f"skipping singles scan: {e}", file=sys.stderr)

        # 3) Stride test: 1 read + (jumps_across_groups-1) jumps of jump_distance_bytes
        try:
            stride_durations = []
            jumps = max(1, int(jumps_across_groups))  # total reads = jumps
            for _ in range(args.num_tests):
                stride_durations += stride_sequence_seeks(
                    fd,
                    filesize,
                    jumps=jumps - 1,               # function adds initial read, so jumps = total_reads - 1
                    stride=jump_distance_bytes,
                    block_size=scan_size,
                )
            print_stats(f"Stride scan: reads={jumps}, stride={jump_distance_bytes}B, chunk={scan_size}B", stride_durations)
        except ValueError as e:
            print(f"skipping stride scan: {e}", file=sys.stderr)

        # 4) Large sequential read: N * scan_size * jumps_across_groups bytes in one go
        try:
            large_seq_durations = []
            total_bytes_large = args.N * scan_size * int(jumps_across_groups)
            for _ in range(args.num_tests):
                large_seq_durations += sequential_large_read(fd, filesize, total_bytes=total_bytes_large)
            print_stats(f"Large sequential: {total_bytes_large}B", large_seq_durations)
        except ValueError as e:
            print(f"skipping large sequential read: {e}", file=sys.stderr)

        # 5) Single sequential read: scan_size * jumps_across_groups bytes in one go
        try:
            single_seq_durations = []
            total_bytes_single = scan_size * int(jumps_across_groups)
            for _ in range(args.num_tests):
                single_seq_durations += sequential_large_read(fd, filesize, total_bytes=total_bytes_single)
            print_stats(f"Single sequential: {total_bytes_single}B", single_seq_durations)
        except ValueError as e:
            print(f"skipping single sequential read: {e}", file=sys.stderr)

        # now summarize durations of each test, just output the final durations
        print("Final durations:")
        for label, durations in [
            ("Grouped scan", grouped_durations),
            ("Singles scan", singles_durations),
            ("Stride scan", stride_durations),
            ("Large sequential", large_seq_durations),
            ("Single sequential", single_seq_durations),
        ]:
            if durations:
                print(f"  {label}: {sum(durations) / len(durations):.2f} ns, time in ms: {sum(durations) / 1_000_000.0:.2f} ms")
        
        # the overall performance of grouped N vs singles is:
        # grouped performance = grouped_durations / N + stride_durations / 32
        # single performance = singles_durations / N + single_seq_durations / 32
        grouped_1st_seek_time_ms = sum(grouped_durations) / (1_000_000.0)
        grouped_large_seq_time_ms = sum(large_seq_durations) / (1_000_000.0)
        singles_1st_seek_time_ms = sum(singles_durations) / (1_000_000.0)
        singles_seq_time_ms = sum(single_seq_durations) / (1_000_000.0)
        print(f"Grouped scan first seek time per read: {grouped_1st_seek_time_ms:.2f} ms")
        print(f"Singles scan first seek time per read: {singles_1st_seek_time_ms:.2f} ms")
        print(f"Grouped large sequential read time: {grouped_large_seq_time_ms:.2f} ms")
        print(f"Singles sequential read time: {singles_seq_time_ms:.2f} ms")
        singles_total_average_time = singles_1st_seek_time_ms / args.N + singles_seq_time_ms / 32
        grouped_total_average_time = grouped_1st_seek_time_ms / args.N + grouped_large_seq_time_ms / 32
        print(f"Overall grouped average time: {grouped_total_average_time:.2f} ms")
        print(f"Overall singles average time: {singles_total_average_time:.2f} ms")
        if grouped_total_average_time > 0:
            speedup = singles_total_average_time / grouped_total_average_time
            print(f"Speedup (singles / grouped): {speedup:.2f}x")
        else:
            slowdown = grouped_total_average_time / singles_total_average_time
            print(f"Slowdown (grouped / singles): {slowdown:.2f}x")
        
         # overall performance calculation
         # note: only compute if we have all durations
    finally:
        os.close(fd)

if __name__ == "__main__":
    main()