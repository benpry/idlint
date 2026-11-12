import random
import time

import pytest

from idlint import cli


@pytest.mark.slow
def test_50_mb_of_csv_across_100_files_in_under_10_seconds(repo, capsys):
    rng = random.Random(1)
    header = "ResponseId,RecordedDate,p,q1,q2,rt,condition,text,score,finished\n"
    body = "".join(
        f"R_{rng.getrandbits(60):015x},2026-03-{i % 28 + 1:02d} 10:{i % 60:02d}:{i % 60:02d},"
        f"{rng.random():.3f},{rng.randint(1, 7)},{rng.randint(1, 7)},{rng.randint(200, 9000)},"
        f"condition_{i % 4},The quick brown fox jumps over the lazy dog,{rng.random() * 100:.2f},TRUE\n"
        for i in range(4200))
    for n in range(100):
        (repo / f"s{n:03d}.csv").write_text(header + body)
    assert sum(p.stat().st_size for p in repo.glob("*.csv")) >= 50_000_000

    start = time.perf_counter()
    code = cli.main(["scan"])
    elapsed = time.perf_counter() - start
    assert "No findings in 100 files." in capsys.readouterr().out
    assert code == 0
    assert elapsed < 10, f"scan took {elapsed:.1f}s"
