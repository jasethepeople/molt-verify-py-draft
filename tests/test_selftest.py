from molt_verify.generate import generate_all
from molt_verify.selftest import run_selftest


def test_corpus(tmp_path):
    generate_all(tmp_path)
    assert run_selftest(tmp_path) == []
