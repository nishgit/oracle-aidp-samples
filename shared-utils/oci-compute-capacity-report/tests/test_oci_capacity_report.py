# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v1.0 as shown at
# https://oss.oracle.com/licenses/upl/
"""Offline tests for oci_capacity_report.py — the OCI CLI is fully mocked.

Run:  python3 -m pytest tests/
"""
import importlib.util
import json
import pathlib

import pytest

_SRC = pathlib.Path(__file__).resolve().parents[1] / "oci_capacity_report.py"
_spec = importlib.util.spec_from_file_location("ocr", _SRC)
ocr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ocr)

AD1, AD2 = "xxxx:EXAMPLE-AD-1", "xxxx:EXAMPLE-AD-2"


def flex(shape, arch, min_oc=1, max_oc=64, min_mem=1, max_mem=1024, min_per=1, max_per=64):
    return {"shape": shape, "arch": arch, "flexible": True, "proc": "", "ocpus": None,
            "mem": None, "min_oc": min_oc, "max_oc": max_oc, "min_mem": min_mem,
            "max_mem": max_mem, "min_per_oc": min_per, "max_per_oc": max_per}


def report(*rows):
    """A capacity-report response body. rows: (shape, status, count-or-None)."""
    return {"data": {"shape-availabilities": [
        {"instance-shape": s, "availability-status": st,
         **({"available-count": c} if c is not None else {})} for s, st, c in rows]}}


class FakeOCI:
    """Stands in for ocr._oci. `answers[(ad, shape)]` = (status, count) or an
    exception string (the CLI error text) for that shape."""

    def __init__(self, answers, fail_batches_containing=()):
        self.answers = answers
        self.fail_batches_containing = set(fail_batches_containing)
        self.calls = []

    def __call__(self, args, profile, region):
        assert args[:3] == ["compute", "compute-capacity-report", "create"]
        ad = args[args.index("--availability-domain") + 1]
        batch = json.loads(args[args.index("--shape-availabilities") + 1])
        shapes = [b["instanceShape"] for b in batch]
        self.calls.append((ad, shapes))
        assert len(shapes) == len(set(shapes)), "same shape twice in one batch"
        # Like the real API, one failing shape fails the WHOLE request.
        for s in shapes:
            ans = self.answers[(ad, s)]
            if isinstance(ans, str):
                if len(shapes) > 1 and s in self.fail_batches_containing:
                    return None, "InvalidParameter: one config in the batch is invalid"
                return None, ans
        return report(*[(s, *self.answers[(ad, s)]) for s in shapes]), None


# ---------------------------------------------------------------- fits()

def test_fits_flexible_limits():
    sh = flex("VM.Standard.A1.Flex", "ARM", max_oc=80, max_mem=512, max_per=64)
    assert ocr.fits(sh, 32, 256) == (True, "")
    assert ocr.fits(sh, 96, 512)[0] is False          # > max OCPU
    assert ocr.fits(sh, 8, 1024)[0] is False          # > max memory
    assert "GB/OCPU" in ocr.fits(sh, 1, 128)[1]       # > max memory per OCPU


def test_fits_fixed_shape_matches_exactly_only():
    sh = {**flex("VM.Standard.E4.Fixed", "AMD"), "flexible": False, "ocpus": 8, "mem": 128}
    assert ocr.fits(sh, 8, 128) == (True, "")
    assert ocr.fits(sh, 8, 64)[0] is False


def test_fits_missing_metadata_never_guesses():
    sh = flex("VM.X.Flex", "AMD", min_oc=None, max_oc=None)
    assert ocr.fits(sh, 4, 64) == (False, "no OCPU metadata")


# ---------------------------------------------------------------- _parse()

def test_parse_statuses():
    batch = [("A", 8, 64, True), ("B", 8, 64, True), ("C", 8, 64, True),
             ("D", 8, 64, True), ("E", 8, 64, True)]
    data = report(("A", "AVAILABLE", 12), ("B", "AVAILABLE", None),
                  ("C", "OUT_OF_HOST_CAPACITY", None), ("D", "HARDWARE_NOT_SUPPORTED", None))
    out = ocr._parse(batch, data)
    assert out[("A", 8, 64)] == {"status": "AVAILABLE", "count": 12, "error": None}
    assert out[("B", 8, 64)]["status"] == ocr.NO_COUNT and out[("B", 8, 64)]["count"] is None
    assert out[("C", 8, 64)]["count"] == 0
    assert out[("D", 8, 64)]["status"] == "HARDWARE_NOT_SUPPORTED"
    assert out[("E", 8, 64)]["status"] == "MISSING_FROM_RESPONSE"


def test_parse_duplicate_rows_are_ambiguous():
    data = report(("A", "AVAILABLE", 1), ("A", "AVAILABLE", 2))
    assert ocr._parse([("A", 1, 8, True)], data)[("A", 1, 8)]["status"] == "AMBIGUOUS"


# ---------------------------------------------------------------- probe()

def test_probe_isolates_invalid_config_and_keeps_others(monkeypatch):
    fake = FakeOCI({(AD1, "A"): ("AVAILABLE", 5), (AD1, "B"): "InvalidParameter: bad config",
                    (AD1, "C"): ("AVAILABLE", 7)}, fail_batches_containing={"B"})
    monkeypatch.setattr(ocr, "_oci", fake)
    res = ocr.probe("p", "r", "t", AD1, [("A", 8, 64, True), ("B", 8, 64, True), ("C", 8, 64, True)])
    assert res[("A", 8, 64)]["count"] == 5
    assert res[("C", 8, 64)]["count"] == 7
    assert res[("B", 8, 64)]["status"] == "INVALID_CONFIG"


def test_probe_other_failure_is_request_failed(monkeypatch):
    fake = FakeOCI({(AD1, "A"): "ServiceError: 500 internal"})
    monkeypatch.setattr(ocr, "_oci", fake)
    res = ocr.probe("p", "r", "t", AD1, [("A", 8, 64, True)])
    assert res[("A", 8, 64)]["status"] == "REQUEST_FAILED"


def test_probe_respects_batch_size(monkeypatch):
    answers = {(AD1, s): ("AVAILABLE", 1) for s in "ABCDE"}
    fake = FakeOCI(answers)
    monkeypatch.setattr(ocr, "_oci", fake)
    ocr.probe("p", "r", "t", AD1, [(s, 1, 8, True) for s in "ABCDE"], batch_size=2)
    assert [len(shapes) for _ad, shapes in fake.calls] == [2, 2, 1]


def test_cli_timeout_becomes_request_failed(monkeypatch):
    def boom(*a, **k):
        raise ocr.subprocess.TimeoutExpired(cmd="oci", timeout=1)
    monkeypatch.setattr(ocr.subprocess, "run", boom)
    data, err = ocr._oci(["compute", "x"], "p", "r")
    assert data is None and "timed out" in err


# ---------------------------------------------------------------- sweep / fit check

SHAPES = {AD1: [flex("VM.Standard.A1.Flex", "ARM"), flex("VM.Standard.E5.Flex", "AMD")],
          AD2: [flex("VM.Standard.A1.Flex", "ARM"), flex("VM.Standard.E5.Flex", "AMD")]}


def _run_sweep(monkeypatch, capsys, answers):
    monkeypatch.setattr(ocr, "_oci", FakeOCI(answers))
    code = ocr.sweep("p", "r", "t", [AD1, AD2], SHAPES, {"ARM": 8, "AMD": 16}, [8], False)
    return code, capsys.readouterr().out


def test_sweep_all_counts_exit_0(monkeypatch, capsys):
    ans = {(ad, s): ("AVAILABLE", 10) for ad in (AD1, AD2)
           for s in ("VM.Standard.A1.Flex", "VM.Standard.E5.Flex")}
    code, out = _run_sweep(monkeypatch, capsys, ans)
    assert code == 0
    assert "20   (AD-1=10, AD-2=10)" in out
    assert "Limitations:" in out and "NO COUNT" not in out


def test_sweep_hidden_counts_are_flagged_not_guessed(monkeypatch, capsys):
    ans = {(ad, s): ("AVAILABLE", None) for ad in (AD1, AD2)
           for s in ("VM.Standard.A1.Flex", "VM.Standard.E5.Flex")}
    ans[(AD1, "VM.Standard.E5.Flex")] = ("AVAILABLE", 4)
    code, out = _run_sweep(monkeypatch, capsys, ans)
    assert code == 3
    assert f"avail{ocr.DAGGER}" in out                 # ARM: no counts at all
    assert f"4+{ocr.DAGGER}" in out                    # AMD: partial count = lower bound
    assert "external customer tenancies may" in out
    assert "INCOMPLETE" not in out


def test_sweep_failure_is_incomplete_exit_2(monkeypatch, capsys):
    ans = {(ad, s): ("AVAILABLE", 1) for ad in (AD1, AD2)
           for s in ("VM.Standard.A1.Flex", "VM.Standard.E5.Flex")}
    ans[(AD2, "VM.Standard.A1.Flex")] = "ServiceError: 500"
    code, out = _run_sweep(monkeypatch, capsys, ans)
    assert code == 2 and "INCOMPLETE" in out


def test_fit_check_reports_hidden_count(monkeypatch, capsys):
    ans = {(AD1, "VM.Standard.A1.Flex"): ("AVAILABLE", None),
           (AD1, "VM.Standard.E5.Flex"): ("OUT_OF_HOST_CAPACITY", None)}
    monkeypatch.setattr(ocr, "_oci", FakeOCI(ans))
    code = ocr.fit_check("p", "r", "t", [AD1], {AD1: SHAPES[AD1]}, 8, 64)
    out = capsys.readouterr().out
    assert code == 3
    assert f"not returned{ocr.DAGGER}" in out
    assert "ARM 16 vCPU" in out or "AMD 16 vCPU" in out


# ---------------------------------------------------------------- config

def test_region_defaults_to_profile(monkeypatch, tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text("[DEFAULT]\ntenancy=ocid1.tenancy.oc1..example\nregion=us-ashburn-1\n")
    monkeypatch.setenv("OCI_CLI_CONFIG_FILE", str(cfg))
    assert ocr._region_from_profile("DEFAULT") == "us-ashburn-1"
    assert ocr._tenancy_from_profile("DEFAULT") == "ocid1.tenancy.oc1..example"


def test_missing_region_is_a_setup_error(monkeypatch, tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text("[DEFAULT]\ntenancy=ocid1.tenancy.oc1..example\n")
    monkeypatch.setenv("OCI_CLI_CONFIG_FILE", str(cfg))
    with pytest.raises(SystemExit):
        ocr._region_from_profile("DEFAULT")
