#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v1.0 as shown at
# https://oss.oracle.com/licenses/upl/
"""OCI compute capacity — ARM + AMD launchable-nodes report for any OCI region.

Answers: "How many VM nodes of size S could OCI launch right now in region R,
for ARM (Ampere) and for AMD?" Useful when sizing Spark clusters for services
where the node shape matters, such as OCI Data Flow, OCI Compute, or Oracle AI
Data Platform clusters (ARM vs AMD).

Each number comes from OCI's CreateComputeCapacityReport API at one EXACT
(shape, OCPUs, memory) configuration. It is a best-effort, point-in-time
estimate of launchable instances for THAT configuration — not a hardware
inventory, not a reservation, and not a launch guarantee.

IMPORTANT — count visibility: depending on your tenancy's access level, OCI may
return only the availability status (AVAILABLE / OUT_OF_HOST_CAPACITY) without
a launchable count. External customer tenancies may therefore not see counts,
while Oracle-internal tenancies typically do. When a count is not returned the
report says so explicitly (marked with a dagger, "†") instead of guessing.

Region-generic: ADs, shape families and their limits are discovered at runtime.
Multi-AD regions are probed in EVERY AD and consolidated (region total, per-AD
in parentheses). --ad restricts to one AD.

Shape families come from ListShapes, so existing and future ARM/AMD families
are picked up automatically with no code change. Per-shape limits (min/max
OCPU, min/max memory, min/max memory per OCPU) also come from ListShapes.
Architecture is classified from the processor description ("Ampere" -> ARM,
"AMD" -> AMD). Only standard VM shapes are probed; GPU, bare-metal and
".Generic" placeholder shapes are skipped.

Modes
-----
Default — ratio sweep: for each OCPU size, probe at memory = size x ratio
  (defaults: ARM 1:8, AMD 1:16) and print launchable nodes per size.
--ocpus N --memory-gb M — fit check for one explicit configuration.
--show-shapes — list the discovered shapes and their limits.

Usage
-----
    python3 oci_capacity_report.py                        # profile's region
    python3 oci_capacity_report.py --region us-ashburn-1  # all ADs, consolidated
    python3 oci_capacity_report.py --region us-ashburn-1 --detail
    python3 oci_capacity_report.py --sizes 8,32 --arm-ratio 8 --amd-ratio 16
    python3 oci_capacity_report.py --ocpus 32 --memory-gb 512
    python3 oci_capacity_report.py --show-shapes

Exit codes
----------
  0  every probe returned a definite answer with a count
     (AVAILABLE with a count, OUT_OF_HOST_CAPACITY, or a rejected config)
  3  every probe returned a definite status, but OCI did not return a count
     for at least one AVAILABLE shape (totals are lower bounds)
  2  coverage incomplete: some probe failed, timed out, was missing or ambiguous
  1  setup error (config, auth, bad arguments)

Requirements
------------
- `oci` CLI on PATH (https://docs.oracle.com/iaas/Content/API/SDKDocs/cliinstall.htm)
- `~/.oci/config` (or $OCI_CLI_CONFIG_FILE) with the chosen profile
- IAM:  Allow group <your-group> to manage compute-capacity-reports in tenancy
        Allow group <your-group> to inspect instance-family in tenancy   (ListShapes)
"""
from __future__ import annotations

import argparse
import configparser
import json
import math
import os
import subprocess
import sys
from typing import Any

# Shape entries sent per capacity-report request. 3 is a conservative value
# that has worked in every tenancy we tested; the accepted maximum can vary by
# tenancy, so it is configurable (--batch-size).
DEFAULT_BATCH_SIZE = 3
CLI_TIMEOUT_S = 180                  # one OCI CLI call; a hang becomes REQUEST_FAILED
# OCI definition: 1 OCPU = 2 vCPU on x86 (AMD/Intel), 1 vCPU on Ampere ARM.
# ListShapes exposes no vCPU field, so this is applied per architecture.
VCPU_PER_OCPU = {"ARM": 1, "AMD": 2}
DEFAULT_SIZES = (1, 2, 4, 8, 16, 32, 64)

# Result statuses (OCI's availability-status values plus the script's own).
COUNTED = {"AVAILABLE", "OUT_OF_HOST_CAPACITY"}           # definite, with a count
NO_COUNT = "AVAILABLE_NO_COUNT"                           # definite, count not returned
NOT_PROBEABLE = {"INVALID_CONFIG", "HARDWARE_NOT_SUPPORTED"}  # definite, not launchable


# ---------------------------------------------------------------- config

def _config_path() -> str:
    return os.environ.get("OCI_CLI_CONFIG_FILE",
                          os.path.expanduser("~/.oci/config"))


def _profile_section(profile: str) -> configparser.SectionProxy:
    path = _config_path()
    if not os.path.exists(path):
        sys.exit(f"ERROR: OCI config not found: {path}")
    cfg = configparser.ConfigParser()
    cfg.read(path)
    if profile not in cfg:
        sys.exit(f"ERROR: profile [{profile}] not found in {path}")
    return cfg[profile]


def _tenancy_from_profile(profile: str) -> str:
    sec = _profile_section(profile)
    if "tenancy" not in sec:
        sys.exit(f"ERROR: profile [{profile}] has no `tenancy` entry in {_config_path()}")
    return sec["tenancy"]


def _region_from_profile(profile: str) -> str:
    sec = _profile_section(profile)
    if "region" not in sec:
        sys.exit(f"ERROR: profile [{profile}] has no `region` entry; pass --region")
    return sec["region"]


def _oci(args: list[str], profile: str, region: str) -> tuple[Any, str | None]:
    cmd = ["oci", *args, "--config-file", _config_path(),
           "--profile", profile, "--region", region, "--output", "json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=CLI_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None, f"OCI CLI call timed out after {CLI_TIMEOUT_S}s"
    except FileNotFoundError:
        sys.exit("ERROR: `oci` CLI not found on PATH")
    if r.returncode != 0:
        return None, (r.stderr or r.stdout).strip()[:400]
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError:
        return None, f"unparseable response: {r.stdout[:200]}"


# ------------------------------------------------------- shape discovery

def _arch(shape: dict) -> str | None:
    p = (shape.get("processor-description") or "").lower()
    name = shape.get("shape", "")
    if not name.startswith("VM.") or ".GPU" in name or name.endswith(".Generic"):
        return None
    if "ampere" in p:
        return "ARM"
    if "amd" in p:
        return "AMD"
    return None


def discover_shapes(profile: str, region: str, tenancy: str, ad: str) -> list[dict]:
    """Return ARM/AMD VM shapes offered in the AD, with limits from ListShapes."""
    data, err = _oci(["compute", "shape", "list", "--compartment-id", tenancy,
                      "--availability-domain", ad, "--all"], profile, region)
    if data is None:
        sys.exit(f"ERROR: ListShapes failed: {err}")
    seen: dict[str, dict] = {}
    for s in data.get("data", []):
        arch = _arch(s)
        if not arch or s["shape"] in seen:
            continue
        oo = s.get("ocpu-options")
        mo = s.get("memory-options")
        fixed_oc = s.get("ocpus")
        fixed_mem = s.get("memory-in-gbs")
        # Per Oracle's Shape contract, a NULL ocpu-options / memory-options
        # means that dimension is FIXED at `ocpus` / `memoryInGBs` — never
        # "unrestricted". Fall back to min=max=fixed value.
        if oo:
            min_oc, max_oc = oo.get("min"), oo.get("max")
        else:
            min_oc = max_oc = fixed_oc
        if mo:
            min_mem, max_mem = mo.get("min-in-g-bs"), mo.get("max-in-g-bs")
            min_per, max_per = mo.get("min-per-ocpu-in-gbs"), mo.get("max-per-ocpu-in-gbs")
        else:
            min_mem = max_mem = fixed_mem
            min_per = max_per = None   # implied by fixed ocpu+mem
        seen[s["shape"]] = {
            "shape": s["shape"], "arch": arch,
            "flexible": bool(s.get("is-flexible")),
            "proc": s.get("processor-description") or "",
            "ocpus": fixed_oc, "mem": fixed_mem,
            "min_oc": min_oc, "max_oc": max_oc,
            "min_mem": min_mem, "max_mem": max_mem,
            "min_per_oc": min_per, "max_per_oc": max_per,
        }
    return sorted(seen.values(), key=lambda x: (x["arch"], x["shape"]))


def fits(shape: dict, oc: float, mem: float) -> tuple[bool, str]:
    """Does (oc, mem) satisfy this shape's published limits? Returns (ok, reason)."""
    if not shape["flexible"]:
        if shape["ocpus"] == oc and shape["mem"] == mem:
            return True, ""
        return False, f"fixed {_g(shape['ocpus'])}/{_g(shape['mem'])}"
    if shape["min_oc"] is None and shape["max_oc"] is None:
        return False, "no OCPU metadata"
    if shape["min_mem"] is None and shape["max_mem"] is None:
        return False, "no memory metadata"
    checks = [
        (shape["min_oc"], shape["max_oc"], oc, "ocpus"),
        (shape["min_mem"], shape["max_mem"], mem, "memory"),
        (shape["min_per_oc"], shape["max_per_oc"], mem / oc, "GB/OCPU"),
    ]
    for lo, hi, v, label in checks:
        if lo is not None and v < lo:
            return False, f"{label} {v:g} < min {lo:g}"
        if hi is not None and v > hi:
            return False, f"{label} {v:g} > max {hi:g}"
    return True, ""


# ---------------------------------------------------------- capacity API

def _send(profile, region, tenancy, ad, batch):
    payload = []
    for shape, oc, mem, flex in batch:
        item: dict[str, Any] = {"instanceShape": shape}
        if flex:
            item["instanceShapeConfig"] = {"ocpus": oc, "memoryInGBs": mem}
        payload.append(item)
    return _oci(["compute", "compute-capacity-report", "create",
                 "--compartment-id", tenancy, "--availability-domain", ad,
                 "--shape-availabilities", json.dumps(payload)], profile, region)


def _parse(batch, data) -> dict[tuple, dict]:
    """Map one capacity-report response onto the batch's probes.

    AVAILABLE without a count is reported as AVAILABLE_NO_COUNT: OCI can return
    the status without `available-count` (tenancy access level). Never invent a
    number. OUT_OF_HOST_CAPACITY is a genuine zero.
    """
    out: dict[tuple, dict] = {}
    by_shape: dict[str, list[dict]] = {}
    for row in (data.get("data", {}).get("shape-availabilities") or []):
        by_shape.setdefault(row.get("instance-shape"), []).append(row)
    for shape, oc, mem, _flex in batch:
        key = (shape, oc, mem)
        rows = by_shape.get(shape, [])
        if not rows:
            out[key] = {"status": "MISSING_FROM_RESPONSE", "count": None, "error": None}
        elif len(rows) > 1:
            out[key] = {"status": "AMBIGUOUS", "count": None,
                        "error": f"{len(rows)} rows for one probe"}
        else:
            row = rows[0]
            status = row.get("availability-status") or "UNKNOWN"
            count = row.get("available-count")
            if status == "AVAILABLE" and count is None:
                status = NO_COUNT
            elif status == "OUT_OF_HOST_CAPACITY":
                count = 0
            elif status == "HARDWARE_NOT_SUPPORTED":
                count = None
            out[key] = {"status": status, "count": count, "error": None}
    return out


def probe(profile: str, region: str, tenancy: str, ad: str,
          specs: list[tuple[str, float, float, bool]],
          batch_size: int = DEFAULT_BATCH_SIZE) -> dict[tuple, dict]:
    """specs: (shape, ocpus, mem, flexible). Returns {(shape,oc,mem): result}.

    - Batches never contain the same shape twice, so response rows are matched
      by shape name (no reliance on array order / echoed config).
    - OCI rejects a WHOLE batch with InvalidParameter if ANY one config in it is
      invalid (observed: VM.DenseIO.E6.Ax.Flex rejected 8 OCPU/128 GB and took
      the other shapes in its batch down with it). On a failed batch every spec
      is retried ALONE; a solo InvalidParameter is a definite answer ->
      INVALID_CONFIG. Any other failure stays REQUEST_FAILED (incomplete).
    """
    results: dict[tuple, dict] = {}
    pending = list(specs)
    while pending:
        batch, rest, used = [], [], set()
        for sp in pending:
            if sp[0] not in used and len(batch) < batch_size:
                batch.append(sp)
                used.add(sp[0])
            else:
                rest.append(sp)
        pending = rest

        data, err = _send(profile, region, tenancy, ad, batch)
        if data is not None:
            results.update(_parse(batch, data))
            continue
        to_retry = batch if len(batch) > 1 else []
        if len(batch) == 1:
            results.update(_solo_failure(batch[0], err))
        for sp in to_retry:                        # isolate the bad one
            d1, e1 = _send(profile, region, tenancy, ad, [sp])
            if d1 is not None:
                results.update(_parse([sp], d1))
            else:
                results.update(_solo_failure(sp, e1))
    return results


def _solo_failure(sp, err) -> dict[tuple, dict]:
    status = "INVALID_CONFIG" if "InvalidParameter" in (err or "") else "REQUEST_FAILED"
    return {(sp[0], sp[1], sp[2]): {"status": status, "count": None, "error": err}}


# ----------------------------------------------------------------- report

DAGGER = "†"


def _g(v) -> str:
    """Format an optional number; None -> '?' (never crash on missing metadata)."""
    return "?" if v is None else f"{v:g}"


def _rng(lo, hi) -> str:
    if lo is None and hi is None:
        return "?"
    if lo == hi:
        return _g(lo)
    return f"{_g(lo)}-{_g(hi)}"


def _short(shape: str) -> str:
    return shape.replace("VM.Standard.", "").replace(".Flex", "").replace("VM.", "")


def _ad_short(ad: str) -> str:
    """'xxxx:US-ASHBURN-AD-2' -> 'AD-2'."""
    tail = ad.split(":")[-1]
    return "AD-" + tail.rsplit("-", 1)[-1] if "-AD-" in tail else tail


def _fmt_total(total: int, hidden: bool, incomplete: bool) -> str:
    """Counted total, plus markers: † = some AVAILABLE shape had no count
    (true value is higher), * = some probe gave no definite answer."""
    if hidden and total == 0:
        s = f"avail{DAGGER}"
    else:
        s = f"{total:,}" + (f"+{DAGGER}" if hidden else "")
    return s + ("*" if incomplete else "")


def _cell_part(sh: dict, r: dict) -> str:
    name = _short(sh["shape"])
    st = r["status"]
    if st in COUNTED:
        return f"{name}={r['count']:,}"
    if st == NO_COUNT:
        return f"{name}=avail{DAGGER}"
    if st == "INVALID_CONFIG":
        return f"{name}=invalid-cfg"
    if st == "HARDWARE_NOT_SUPPORTED":
        return f"{name}=not-supported"
    return f"{name}={st}"


def _collect(profile, region, tenancy, ads, shapes_by_ad, arch_specs, batch_size):
    """arch_specs: {arch: [(oc, mem), ...]} -> per (arch, oc, mem, ad):
    {"total": int, "hidden": bool, "incomplete": bool, "any": bool, "parts": [str]}"""
    agg: dict[tuple, dict] = {}
    for ad in ads:
        shapes = shapes_by_ad[ad]
        specs, plan = [], {}
        for arch, pairs in arch_specs.items():
            for oc, mem in pairs:
                entries = []
                for sh in (s for s in shapes if s["arch"] == arch):
                    ok, _why = fits(sh, oc, mem)
                    entries.append((sh, ok))
                    if ok:
                        specs.append((sh["shape"], oc, mem, sh["flexible"]))
                plan[(arch, oc, mem)] = entries
        res = probe(profile, region, tenancy, ad, specs, batch_size) if specs else {}
        for (arch, oc, mem), entries in plan.items():
            cell = {"total": 0, "hidden": False, "incomplete": False, "any": False, "parts": []}
            for sh, ok in entries:
                if not ok:
                    continue
                cell["any"] = True
                r = res[(sh["shape"], oc, mem)]
                if r["status"] in COUNTED:
                    cell["total"] += r["count"]
                elif r["status"] == NO_COUNT:
                    cell["hidden"] = True
                elif r["status"] not in NOT_PROBEABLE:
                    cell["incomplete"] = True
                cell["parts"].append(_cell_part(sh, r))
            agg[(arch, oc, mem, ad)] = cell
    return agg


def _limitations(hidden_seen: bool) -> None:
    print("Limitations: best-effort, point-in-time estimate from OCI's capacity report;")
    print("  not a reservation or launch guarantee. It does not consider capacity")
    print("  reservations or tenancy service limits/quotas (check those separately), and")
    print("  results can vary by tenancy.")
    if hidden_seen:
        print(f"{DAGGER}  NOTE: OCI reported AVAILABLE but returned NO COUNT for some shapes. This")
        print("   depends on your tenancy's access level: external customer tenancies may")
        print("   not receive counts, while Oracle-internal tenancies typically do. Totals")
        print(f"   marked {DAGGER} are lower bounds; the shape can launch, but how many is unknown.")


def sweep(profile, region, tenancy, ads, shapes_by_ad, ratios, sizes, detail,
          batch_size=DEFAULT_BATCH_SIZE) -> int:
    """Ratio sweep. Returns the exit code (0, 2 or 3)."""
    arch_specs = {arch: [(float(s), float(s * r)) for s in sizes] for arch, r in ratios.items()}
    agg = _collect(profile, region, tenancy, ads, shapes_by_ad, arch_specs, batch_size)
    incomplete_seen = hidden_seen = False
    multi = len(ads) > 1
    for arch, ratio in ratios.items():
        fams = sorted({_short(s["shape"]) for ad in ads for s in shapes_by_ad[ad] if s["arch"] == arch})
        print()
        print(f"=== {arch} @ 1 OCPU : {ratio:g} GB   (region total across {len(ads)} AD"
              f"{'s' if multi else ''})   families: {', '.join(fams) or 'NONE'} ===")
        print(f"{'OCPU/VM':>8} {'vCPU/VM':>8} {'RAM/VM(GB)':>11} {'Launchable':>13}   "
              f"{'Per-AD' if multi else 'Per-family'}")
        print("-" * 96)
        for oc, mem in arch_specs[arch]:
            total, hid, inc, any_ok, parts = 0, False, False, False, []
            for ad in ads:
                c = agg[(arch, oc, mem, ad)]
                total += c["total"]
                hid |= c["hidden"]
                inc |= c["incomplete"]
                any_ok |= c["any"]
                if multi:
                    parts.append(f"{_ad_short(ad)}={_fmt_total(c['total'], c['hidden'], c['incomplete'])}"
                                 if c["any"] else f"{_ad_short(ad)}=—")
                else:
                    parts.extend(c["parts"])
            if not any_ok:
                tot = "—"
            else:
                tot = _fmt_total(total, hid, inc)
                hidden_seen |= hid
                incomplete_seen |= inc
            vc = oc * VCPU_PER_OCPU[arch]
            print(f"{oc:>8g} {vc:>8g} {mem:>11g} {tot:>13}   ({', '.join(parts)})")
            if detail and multi:
                for ad in ads:
                    c = agg[(arch, oc, mem, ad)]
                    if c["any"]:
                        print(f"{'':>45}{_ad_short(ad)}: {', '.join(c['parts'])}")
    print()
    print("Launchable = arithmetic sum of OCI's per-shape counts at that exact size"
          + (", across all ADs." if multi else "."))
    print("  Each count is OCI's figure for that shape+config+AD alone; the sum is NOT a")
    print("  guaranteed simultaneous launch count. A single cluster usually lands in ONE AD —")
    print("  for the largest single cluster, look at the per-AD figure, not the region total.")
    print("Rows are alternative scenarios — do NOT add rows together.")
    print("Sizes are in OCPUs (OCI's unit). 1 OCPU = 2 vCPU on AMD/Intel, 1 vCPU on Ampere ARM.")
    print("  Comparing ARM vs AMD? Match rows by vCPU + RAM, not OCPU — e.g. ARM 32 OCPU")
    print("  (32 vCPU/256 GB) is the same machine as AMD 16 OCPU (32 vCPU/256 GB).")
    print("—  = no discovered family supports that size here")
    if incomplete_seen:
        print("*  = INCOMPLETE: some shapes returned no definite answer (run --detail).")
    _limitations(hidden_seen)
    return 2 if incomplete_seen else (3 if hidden_seen else 0)


def fit_check(profile, region, tenancy, ads, shapes_by_ad, oc, mem,
              batch_size=DEFAULT_BATCH_SIZE) -> int:
    """One explicit configuration across every AD and shape. Returns the exit code."""
    print()
    va, vd = oc * VCPU_PER_OCPU["ARM"], oc * VCPU_PER_OCPU["AMD"]
    print(f"Target: {oc:g} OCPU x {mem:g} GB ({mem/oc:.2f} GB/OCPU)"
          f"  ->  ARM {va:g} vCPU / AMD {vd:g} vCPU (same OCPU, NOT same vCPU)")
    incomplete = False
    total = {"ARM": 0, "AMD": 0}
    hidden = {"ARM": False, "AMD": False}
    print(f"\n{'AD':<6} {'Shape':<26} {'Arch':<5} {'vCPU':>5} {'Status':<22} {'Launchable':>11}")
    print("-" * 84)
    for ad in ads:
        specs, rows = [], []
        for sh in shapes_by_ad[ad]:
            ok, _why = fits(sh, oc, mem)
            if ok:
                specs.append((sh["shape"], oc, mem, sh["flexible"]))
                rows.append(sh)
        res = probe(profile, region, tenancy, ad, specs, batch_size) if specs else {}
        for sh in rows:
            r = res[(sh["shape"], oc, mem)]
            st = r["status"]
            if st in COUNTED:
                total[sh["arch"]] += r["count"]
                cnt = f"{r['count']:,}"
            elif st == NO_COUNT:
                hidden[sh["arch"]] = True
                cnt = f"not returned{DAGGER}"
            elif st in NOT_PROBEABLE:
                cnt = "—"
            else:
                incomplete, cnt = True, "N/A"
            print(f"{_ad_short(ad):<6} {sh['shape']:<26} {sh['arch']:<5} "
                  f"{oc * VCPU_PER_OCPU[sh['arch']]:>5g} {st:<22} {cnt:>11}")
    print()
    arm_t = _fmt_total(total["ARM"], hidden["ARM"], False)
    amd_t = _fmt_total(total["AMD"], hidden["AMD"], False)
    print(f"Region total at {oc:g} OCPU x {mem:g} GB:  "
          f"ARM {arm_t} ({va:g} vCPU)   AMD {amd_t} ({vd:g} vCPU)"
          + ("" if not incomplete else "   (* incomplete — some shapes N/A)"))
    # ARM and AMD totals above are different machines (vCPU differs). Point at the
    # like-for-like runs instead of letting the reader compare them directly.
    print("  Not like-for-like: 1 OCPU = 1 vCPU on ARM, 2 vCPU on AMD.")
    print(f"  ARM at AMD's {vd:g} vCPU / {mem:g} GB:  --ocpus {oc * 2:g} --memory-gb {mem:g}")
    if (oc / 2).is_integer():
        print(f"  AMD at ARM's {va:g} vCPU / {mem:g} GB:  --ocpus {oc / 2:g} --memory-gb {mem:g}")
    else:
        print(f"  AMD at ARM's {va:g} vCPU: no equivalent (AMD vCPUs come in pairs, whole OCPUs only).")
    print()
    hidden_seen = hidden["ARM"] or hidden["AMD"]
    _limitations(hidden_seen)
    return 2 if incomplete else (3 if hidden_seen else 0)


# ------------------------------------------------------------------- main

def _pos_finite(name: str, v: float) -> float:
    if v is None or not math.isfinite(v) or v <= 0:
        sys.exit(f"ERROR: --{name} must be a positive finite number (got {v})")
    return v


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OCI ARM/AMD launchable-nodes report")
    ap.add_argument("--profile", default="DEFAULT")
    ap.add_argument("--region", default=None,
                    help="OCI region, e.g. us-ashburn-1 (default: the profile's region)")
    ap.add_argument("--ad", default=None,
                    help="restrict to ONE availability domain (default: ALL ADs, consolidated)")
    ap.add_argument("--tenancy-ocid", default=None,
                    help="ROOT tenancy OCID (default: from profile)")
    ap.add_argument("--arm-ratio", type=float, default=8.0)
    ap.add_argument("--amd-ratio", type=float, default=16.0)
    ap.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)))
    ap.add_argument("--ocpus", type=float)
    ap.add_argument("--memory-gb", type=float)
    ap.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                    help=f"shape entries per capacity-report request (default {DEFAULT_BATCH_SIZE})")
    ap.add_argument("--detail", action="store_true",
                    help="multi-AD regions: also print per-AD per-family breakdown")
    ap.add_argument("--show-shapes", action="store_true",
                    help="print discovered ARM/AMD shapes + limits per AD and exit")
    a = ap.parse_args(argv)

    if (a.ocpus is None) != (a.memory_gb is None):
        sys.exit("ERROR: --ocpus and --memory-gb must be used together")
    _pos_finite("arm-ratio", a.arm_ratio)
    _pos_finite("amd-ratio", a.amd_ratio)
    if a.ocpus is not None:
        _pos_finite("ocpus", a.ocpus)
        _pos_finite("memory-gb", a.memory_gb)
    if a.batch_size < 1:
        sys.exit("ERROR: --batch-size must be >= 1")
    try:
        sizes = [int(x) for x in a.sizes.split(",")]
    except ValueError:
        sys.exit(f"ERROR: --sizes must be comma-separated integers: {a.sizes!r}")
    if any(s <= 0 for s in sizes):
        sys.exit("ERROR: --sizes must all be positive")

    tenancy = a.tenancy_ocid or _tenancy_from_profile(a.profile)
    region = a.region or _region_from_profile(a.profile)
    ads_data, err = _oci(["iam", "availability-domain", "list",
                          "--compartment-id", tenancy], a.profile, region)
    if ads_data is None:
        sys.exit(f"ERROR listing ADs: {err}")
    all_ads = [x["name"] for x in ads_data.get("data", [])]
    if not all_ads:
        sys.exit(f"ERROR: no ADs in {region}")
    if a.ad:
        if a.ad not in all_ads:
            sys.exit(f"ERROR: --ad {a.ad!r} not in {all_ads}")
        ads = [a.ad]
    else:
        ads = all_ads

    shapes_by_ad = {ad: discover_shapes(a.profile, region, tenancy, ad) for ad in ads}
    print(f"Region : {region}   ADs : {', '.join(_ad_short(x) for x in ads)}"
          f"{'' if a.ad else ' (all, consolidated)'}")
    print(f"Profile: {a.profile}")

    if a.show_shapes:
        for ad in ads:
            print(f"\n[{_ad_short(ad)}]")
            print(f"{'Shape':<26} {'Arch':<5} {'Flex':<5} {'OCPU':>11} {'Mem GB':>13} {'GB/OCPU':>9}  Processor")
            for s in shapes_by_ad[ad]:
                if s["flexible"]:
                    oc, mg, po = _rng(s["min_oc"], s["max_oc"]), _rng(s["min_mem"], s["max_mem"]), _rng(s["min_per_oc"], s["max_per_oc"])
                else:
                    oc, mg, po = _g(s["ocpus"]), _g(s["mem"]), "fixed"
                print(f"{s['shape']:<26} {s['arch']:<5} {str(s['flexible']):<5} {oc:>11} {mg:>13} {po:>9}  {s['proc'][:40]}")
        return 0

    if a.ocpus is not None:
        return fit_check(a.profile, region, tenancy, ads, shapes_by_ad, a.ocpus, a.memory_gb,
                         a.batch_size)
    return sweep(a.profile, region, tenancy, ads, shapes_by_ad,
                 {"ARM": a.arm_ratio, "AMD": a.amd_ratio}, sizes, a.detail, a.batch_size)


if __name__ == "__main__":
    sys.exit(main())
