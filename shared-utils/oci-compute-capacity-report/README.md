# OCI compute capacity report: ARM and AMD launchable nodes

`oci_capacity_report.py` answers one question: **how many VM nodes of a given size can OCI launch right now in a region, for ARM (Ampere) and for AMD?** It queries the OCI [CreateComputeCapacityReport](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/compute-capacity-report/create.html) API for every ARM and AMD VM shape family and every availability domain (AD) in the region, then prints one consolidated report.

Use it before you size a Spark cluster or a compute fleet, for example:

- **OCI Data Flow, OCI Compute, or Kubernetes node pools**, where you choose the exact shape (A1, E4, E5, ...) for each node.
- **Oracle AI Data Platform (AIDP) Workbench clusters.** AIDP doesn't ask you to pick a specific shape family, but the report still shows whether ARM or AMD capacity at a given node size is plentiful or scarce in the region.

> [!IMPORTANT]
> **External customer tenancies might not receive launchable counts.** Depending on your tenancy's access level, OCI can return only the availability status (`AVAILABLE` or `OUT_OF_HOST_CAPACITY`) and leave the count empty. Oracle-internal tenancies typically receive counts. When a count isn't returned, the report marks the value with **†** and prints a note. It never guesses a number. Read [Limitations](#limitations) before you share results.

## What the report tells you

- **Launchable nodes at an exact size.** Each number is OCI's estimate for one exact shape, OCPU count, and memory size, in one AD.
- **ARM and AMD side by side**, by default at 1 OCPU : 8 GB for ARM and 1 OCPU : 16 GB for AMD, across sizes from 1 to 64 OCPUs.
- **A region total and a per-AD breakdown.** A single cluster usually lands in one AD, so the per-AD figure shows the largest cluster you can expect to place.
- **Any region, any current or future shape family.** The script discovers ADs, shape families, and their limits at run time, so new families appear without code changes.

## Limitations

Read these before you rely on, or share, the numbers:

- **Count visibility depends on your tenancy.** Some tenancies, typically external customer tenancies, receive the availability status but no count. The report then shows `avail†` (available, count not returned) and exits with code `3`. Treat totals marked † as lower bounds.
- **The report is a best-effort, point-in-time estimate.** It isn't a reservation and it doesn't guarantee that a later launch succeeds. Capacity changes from minute to minute, so run the report again just before a large launch.
- **The report doesn't consider capacity reservations or your service limits and quotas.** Check your tenancy limits separately (for example, with `oci limits resource-availability get` or the **Limits, Quotas and Usage** page in the Console). A launch succeeds only when both capacity and your limits allow it.
- **Results can vary by tenancy.** Allocation policies and placement constraints can make the same query return different results in different tenancies.
- **Sums are arithmetic, not a joint guarantee.** Shape families can share hosts, so you can't necessarily launch the region total at once.
- **Only standard VM shapes are covered.** The script skips GPU, bare metal, and `.Generic` shapes, and doesn't request burstable or preemptible capacity.

### When you share results

Include the limitations with the numbers. For example, paste this note with the output:

> Capacity figures come from the OCI compute capacity report: a best-effort, point-in-time estimate, not a reservation or launch guarantee. They don't account for capacity reservations or our tenancy service limits. Values marked † were reported as available without a count; the actual number is unknown.

## Prerequisites

- **Python 3.8 or later.** The script uses only the standard library.
- **The OCI CLI** on your `PATH`. See [Installing the CLI](https://docs.oracle.com/iaas/Content/API/SDKDocs/cliinstall.htm).
- **An OCI CLI configuration file** (`~/.oci/config`, or the path in `$OCI_CLI_CONFIG_FILE`) with a profile that uses API key authentication.
- **A subscription to the region** you query.
- **IAM policies** for the group that runs the report:

  ```text
  Allow group <your-group> to manage compute-capacity-reports in tenancy
  Allow group <your-group> to inspect instance-family in tenancy
  ```

  The first statement allows the capacity report. The `manage` verb is required; `use` isn't enough. The second statement allows the script to list shapes. Without these policies, the API returns `NotAuthorizedOrNotFound`.

## Run the report

Run the default sweep in your profile's region:

```bash
python3 oci_capacity_report.py
```

Query a specific region. Multi-AD regions are probed in every AD and consolidated:

```bash
python3 oci_capacity_report.py --region us-ashburn-1
```

Add the per-AD, per-shape-family breakdown, which helps you choose a shape:

```bash
python3 oci_capacity_report.py --region us-ashburn-1 --detail
```

Check only the node sizes that you plan to use:

```bash
python3 oci_capacity_report.py --region us-ashburn-1 --sizes 8,32
```

Check one exact configuration in every shape and every AD:

```bash
python3 oci_capacity_report.py --region us-ashburn-1 --ocpus 32 --memory-gb 512
```

List the discovered ARM and AMD shapes and their published limits:

```bash
python3 oci_capacity_report.py --region us-ashburn-1 --show-shapes
```

Restrict the report to one AD (get the exact AD names from `--show-shapes` or `oci iam availability-domain list`):

```bash
python3 oci_capacity_report.py --region us-ashburn-1 --ad "<AD name>"
```

### Options

| Option | Default | Description |
|---|---|---|
| `--region` | The profile's region | OCI region to query, such as `us-ashburn-1`. |
| `--profile` | `DEFAULT` | Profile in the OCI CLI configuration file. |
| `--ad` | All ADs | Restrict the report to one availability domain. |
| `--sizes` | `1,2,4,8,16,32,64` | OCPU sizes to sweep. |
| `--arm-ratio` | `8` | GB of memory per OCPU for ARM rows. |
| `--amd-ratio` | `16` | GB of memory per OCPU for AMD rows. |
| `--ocpus N --memory-gb M` | — | Fit check: one exact configuration, every shape, every AD. |
| `--detail` | Off | In multi-AD regions, add a per-AD line with each shape family's count. |
| `--show-shapes` | Off | Print the discovered shapes and their limits, then exit. |
| `--tenancy-ocid` | From the profile | Root tenancy OCID override. |
| `--batch-size` | `3` | Shape entries per capacity-report request. Lower it if the API rejects requests for size. |

## Read the output

- **Launchable** is the sum of OCI's per-shape counts at that exact size (and across ADs in multi-AD regions).
- **Per-AD** (multi-AD regions) or **Per-family** (single-AD regions) shows where the total comes from.
- **Rows are alternative scenarios.** Don't add rows together.
- **OCPU and vCPU differ by architecture.** Sizes are in OCPUs, OCI's unit. 1 OCPU is 2 vCPUs on AMD and Intel but 1 vCPU on Ampere ARM. To compare ARM with AMD, match rows by vCPU and memory, not by OCPU. For example, ARM at 32 OCPU (32 vCPUs, 256 GB) is comparable to AMD at 16 OCPU (32 vCPUs, 256 GB). The fit check prints the matching commands for you.

| Marker or status | Meaning |
|---|---|
| A number | OCI can launch that many nodes of this configuration now. |
| `OUT_OF_HOST_CAPACITY` or `0` | The configuration is valid, but no capacity is available now. |
| `avail†` or `N+†` | OCI reports capacity as available but didn't return a count for at least one shape. `N+†` means at least N. |
| `invalid-cfg` or `INVALID_CONFIG` | OCI rejects this configuration for that shape. Some shapes accept only specific sizes. |
| `not-supported` or `HARDWARE_NOT_SUPPORTED` | The shape isn't supported in that AD. |
| `—` | No discovered shape family supports that size in that location. |
| `N*` | Incomplete: at least one request failed or timed out. Run with `--detail` to see which one. |

### Sample output

The following samples are **illustrative**. The numbers are made up, and they show the format only.

A tenancy that receives counts:

```text
Region : us-ashburn-1   ADs : AD-1, AD-2, AD-3 (all, consolidated)
Profile: DEFAULT

=== ARM @ 1 OCPU : 8 GB   (region total across 3 ADs)   families: A1, A2 ===
 OCPU/VM  vCPU/VM  RAM/VM(GB)    Launchable   Per-AD
------------------------------------------------------------------------------------------------
       8        8          64         8,370   (AD-1=2,700, AD-2=3,510, AD-3=2,160)
      32       32         256         2,092   (AD-1=675, AD-2=877, AD-3=540)

=== AMD @ 1 OCPU : 16 GB   (region total across 3 ADs)   families: E4, E5 ===
 OCPU/VM  vCPU/VM  RAM/VM(GB)    Launchable   Per-AD
------------------------------------------------------------------------------------------------
       8       16         128         4,650   (AD-1=1,500, AD-2=1,950, AD-3=1,200)
      32       64         512         1,162   (AD-1=375, AD-2=487, AD-3=300)
...
Limitations: best-effort, point-in-time estimate from OCI's capacity report;
  not a reservation or launch guarantee. It does not consider capacity
  reservations or tenancy service limits/quotas (check those separately), and
  results can vary by tenancy.
```

A tenancy that receives the status only (exit code `3`):

```text
=== ARM @ 1 OCPU : 8 GB   (region total across 3 ADs)   families: A1, A2 ===
 OCPU/VM  vCPU/VM  RAM/VM(GB)    Launchable   Per-AD
------------------------------------------------------------------------------------------------
       8        8          64        avail†   (AD-1=avail†, AD-2=avail†, AD-3=avail†)
      32       32         256        avail†   (AD-1=avail†, AD-2=avail†, AD-3=avail†)
...
†  NOTE: OCI reported AVAILABLE but returned NO COUNT for some shapes. This
   depends on your tenancy's access level: external customer tenancies may
   not receive counts, while Oracle-internal tenancies typically do. Totals
   marked † are lower bounds; the shape can launch, but how many is unknown.
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every request returned a definite answer with a count. |
| `3` | Every request returned a definite status, but OCI didn't return a count for at least one available shape. Totals are lower bounds. |
| `2` | Coverage is incomplete: at least one request failed, timed out, or returned no usable row. |
| `1` | Setup error, such as a missing configuration, failed authorization, or bad arguments. |

## How it works

1. The script lists the region's availability domains (`oci iam availability-domain list`).
2. For each AD, it lists the VM shapes and their published OCPU and memory limits (`oci compute shape list`). It classifies Ampere shapes as ARM and AMD shapes as AMD, and skips GPU, bare metal, and `.Generic` shapes.
3. For each size, it keeps only the shapes whose limits allow that configuration.
4. It calls `oci compute compute-capacity-report create` with up to three shapes per request. If the API rejects a request because one configuration is invalid, the script retries each shape on its own so that the other shapes still return results.
5. It sums the results per architecture, per AD, and per region, and prints the report.

The script is read-only. It doesn't create instances, reservations, or any other resources.

## Run the tests

The tests mock the OCI CLI, so they run without OCI access:

```bash
python3 -m pip install pytest
python3 -m pytest tests/
```
