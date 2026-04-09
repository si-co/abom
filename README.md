# At-Compromise Security: The Case for Alert Blindness
**WARNING**: This software is **not** production-ready and it might contain security vulnerabilities.

This code accompanies the paper ["At-Compromise Security: The Case for Alert Blindness"](https://eprint.iacr.org/2026/252) by Martin R. Albrecht, Simone Colombo, Benjamin Dowling and Rikke Bjerg Jensen to appear at EUROCRYPT 2026.

The root directory of the repository contains the Go reference implementation of the ABOM scheme (Figure 5 in the proceedings version, Figure 10 of the full version linked above). The [scripts](scripts) directory contains a SageMath script that make it easier to explore the effect of the personal secret distribution S on the advantage in Definition 1 in the full version.

## ABOM scheme implementation
This directory contains the Go reference implementation of the ABOM scheme (Figure 5 in the proceedings version, Figure 10 of the full version linked above).

### Running tests

Provided you have Go version 1.24.6 or above installed, from this directory, run:

  `go test`

## Advantage estimation
Provided you have SageMath version 10.x installed, you can use the function in the Sage interactive shell by loading the code with `load("scripts/pw.py")` from the root of the repository. See the examples at the end of [scripts/pw.py](scripts/pw.py).

To test the script, from the root of the repository, run:

`python -m sage.doctest scripts/pw.py`

## Running all tests with Docker
If you have Docker installed, you can run both test suites without installing Go or SageMath. From the root of the repository run the following command:

`docker build -t abom .`

