FHE-Turing
==========

*This project probably doesn't work, it was an experiment in using TFHE.*

A fully homomorphic Turing machine: the instructions and the initial tape are only known to the client, and the computations are entirely carried out by the server.

## Setup

Download [the TFHE library](https://github.com/tfhe/tfhe/) (tested against 5fd4d8b) and compile it (`cd` into the folder, run `make`, then `sudo make install`).