# Implementation of Batched Threshold Encryption Scheme

This is a proof of concept implementation of our Batched Threshold Encryption Scheme.
Please do not use it for anything else than testing purposes.
Also, note that the source groups G_1 and G_2 are swapped with respect to the representation in the paper.
This is because G_1 operations are generally a bit more efficient.

## Evaluation
You can rerun the benchmarks on your machine using `./bench.sh`.
The results will be placed into the `bench` directory.
The evaluation results for the paper can be found in the `bench-bls-subbatching` directory.