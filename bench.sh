#!/bin/bash

benchmarks=(
    "Enc:50000x"
    "PDec8:10000x"
    "PDec32:1500x"
    "PDec128:800x"
    "PDec512:400x"
    "BatchCombine8:1000x"
    "BatchCombine32:100x"
    "BatchCombine128:20x"
    "BatchCombine512Slow:2x"
    "BatchCombine512Fast:10x"
    "BatchCombineParSqrt:50x"
)

benchdir="bench"

mkdir -p "$benchdir"

for entry in "${benchmarks[@]}"; do
    IFS=":" read -r bench benchtime <<< "$entry"

    # Run the benchmark and save the output to a file
    go test -bench="$bench" -benchtime="$benchtime" > "${benchdir}/bench-${bench}.txt"
    echo "Saved results of $bench to $benchdir"
done

echo "All benchmarks completed."