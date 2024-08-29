#!/bin/bash

benchmarks=(
    "Enc:100000x"
    "PDec8:15000x"
    "PDec32:2000x"
    "PDec128:1000x"
    "PDec512:500x"
    "BatchCombine8:1500x"
    "BatchCombine32:150x"
    "BatchCombine128:20x"
    "BatchCombine512Slow:2x"
    "BatchCombine512Fast:10x"
    "BatchCombinePar:50x"
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