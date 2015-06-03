#!/bin/bash

rm bench_perf.dat
rm bench_accuracy.dat

echo "#rows/uniqe_vals  time exact (ms)    time approx (ms)" > bench_perf.dat
echo "#rows/uniqe_vals  exact cardinality    approx cardinality" > bench_accuracy.dat

./run.sh 32768 16384
./run.sh 65536 32758
./run.sh 131072 65536
./run.sh 262144 131072
./run.sh 524288 262144
./run.sh 1048576 524288
./run.sh 2097152 1048576


gnuplot -p bench_perf.gpl
gnuplot -p bench_accuracy.gpl
