set -e -o pipefail

for arg in "$@"
do
    if [[ $arg == spanner_prober_args=* ]]; then
    args1=(${arg#spanner_prober_args=})
    fi

    if [[ $arg == lightfoot_args=* ]]; then
    args2=(${arg#lightfoot_args=})
    fi
done

echo Running Prober
./spanner_prober "${args1[@]}" &
SPPID=$!
echo Probe running with PID $SPPID
echo Running Tracer

./lightfoot $SPPID "${args2[@]}"
