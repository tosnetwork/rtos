#!/usr/bin/env bash
# Retain phase resource evidence without changing the wrapped command's result.
set -euo pipefail

if (( $# < 2 )) || [[ ! $1 =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "usage: $0 PHASE COMMAND [ARG ...]" >&2
    exit 2
fi

task_phase=$1
shift
task_resource_dir=${CI_RESOURCE_DIR:-${RUNNER_TEMP:-/tmp}/rtos-ci-resources}
mkdir -p -- "$task_resource_dir"
task_resource_file="$task_resource_dir/$task_phase-resources.txt"
task_time_file="$task_resource_dir/$task_phase-time.txt"

report_resources() {
    date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
    nproc || true
    free -m || true
    df -Pk . || true
}

echo "Starting CI phase: $task_phase"
report_resources > "$task_resource_file"
cat -- "$task_resource_file"

# Stream snapshots before a runner failure can prevent artifact upload. The
# observer must never replace the wrapped command's exit status.
python3 "$(dirname -- "${BASH_SOURCE[0]}")/sample_resources.py" \
    --root-pid "$$" --phase "$task_phase" \
    --output "$task_resource_dir/$task_phase-samples.jsonl" &
task_sampler_pid=$!
stop_sampler() {
    kill "$task_sampler_pid" 2>/dev/null || true
    wait "$task_sampler_pid" 2>/dev/null || true
}
trap stop_sampler EXIT

task_command_status=0
/usr/bin/time --verbose --output="$task_time_file" "$@" || task_command_status=$?

report_resources >> "$task_resource_file" || true
echo "CI phase $task_phase command exit: $task_command_status"
cat -- "$task_time_file" || true
cat -- "$task_resource_file" || true
exit "$task_command_status"
