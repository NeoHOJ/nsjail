# Docs for HOJ fork (tentative)

## Statistics

There have been plenty of forks that add some execution statistics that are
somehow handy when inspecting or benchmarking. This fork builds the same wheel
basically, but focuses more on compatibility with existing debuging messages,
for easy-grepping for further analysis.

A statistic entry is a line of the following format:

```
[S][<timestamp>] __STAT__:0 <key> = <value-for-this-key>
```

Statistics are of highest log level. It is (currently?) not possible to hide
these messages.

For which `<timestamp>` is the timestamp, `<key>` is an identifier (sequence of
non-whitespace characters), and `<value-for-this-key>` is a value. In some
cases where the process id is relevent, the key starts with `%d:`, where `%d`
(digits) is the pid. The value is a JS-like literal that spans until, but does
not cross, the line end, escaping as needed.

Below is currently-defined ids. The list is likely to be extended in the future.

| ID                           | Type    | Description |
|------------------------------|---------|-------------|
| `info`                       | String  | The string describing this nsjail fork.
| `%d:time`                    | Integer | The running time in milliseconds.
| `%d:exit_normally`           | Boolean | True when the process exits (not killed by signal).
| `%d:exit_code`               | Integer | The status code of process.
| `%d:cgroup_memory_max_usage` | Integer | Max. usage of the process memory. Only present when memory cgroup is enabled.
| `%d:cgroup_memory_failcnt`   | Integer | >0 usually indicates the usage of exceeded memory. Only present when memory cgroup is enabled.
| `%d:seccomp_violation`       | Boolean | Whether the program is killed because of a violation of secomp-bpf rules. Only present when a seccomp BPF is specified.
