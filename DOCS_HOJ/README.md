# Docs for HOJ fork (tentative)

## Statistics

There have been plenty of forks that add some execution statistics that are
somehow handy when inspecting or benchmarking. This fork builds the same wheel
basically, but focuses more on compatibility with existing debuging messages,
for easy-grepping for further analysis.

A statistic entry is a line of the following format:

```
[S][<pid>] __STAT__:0 <key> = <value-for-this-key>
```

For which `<pid>` is the pid of nsjail, `<key>` is an identifier (sequence of
non-whitespace characters), and `<value-for-this-key>` is a value. In some
cases where the process id is relevent, the key starts with `%d:`, where `%d`
(digits) is the pid. The value is a JS-like literal that spans until, but does
not cross, the line end, escaping as needed.

Statistics are of highest log level. It is (currently?) not possible to hide
these messages.

Below is currently-defined ids. The list is likely to be extended in the future.

| ID                           | Type    | Description |
|------------------------------|---------|-------------|
| `info`                       | String  | The string describing this nsjail fork.
| `%d:process_spawned`         | Integer | The **UNIX time (in seconds)** the child is going to be kept track of by nsjail. The main purpose is to know the pid of the child.
| `%d:time`                    | Integer | The running time in milliseconds.
| `%d:exit_normally`           | Boolean | True when the process exits (not killed by signal).
| `%d:exit_code`               | Integer | The **exit code** of process if the process exits normally, or the **signal id** that terminates the process otherwise.
| `%d:cgroup_memory_max_usage` | Integer | Cumulative usage of the process memory. Only present when memory cgroup is enabled.
| `%d:cgroup_memory_failcnt`   | Integer | >0 usually indicates the usage of exceeded memory. Only present when memory cgroup is enabled.
| `%d:seccomp_violation`       | Boolean | Whether the program is killed because of a violation of secomp-bpf rules. Only present when a seccomp BPF is specified.

It is possible that the same pid of some child repeat. It is yet specified how
to handle repeated keys.
