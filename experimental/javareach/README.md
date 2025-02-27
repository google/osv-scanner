# Java reachability (WIP)

This is an experimental tool to statically enumerate the reachable classes in a
Java program.

The intention is to see if this can be used to exclude transitive dependencies
from vulnerability scanning completely, if they can be proven to be
unreachable.

This supports uber (or fat) JARs.

## Usage

```
go run ./cmd/reachable /path/to/file.jar
```
