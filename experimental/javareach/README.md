# Java reachability (WIP)

This is an experimental tool to statically enumerate the reachable classes in a
Java program.

The intention is to see if this can be used to exclude transitive dependencies
from vulnerability scanning completely, if they can be proven to be
unreachable.

## Usage

```
go run ./cmd/reachable -classpath=<classpath> path/to/root/class
```

Note that `<classpath>` currently only supports a single directory path
containing .class files, with a directory structure that mirrors the package
hierarchy. This is unlike classpaths supported by Java runtimes (which supports
specifying multiple directories and .jar files)
