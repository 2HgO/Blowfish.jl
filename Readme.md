# Blowfish.jl

Blowfish.jl is an implementation of Bruce Schneier's Blowfish encryption algorithm.

This implementation was loosely transcribed from the [Go](https://golang.org)(golang) port of [Bruce Schneier's C implementation](https://www.schneier.com/blowfish.html).  
See [crpto/blowfish](https://pkg.go.dev/golang.org/x/crypto/blowfish)

## Installation
---
From a julia session, run:
```julia-repl
julia> using Pkg
julia> Pkg.add("Blowfish")
```

## License
---
The source code for the package `Blowfish.jl` is licensed under the MIT License.