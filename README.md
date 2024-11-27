# Fuzzing Nix

This repository works on the facilitation of fuzzing infrastructure for [Nix](https://github.com/NixOS/nix).

## Getting started

If you want to configure a new machine to fuzz with one of the setups available in this repository, follow
these steps.

### Prerequisites

- A Nix installation.

### Step-by-Step guide: `libexpr` harness

We're using the most simple harness for the basic guide here; `libexpr`.

It fuzzes the evaluation of Nix expressions, using AFL++ persistent mode and Nix' C bindings.

First, configure your system for efficient use with AFL++:

```sh
cd nix-fuzzing
nix shell .#aflxx
sudo afl-system-config
```

Now, compile the fuzzing target. In this case, it's going to be the `libexpr` harness, so we're
building `harness.libexpr`

```sh
nix build .#harness.libexpr
```

Then, create a working directory and move your seeds into there:

```sh
mkdir fuzz
cd fuzz
cp -r ../seeds .
```

Now, we can start fuzzing:

```sh
afl-fuzz -i seeds/ -o out -- ../result/bin/main
```

## Acknowledgements

This repository is a public view into the experiments I'm conducting on fuzzing Nix
as part of my master's thesis at RUB, supervised by [Flavio Toffalini](https://flaviotoffalini.info/).
