# c2rust

Notes on how to transpile using c2rust.

## Steps

```
LLVM_CONFIG_PATH=llvm-config-19 cargo install c2rust
./bootstrap.sh
./configure
intercept-build-19 make
c2rust transpile --binary arping_main compile_commands.json -o rarping
cd rarping
sed -i 's/^chan/#chan/' rust-toolchain.toml
# Add in build.rs: println!("cargo:rustc-flags=-l net");
# Add in build.rs: println!("cargo:rustc-flags=-l pcap");
```
