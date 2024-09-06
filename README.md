# bitcoin-primitives

Libraries and primitives for Bitcoin, written in Zig.

# Zig Official Package Manager

To install `bitcoin-primitives`, you need to run the following command in your root folder with `build.zig`:

```bash
zig fetch --save git+https://github.com/zig-bitcoin/bitcoin-primitives#f3af13008b088796697fc656e26d8c2ddf73dc18
```

where `f3af13008b088796697fc656e26d8c2ddf73dc18` is the commit hash.

Then, in your `build.zig`, you need to add our module:

```zig
const bitcoin_primitives = b.dependency("bitcoin-primitives", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("bitcoin-primitives", bitcoin_primitives.module("bitcoin-primitives"));
```
