# Teleprobe

Run MCU binaries on remote targets.

## ⚠️ maintenance status ⚠️

This project is actively maintained only for the goal of running [Embassy](https://github.com/embassy-rs/embassy) hardware-in-the-loop tests in CI. I don't have bandwidth to maintain it for other use cases. If you need help or want to contribute big features feel free to ask, but a positive response (or a response at all) is not guaranteed.

## Operation Modes
Teleprobe has three operation modes - local, server and client.

### Local Mode
Local mode is intended to be run on the machine where the MCU is connected, usually for debugging purposes.

List available probes:
```
teleprobe local list-probes
```

Run an elf on available probe:
```
teleprobe local run --elf test_max31865 --chip STM32H743BITx --probe 0483:374e
```

### Server Mode
Starts a HTTP server responsible for remotely flashing connected MCUs.

```
teleprobe server
```

The server listens on port `8080` by default, this can be changed via the `--port XX` option.
Logging verbosity can be adjusted via `RUST_LOG` environment variable.

#### Configuration
Server configuration is stored in a file called `config.yaml`. It contains both configuration of authentication (bearer tokens or OIDC) and definition of targets.

An example configuration can be seen in the following snippet:
```
auths:
  - !oidc
    issuer: https://token.actions.githubusercontent.com
    rules:
      - claims:
          iss: https://token.actions.githubusercontent.com
          aud: https://github.com/embassy-rs
          repository: embassy-rs/embassy
  - !token
    token: hN6e2msKlqsW9smsjyF5I7xmiuPQij0O
targets:
  - name: nucleo-stm32f429zi
    chip: stm32f429zitx
    probe: 0483:374b:0670FF495254707867252236
```

### Client Mode
Client mode is useful for interfacing with the server seamlessly.

Request available target MCUs:
```
teleprobe client --host http://SERVER_ADDRESS:8080 --token ACCESS_TOKEN list-targets
```

Run a binary on target MCU:
```
teleprobe client --host 'http://SERVER_ADDRESS:8080' --token ACCESS_TOKEN run --elf test_max31865 --target nucleo
```

The `ACCESS_TOKEN` and host can be also stored into `TELEPROBE_TOKEN` and `TELEPROBE_HOST` environment variables.

## Preparing MCU binaries

### Automatic target discovery

Using teleprobe-meta crate, it's possible to embed various metadata into target binary,
including target name and timeout. This allows running binaries just by calling `run <ELF>`
without additional flags.

### Running from RAM

Before uploading binary to target, teleprobe analyzes it to see whether it's possible
to run it from RAM instead of uploading it to MCU's internal flash and running from there.

In order to achieve that, target binary needs to be linked with a modified linker script
which puts data into RAM instead of FLASH.

* Cortex-M: [`link_ram_cortex_m.x`](link_ram_cortex_m.x)

Then include the renamed `link_ram.x` linker script  via `build.rs`:

```rust
fn main() -> Result<(), Box<dyn Error>> {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("link_ram.x"), include_bytes!("link_ram.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rerun-if-changed=link_ram.x");
    println!("cargo:rustc-link-arg-bins=-Tlink_ram.x");

    // ...

    Ok(())
}
```

## License

This work is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

