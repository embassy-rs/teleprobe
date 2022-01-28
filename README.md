# Teleprobe

Run MCU binaries on remote targets.

## Operation Modes
Teleprobe has three operation modes - local, server and client.

### Local Mode
Local mode is intended to be run on the machine where the remote MCU is connected, usually for debugging purposes.

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

#### Configuration
Server configuration is stored in a file called `config.yaml`. It contains both configuration of authentication (bearer tokens or OIDC) and definition of targets.

An example configuration can be seen in the following snippet:
```
auths:
  - oidc:
      issuer: https://token.actions.githubusercontent.com
      rules:
        - claims:
            iss: https://token.actions.githubusercontent.com
            aud: https://github.com/embassy-rs
            repository: embassy-rs/embassy
  - token:
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
