# TOS Node Console

Client for the node's control port. Its commands, argument syntax, output
and exit codes are those of the reference validator console, so scripts
written for one work with the other.

## Usage

```bash
console -a <ip:port> -k <client key file> -p <server public key file> -c "<command>" [-c "<command>" ...] [-t <seconds>]
console -C console.json -c "<command>" [-c "<command>" ...] [-t <seconds>]
```

- `-a`, `-k`, `-p` — the control port address, the console's private key
  file and the server's public key file. The key files hold the serialized
  key, as the reference engine writes them (`keyring/` files and
  `*.pub` files).
- `-C` — instead of `-a`/`-k`/`-p`: a settings file (see below).
- `-c` — a command to run. With one or more `-c` the console runs them in
  order and exits; without, it reads commands from standard input.
- `-t` — a deadline in seconds for the whole run; when it passes the
  console exits with code 7.
- `-v` — log verbosity, 0 to 9. `-r`/`-R` are accepted; there is no line
  editor.

The console first prints the address and both key hashes, then
`conn ready` once connected, and then each command's output.

Exit codes in batch mode:

- `0` — every command succeeded, or `quit` ran (later commands do not run);
- `2` — a command failed: the console prints
  `Failed <command> query: [Error : <code> : <message>]` and does not run
  the rest;
- `7` — the `-t` deadline passed.

A line that is not a command prints `unknown command '<name>'`. If it is
the last one the console exits with `0`; otherwise, as the reference
console, it runs nothing more and waits for the deadline.

Arguments are words separated by spaces. A key hash is 64 hex digits or 44
base64 characters. Numbers must be written exactly (no sign, no leading
zeros). Data for `sign` is hex.

## Settings file

```json
{
    "config": {
        "server_address": "127.0.0.1:4924",
        "server_key": {
            "type_id": 1209251014,
            "pub_key": "cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8="
        },
        "client_key": {
            "type_id": 1209251014,
            "pvt_key": "oEivbTDjSOSCgooUM0DAS2z2hIdnLw/PT82A/OFLDmA="
        }
    }
}
```

- `server_address` — the control port address.
- `server_key` — the server's Ed25519 public key (`type_id` `1209251014`).
- `client_key` — the console's Ed25519 private key. Without it the console
  uses a new key, which the server will not know.

## Commands

| Command | Does | Prints |
|---|---|---|
| `get-time` | server time | `received validator time: time=<unixtime>` |
| `help [command]` | lists the commands, or one | the help lines |
| `license` | | the license text |
| `quit` | closes the console | |
| `new-key` | creates a key pair on the server | `created new key <HASH>` |
| `import-f <file>` | imports a private key file | `imported key <HASH>` |
| `export-pub <keyhash>` | exports a public key | `got public key: <base64 of the serialized key>` |
| `export-pubf <keyhash> <file>` | exports a public key to a file | `got public key` |
| `sign <keyhash> <hex data>` | signs data | `got signature <base64>` |
| `sign-f <keyhash> <infile> <outfile>` | signs a file | `got signature` |
| `export-all-private-keys <directory>` | exports every key, encrypted to a key the console makes for the run; each goes to `<directory>/<HASH>` | `exported <n> private keys`, a `pubkey_hash <HASH>` line per key, `written all files to <directory>` |
| `add-adnl <keyhash> <category>` | uses the key as an ADNL address; category 0 to 15 | `success` |
| `add-perm-key <keyhash> <election-date> <expire-at>` | adds a validator permanent key | `success` |
| `add-temp-key <permkeyhash> <keyhash> <expire-at>` | adds a validator temporary key | `success` |
| `add-validator-addr <permkeyhash> <keyhash> <expire-at>` | adds a validator ADNL address | `success` |
| `del-adnl <keyhash>` | removes an unused ADNL address | `success` |
| `del-perm-key <keyhash>` | removes a validator permanent key | `success` |
| `del-temp-key <permkeyhash> <keyhash>` | removes a validator temporary key | `success` |
| `del-validator-addr <permkeyhash> <keyhash>` | removes a validator ADNL address | `success` |
| `get-config` | downloads the node configuration | the JSON between dashed lines |
| `set-verbosity <0..10>` | changes the node's log level | `success` |
| `get-stats` | node statistics | a `<name>`, three tabs, `<value>` line per item |
| `sign-shard-overlay-cert <wc>:<shard> <keyhash> <expire-at> <max-size> <outfile>` | signs a shard overlay certificate | `saved certificate` |
| `import-shard-overlay-cert <wc>:<shard> <keyhash> <certfile>` | imports a shard overlay certificate | `successfully sent certificate to overlay manager` |
| `set-ext-messages-broadcast-disabled <0\|1>` | stops or resumes broadcasting external messages | `success` |
| `add-custom-overlay <file>` | adds a custom overlay from a JSON file | `success` |
| `del-custom-overlay <name>` | removes a custom overlay | `success` |
| `show-custom-overlays` | lists the custom overlays | the overlays, their nodes and sender shards |

Times are Unix times. `<HASH>` is printed as 64 upper-case hex digits. A
shard is `<wc>:<16 hex digits>`, `(<wc>,<16 hex digits>)` or a workchain
and a signed 64-bit shard as two words.

A custom overlay file:

```json
{
    "name": "ov1",
    "nodes": [
        {"adnl_id": "<base64>", "msg_sender": true, "msg_sender_priority": 3, "block_sender": false}
    ],
    "sender_shards": [{"workchain": 0, "shard": "-9223372036854775808"}],
    "skip_public_msg_send": false,
    "use_quic": false
}
```

Fields left out keep their defaults; numbers may be given as strings.
