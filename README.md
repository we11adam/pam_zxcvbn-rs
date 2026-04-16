# pam_zxcvbn-rs

`pam_zxcvbn-rs` is a PAM password module written in Rust. It checks new passwords with [`zxcvbn`](https://github.com/dropbox/zxcvbn) during `pam_chauthtok` and can either reject weak passwords or warn only for root-driven password changes.

The built module is a shared library named `libpam_zxcvbn.so`.

## Features

- evaluates password strength with `zxcvbn`
- supports score-based or entropy-based thresholds
- can retry password entry
- supports `try_first_pass`, `use_first_pass`, and `use_authtok`
- can restrict checks to local users from a passwd-style file
- can warn instead of enforce for root unless `enforce_for_root` is set

## Build

### Local build

You need a Rust toolchain and PAM development headers.

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y libpam0g-dev
cargo build --release
```

The output library will be:

```bash
target/release/libpam_zxcvbn.so
```

### Docker build

If you want a quick manual build without installing Rust on the host, the repository `Dockerfile` can export the compiled module directly to a local directory:

```bash
mkdir -p dist
docker build --output type=local,dest=./dist .
```

The exported file will be:

```bash
dist/libpam_zxcvbn.so
```

This is the shortest container-based path for a manual build.

By default, Docker builds for the host platform. For example:

- on Apple Silicon or other ARM64 hosts, the exported module will usually be `arm64`
- on x86_64 hosts, the exported module will usually be `amd64`

You can select the target platform explicitly:

```bash
mkdir -p dist-amd64
docker build --platform=linux/amd64 --output type=local,dest=./dist-amd64 .

mkdir -p dist-arm64
docker build --platform=linux/arm64 --output type=local,dest=./dist-arm64 .
```

### Build behavior and compatibility

- local `cargo build --release` produces a binary for your current Linux build environment
- the repository `Dockerfile` is a convenience build for manual use, not the release baseline
- GitHub release artifacts are built separately inside `manylinux2014` containers to keep a `glibc 2.17` baseline

If you need the broadest Linux compatibility, prefer the GitHub release assets over a locally built Docker image artifact.

## GitHub Releases

The release workflow publishes prebuilt Linux artifacts for:

- `amd64`
- `arm64`

These release artifacts are built inside `manylinux2014` containers so the resulting binaries stay compatible with a `glibc 2.17` baseline.

## PAM configuration

This module is intended for password change stacks and implements `pam_sm_chauthtok`.

Example snippet:

```pam
password requisite pam_zxcvbn.so retry=3 min_score=3
password required  pam_unix.so use_authtok sha512 shadow
```

Example with local-user-only checks:

```pam
password requisite pam_zxcvbn.so local_users_only local_users_file=/etc/passwd retry=3
password required  pam_unix.so use_authtok sha512 shadow
```

Example with additional zxcvbn inputs:

```pam
password requisite pam_zxcvbn.so retry=3 user_inputs=company,hostname,service
password required  pam_unix.so use_authtok sha512 shadow
```

Install the compiled library into your PAM module directory, commonly one of:

- `/lib/security`
- `/lib64/security`
- `/usr/lib/security`
- `/usr/lib64/security`

The exact path depends on your distribution.

## Module options

Supported options:

- `debug`: enable debug logging through PAM syslog
- `tries=N` or `retry=N`: number of password entry attempts, minimum `1`
- `min_score=N`: required zxcvbn score from `0` to `4`, default `3`
- `min_entropy=F`: required `guesses_log10` threshold; overrides `min_score` when set
- `user_inputs=a,b,c`: extra comma-separated strings passed to `zxcvbn` alongside the username; whitespace is trimmed and empty entries are ignored
- `enforce_for_root`: reject weak passwords even when the caller is root
- `local_users_only`: skip strength checks for users not present in the local passwd file
- `local_users_file=/path/to/passwd`: passwd-style file used by `local_users_only`
- `authtok_type=LABEL`: changes prompts such as `New LABEL password:`
- `try_first_pass`: try a cached password first, prompt if missing
- `use_first_pass`: require a cached password from a previous module
- `use_authtok`: require and reuse the password from a previous module

## Behavior notes

- on `PAM_PRELIM_CHECK`, the module returns success and does not prompt
- on `PAM_UPDATE_AUTHTOK`, the module validates the new password
- the password is checked against the username plus any configured `user_inputs`
- for non-local users with `local_users_only`, the module skips the strength check but still sets the password token for downstream modules
- when root changes a password without `enforce_for_root`, failed strength checks become warnings instead of hard failures
- `zxcvbn` evaluates only the first 100 characters of the password to bound its analysis cost; a long passphrase whose first 100 characters are weak will be judged weak regardless of what follows

## Development

Run tests with:

```bash
cargo test
```

## License

MIT
