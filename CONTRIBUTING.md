# Contributing to JJWT

Thanks for your interest in improving JJWT! This guide covers building the project from source and
running its test suite. For usage documentation, see the [README](README.adoc).

## Reporting issues

- **Security vulnerabilities:** please follow [SECURITY.md](SECURITY.md) — do **not** open a public issue.
- **Bugs and feature requests:** open a [GitHub issue](https://github.com/jwtk/jjwt/issues) using the
  provided templates.

## Building and installing from source

JJWT builds with **JDK 17**+ (the compiled bytecode targets Java 8). Use the included Maven wrapper:

```bash
./mvnw install
```

The build is a multi-module Maven reactor (`api`, `impl`, `extensions`, `tdjar`, `bom`).

To run the full verification build (the same goal CI runs):

```bash
./mvnw verify
```

By default the tests run on a single JVM (your build JDK), which is all you need for most changes.
CI also runs them against a matrix of JDK vendors and versions. Testing locally against multiple JDK
versions is optional, but if you want to, install them and generate the Maven toolchains configuration
with the script in the repo:

```bash
./install-test-jdks.sh
```

New source files must carry the Apache 2.0 license header. Verify with `./mvnw license:check`
(use `./mvnw license:format` to add missing headers).

## SoftHSM and the PKCS11 tests

`Pkcs11Test` exercises JJWT against a real PKCS#11 token using
[SoftHSM](https://www.opendnssec.org/en/latest/softhsm/). Install SoftHSM and OpenSC:

```bash
# macOS
brew install softhsm opensc

# Debian/Ubuntu
sudo apt-get install -y softhsm2 opensc
```

Then configure SoftHSM using the helper script:

```bash
impl/src/test/scripts/softhsm configure   # creates the SoftHSM user config if needed
impl/src/test/scripts/softhsm import      # (re)creates the 'jjwt' token and imports test keys
```

After that, `./mvnw clean verify` will run the PKCS11 tests against the local token.

## Submitting changes

1. Fork the repository and create a branch off `main`.
2. Make your change, including tests, and ensure `./mvnw clean verify` passes.
3. Open a pull request against `main` describing the change and the motivation.
