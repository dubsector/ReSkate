# Signing launcher.json

Every release carries `launcher.json`, which pins the launcher, `ReSkate.dll`, DepotDownloader,
the game build and the servers by size and SHA-256. Release builds also check a
[minisign](https://jedisct1.github.io/minisign/) signature of it, attached to the same release as
`launcher.json.minisig`. A release whose config is unsigned, or signed by another key, is not
used: the launcher keeps its current files and says the release check is unavailable.

## The release key

Make the key once, on the machine that signs releases, and keep the secret key off the repository
and off CI:

```
minisign -G -p reskate-release.pub -s reskate-release.key
```

The second line of `reskate-release.pub` (it starts with `RW`) is the public key. Release builds
take it as a CMake option:

```
cmake --preset vs2022-x64 -DDINGOSDK_LAUNCHER_AUTO_UPDATE=ON -DDINGOSDK_RELEASE_PUBLIC_KEY=RW...
```

A build with `DINGOSDK_LAUNCHER_AUTO_UPDATE=ON` and no key fails to configure. Local builds leave
the key empty and use the config unsigned, so a test config needs no signature there.

Changing the key means the launchers already installed refuse every config signed with the new
one. Keep a backup of the secret key and its password.

## Each release

1. Write `launcher.json`. `depot_downloader` needs `exe_sha256` beside `sha256`: the SHA-256 of
   the `DepotDownloader.exe` inside the zip, which the launcher checks before every run.
2. Sign it and check the signature against the public key the release was built with:

   ```
   python contrib/sign_launcher_json.py launcher.json --secret-key reskate-release.key --public-key RW...
   ```

3. Attach `launcher.json` and `launcher.json.minisig` to the release together. Changing
   `launcher.json` afterwards, even its whitespace, means signing it again.

The dedicated server (Windows and Linux) checks the same signature before it updates itself.

To try a config before it is attached, point `RESKATE_LAUNCHER_CONFIG_FILE` at it and run a local
build. Release builds ignore that variable and read only the release's own `launcher.json`.
