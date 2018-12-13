[![Circle CI](https://circleci.com/gh/LeastAuthority/wormhole-client/tree/master.png?ghtoken=98e29d106176da58957f91ae408fb6499421be14)](https://circleci.com/gh/LeastAuthority/wormhole-client)

# A magic-wormhole client in Haskell

`hwormhole` is a haskell version of Brian Warner's [magic-wormhole][1] file
transfer program (also called `wormhole`) that uses the SPAKE2 based wormhole
protocol. Magic-wormhole allows the user to securely transfer a file from
one computer to another, anywhere in the world. This program interoperates
with the Python implementation of magic-wormhole program. We support transferring
short text messages, files and directories.

## Building

### On Unix

You will need `cabal-install` version 2.2 or above that supports the `new-*` commands.

`git clone https://github.com/LeastAuthority/wormhole-client`

and

```
cd wormhole-client
cabal new-build hwormhole
cabal new-test hwormhole
cabal new-run hwormhole:hwormhole-exe -- send --text foobar
cabal new-run hwormhole:hwormhole-exe -- send /path/to/foobar.txt
cabal new-run hwormhole:hwormhole-exe -- receive
```
There is a `--help` command. It works for subcommands as well.

### On Windows

1. Download `libsodium` [pre-built library].
2. Install Visual Studio 2015 redistributable to install `vcruntime140.dll` needed by `libsodium.dll`.
3. On a command line shell (assuming `ghc` and `cabal-install` are installed and are already in the `PATH`), `set LIBRARY_PATH=C:\path\to\dir\containing\libsodium.dll\`
4. Now, follow the steps above for Unix.

## Development

Please check the `Changelog.md` file for the latest changes.

## What's next?

Adding support for sending via Tor connections is the next important task.

## Feedback

This is my dig at creating a "production" haskell application. I welcome all kinds
of feedback. My email ID can be found in the `hwormhole.cabal` file in the maintainer
field or from [my github page][3]. I also hang out on the IRC at `#magic-wormhole`
on freenode with handle `rkrishnan`.

[1]: https://github.com/warner/magic-wormhole
[2]: https://github.com/LeastAuthority/haskell-magic-wormhole
[3]: https://github.com/vu3rdd

## Thanks

We wish to thank NLnet Foundation for a grant that enabled us to work on this project.
