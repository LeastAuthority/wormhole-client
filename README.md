[![Circle CI](https://circleci.com/gh/LeastAuthority/wormhole-client/tree/master.png?ghtoken=98e29d106176da58957f91ae408fb6499421be14)](https://circleci.com/gh/LeastAuthority/wormhole-client)

# A magic-wormhole client in Haskell

`hwormhole` is a haskell version of Brian Warner's [magic-wormhole][1] file
transfer program (also called `wormhole`) that uses the SPAKE2 based wormhole
protocol also created by him. We use Jonathan Lange's [Magic Wormhole haskell library][2]
to create this application that interoperates with the Python program that
Brian Warner provides.

This builds on the example application in the MagicWormhole library to
build a full fledged wormhole file transfer application that interoperates
with the `wormhole` application.

## Building

We need a forked version of `[haskell-magic-wormhole][3]` at the moment. This will
go away as soon as the changes in there are cleaned up and reviewed by the upstream.

I use `cabal` for my projects. Cabal 2.2 has come a long way and is a pleasure to use.
To use our version of `haskell-magic-wormhole`, I do the following:

1. create a top level directory called `wormhole`
2. `cd wormhole`
3. `git clone https://github.com/vu3rdd/haskell-magic-wormhole -b file-transfer`
4. `git clone https://github.com/vu3rdd/wormhole-client`
5. create a file called `cabal.project` that has just one line:
```
packages: wormhole-client haskell-magic-wormhole
```

That's it. Now, we use the `new-*`commands of `cabal-install` to download, build
and install dependencies, test our code and run the executables.

```
cabal new-build hwormhole
cabal new-test hwormhole
cabal new-run hwormhole:hwormhole-exe -- send --text foobar
```

There is a `--help` command. It works for subcommands as well.

## What works at the moment

- Message send and receive
- Completion support for typing in the code
- File sending to the Python `wormhole` client

## What's next?

Please see `todo.org` for the full set of things to do to make it a full
application.

[1]: https://github.com/warner/magic-wormhole
[2]: https://github.com/LeastAuthority/haskell-magic-wormhole
[3]: https://github.com/vu3rdd/haskell-magic-wormhole
