[![Circle CI](https://circleci.com/gh/vu3rdd/wormhole-client/tree/master.png?ghtoken=98e29d106176da58957f91ae408fb6499421be14)](https://circleci.com/gh/vu3rdd/wormhole-client)

# A magic-wormhole client in Haskell

`hwormhole` is a haskell version of Brian Warner's [magic-wormhole][1] file
transfer program (also called `wormhole`) that uses the SPAKE2 based wormhole
protocol. We use Jonathan Lange's [Magic Wormhole haskell library][2] to 
create this application that interoperates with the Python program that
Brian Warner provides.

This builds on the example application in the MagicWormhole library to
build a full fledged wormhole file transfer application that interoperates
with the Python `wormhole` application.

## Building

We need a version of [`haskell-magic-wormhole`][2] from git at the moment. This will
go away as soon as a new release is uploaded into hackage.

In order to build the code, we need Cabal 2.2 at the moment. A stack yaml file will
be provided soon, for those who use `stack`.

The build steps using the cabal project (supported in cabal 2.x) is as follows:

1. create a top level directory called `wormhole`
2. `cd wormhole`
3. `git clone https://github.com/LeastAuthority/haskell-magic-wormhole`
4. `git clone https://github.com/LeastAuthority/wormhole-client`
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
cabal new-run hwormhole:hwormhole-exe -- send /path/to/foobar.txt
cabal new-run hwormhole:hwormhole-exe -- receive
```

There is a `--help` command. It works for subcommands as well.

## What works at the moment

- Message send and receive
- Completion support for typing in the code
- File sending to the Python `wormhole` client

## What's next?

Please see `todo.org` for the full set of things to do to make it a full
application.

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
