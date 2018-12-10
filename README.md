[![Circle CI](https://circleci.com/gh/LeastAuthority/wormhole-client/tree/master.png?ghtoken=98e29d106176da58957f91ae408fb6499421be14)](https://circleci.com/gh/LeastAuthority/wormhole-client)

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
