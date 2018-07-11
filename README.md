# A magic-wormhole client in Haskell

`hwormhole` is a haskell version of Brian Warner's [magic-wormhole][1] file
transfer program (also called `wormhole`) that uses the SPAKE2 based wormhole
protocol also created by him. We use Jonathan Lange's [Magic Wormhole haskell library][2]
to create this application that interoperates with the Python program that
Brian Warner provides.

This builds on the example application in the MagicWormhole library to
build a full fledged wormhole file transfer application that interoperates
with the `wormhole` application.

## What works at the moment

- Message send and receive
- Completion support for typing in the code
- File sending to the Python `wormhole` client

## What's next?

Please see `todo.org` for the full set of things to do to make it a full
application.

[1]: https://github.com/warner/magic-wormhole
[2]: https://github.com/LeastAuthority/haskell-magic-wormhole
