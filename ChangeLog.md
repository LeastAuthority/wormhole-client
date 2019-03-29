# Revision history for haskell-magic-wormhole-client

## 0.2.0.1  -- 2019-03-29

* Get rid of the dependency on the 'hex' library.
* PGP wordlist is an external dependency now, the wordlist has been
  removed. 'Env' does not carry the wordlist around anymore.
* Expose 'App.send' and 'App.receive' functions.

## 0.2.0.0  -- 2018-12-12

* Fix a bug which shows up as a failed hwormhole to hwormhole transfer,
  at the same time works fine with python magic-wormhole client.

## 0.1.0.0  -- 2018-12-10

* First version of the haskell port of magic-wormhole client.
* The client can send and receive text messages, files and directories.
* Supports sending to local computers or remote ones via relay.
* Interoperable with the reference Brian Warner's Python client.
* Ability to select custom transit server or relay server.
* Completion help while typing the code at the receiver end.
