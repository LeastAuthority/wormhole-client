-- This file is part of hwormhole.

-- hwormhole is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- hwormhole is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with hwormhole.  If not, see <http://www.gnu.org/licenses/>.

{-# LANGUAGE OverloadedStrings #-}

module Main where

import Protolude

import qualified Data.Text.IO as TIO
import qualified Transit

import Options

main :: IO ()
main = do
  env <- Transit.prepareAppEnv appid "wordlist.txt" =<< commandlineParser
  result <- Transit.runApp Transit.app env
  either (TIO.putStrLn . show) return result
    where
      appid = "lothar.com/wormhole/text-or-file-xfer"
