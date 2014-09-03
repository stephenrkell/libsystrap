import System.IO

import qualified Parse        as P
import qualified Generators   as G
import qualified ParseStructs as PS
import qualified GenStructs   as GS

main = do inh <- openFile "syscalls.h" ReadMode
          contents <- hGetContents inh
          let parsed = P.parseFile contents
              in case parsed of
                      Right x -> do   putStrLn $ G.genOCaml x
                      Left _  -> putStrLn $ "Could not parse."
          hClose inh
          inh' <- openFile "structs.h" ReadMode
          contents' <- hGetContents inh'
          let parsed = PS.parseFile contents'
                in case parsed of
                        Right x -> do putStrLn $ GS.genOCaml x
                        _       -> putStrLn $ "Could not parse."
          hClose inh'
