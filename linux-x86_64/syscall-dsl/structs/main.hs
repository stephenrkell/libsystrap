import System.IO

import ParseStructs
import GenStructs

main = do inh' <- openFile "structs.h" ReadMode
          contents' <- hGetContents inh'
          let parsed = parseFile contents'
                in case parsed of
                        Right x -> do putStrLn $ genOCamlStruct x
                                      putStrLn ""
                                      putStrLn $ genOCamlFootprint x
                        _       -> putStrLn $ "Could not parse."
          hClose inh'
