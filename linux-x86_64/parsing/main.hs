import System.IO

import Parse
import Generators

main = do inh <- openFile "syscalls.h" ReadMode
          contents <- hGetContents inh
          let parsed = parseFile contents
              in case parsed of
                      Right x -> do putStrLn "do_syscalls.h:"
                                    putStrLn $ genStructFile x
                                    putStrLn "\nsyscalls_handlers.c:"
                                    putStrLn $ genHandlerFile x
                      Left _  -> putStrLn $ "Could not parse."
          hClose inh
