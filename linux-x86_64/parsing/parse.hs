{-# LANGUAGE NoMonomorphismRestriction #-}

module Parse where

import Text.ParserCombinators.Parsec
import Control.Monad(liftM)
import Data.List(intercalate, delete)
import Data.Maybe(catMaybes)

-- We mean to parse a syscall header with the general form
--      asm lkinage long sys_ ## name ## (type0 arg0, ...);
-- with line breaks possibly happening between arguments.
--
-- The general form of an argument is
--      [type_modifier] type [__user] [*]argname
--
-- One example can be:
--      asmlinkage long sys_rt_sigaction(int,
--      				 const struct sigaction __user *,
--      				 struct sigaction __user *,
--      				 size_t);
--
-- Where __user indicates whether the memory belongs to userspace
-- (and therefore is potentially affected by the execution of the system
-- call).
--
-- We want to keep track of the system call's name, and for each
-- argument:
--           - its name
--           - its type with type modifiers (not including __user)
--           - whether it belongs to userspace

data Space = User | Copy deriving (Show)

data Argument = Argument {sp      :: Space
                         ,argtype :: String
                         ,argname :: String
                         } deriving (Show)

data Sys = Sys {sys_name :: String
               ,args     :: [Argument]
               } deriving (Show)

-- XXX Obviously this accepts invalid C symbols, but fixing it is low priority.
c_symbol = many1 $ try alphaNum <|> char '_'
spaces1  = many1 space

-- file = endBy line (try (string ";\n") <|> try (string ";"))
file = do maybe_syscalls <- endBy blabla (char '\n')
          return $ catMaybes maybe_syscalls
        where blabla = do ret <- (try $ do l <- line; return $ Just l) <|> (try $ do many $ noneOf "\n"; return Nothing); return ret

line = do spaces
          string "asmlinkage long sys_"
          name <- c_symbol
          spaces
          void <- option [] $ try $ string "(void)"
          ret <- case void of
                "(void)" -> return $ Sys name []
                _        -> do args <- between (char '(') (char ')') parseArgs
                               return $ Sys name args
          char ';'
          return ret


parseArgs = sepBy parseArg sepArg
        where sepArg   = (try (string ",\n") <|> try (string ","))

parseArg = do spaces
              types <- many1 $ try c_symbol_space
              star  <- (try $ string "*") <|> string ""
              argname  <- c_symbol
              argspace <- return $ if ("__user" `elem` types)
                                       then User else Copy
              argtype  <- return $ (intercalate " " (delete "__user" types))
                                       ++ star
              return $ Argument argspace argtype argname
           where  c_symbol_space = do ret <- c_symbol
                                      spaces1
                                      return $ ret

parseFile = parse file "(unknown)"
text="asmlinkage long sys_gettid(void);\nIGNORE THIS LINE\nasmlinkage long sys_time(mut time_t __user *tloc);\nasmlinkage long sys_stime(const time_t __user *tptr);\nasmlinkage long sys_gettimeofday(mut struct timeval __user *tv,\nmut struct timezone __user *tz);"

parseLine = parse line "(not a line)"

Right parsed = parseFile text
