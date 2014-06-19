{-# LANGUAGE NoMonomorphismRestriction #-}

module Parse(parseFile
            ,Sys(..)
            ,Argument(..)
            ,Space(..)
            ) where

import Text.ParserCombinators.Parsec
import Data.List(intercalate)
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

-- An argument to a syscall can be tagged __user, in which case it means
-- the memory belongs to userspace and is potentially modified. We want
-- to keep track of those.
--
data Space = User | Copy deriving (Show)

data Argument = Argument {arg_space :: Space
                         ,arg_type  :: String
                         ,arg_name  :: String
                         } deriving (Show)

data Sys = Sys {sys_name  :: String
               ,arguments :: [Argument]
               } deriving (Show)

-- XXX Obviously this accepts invalid C symbols, but fixing it is low priority.
c_symbol = many1 $ try alphaNum <|> char '_'

c_type = (try $ do struct      <- string "struct"
                   spaces
                   struct_name <- c_symbol
                   return $ struct ++ " " ++ struct_name)
     <|> (try c_symbol)

c_modifier = (try $ string "signed")
         <|> (try $ string "unsigned")
         <|> (try $ string "const")
         <|> (try $ string "volatile")
         <|> (try $ string "auto")
         <|> (try $ string "register")
         <|> (try $ string "static")
         <|> (try $ string "extern")


file = do maybe_syscalls <- sepBy line (char '\n')
          return $ catMaybes maybe_syscalls
        where line = (try $ header     >>= return . Just)
                 <|> (try $ ignoreline >>  return Nothing)
              ignoreline = many $ noneOf "\n"

header = do spaces
            _    <- string "asmlinkage long sys_"
            name <- c_symbol
            spaces
            void <- option [] $ try $ string "(void)"
            ret  <- case void of
                   "(void)" -> return $ Sys name []
                   _        -> do args <- between
                                         (char '(') (char ')') parseArgs
                                  return $ Sys name args
            _ <- string ";"
            return ret
        where parseArgs = sepBy parseArg sepArg
              sepArg = (try (string ",\n") <|> try (string ","))


-- The description of an argument can take various forms. In the absence
-- of knowledge about the types, we must be clever if we want to parse
-- them correctly.

parseArg = (try pointerWithNoName)
       <|> (try pointerWithName)
       <|> (try nonPointerWithName)
       <|> (try nonPointerWithNoName)

pointerWithNoName = do x <- many1 $
                        do spaces
                           y     <- endBy c_symbol spaces
                           star  <- string "*"
                           return $ y ++ [star]
                       y    <- return $ concat x
                       user <- return $ if "__user" `elem` y
                                                 then User
                                                 else Copy
                       argtype <- return $ intercalate " " y
                       return $ Argument user argtype ""

pointerWithName = do x    <- many1 . try $
                      do y <- many $ try (spaces >> c_symbol)
                         spaces
                         star <- string "*"
                         return $ y ++ [star]
                     spaces
                     argname <- c_symbol
                     y    <- return $ concat x
                     user <- return $ if "__user" `elem` y
                                               then User
                                               else Copy
                     argtype <- return $ intercalate " " y
                     return $ Argument user argtype argname

nonPointerWithNoName = do spaces
                          modlist <- endBy c_modifier spaces
                          modifiers <- case modlist of
                                  [] -> return ""
                                  _  -> return $ (intercalate " " modlist) ++ " "
                          argtype <- c_type
                          return $ Argument Copy
                                (modifiers ++ argtype) ""

nonPointerWithName = do spaces
                        modlist <- endBy c_modifier spaces
                        modifiers <- case modlist of
                                [] -> return ""
                                _  -> return $ (intercalate " " modlist) ++ " "
                        argtype <- c_type
                        spaces
                        argname <- c_symbol
                        return $ Argument Copy
                              (modifiers ++ argtype) argname

parseFile :: [Char] -> Either ParseError [Sys]
parseFile = parse file "(unknown)"
