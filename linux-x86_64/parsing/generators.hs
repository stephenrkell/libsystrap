module Generators where

import Data.List(intercalate)

import Parse

indent = "        "

genArgStruct :: Sys -> [Char]
genArgStruct sys =
        "struct sys_" ++ (sys_name sys) ++ "_args {\n"
                ++ (intercalate "\n" $ map genPaddedArg (args sys))
        ++ "\n};"
        where genPaddedArg :: Argument -> [Char]
              genPaddedArg a = indent ++ "PADDED("
                      ++ (from_mut $ mut a)
                      ++ argtype a ++ " "
                      ++ argname a
                      ++ ")"
                      where from_mut m = case m of
                              Const -> "const "
                              _     -> ""

genBigStruct :: [Sys] -> [Char]
genBigStruct ss =
        "struct syscall {\n"
             ++ indent ++ "PADDED(int syscall_number)\n"
             ++ indent ++ "union {\n"
                     ++ (intercalate "\n" $ map gen_arg ss)
             ++ "\n" ++ indent ++ "} syscall_args;\n};"
        where gen_arg (Sys _ n _) = indent ++ indent ++ "struct sys_" ++ n ++ "_args "
                                        ++ "sys_" ++ n ++ "args;"

genStructFile :: [Sys] -> [Char]
genStructFile ss = (intercalate "\n" $ map genArgStruct ss) ++ "\n\n" ++ genBigStruct ss

-- XXX At this time, this does nothing and is a bit stupid.
genHandler :: Sys -> [Char]
genHandler (Sys gt n as) = case gt of
        None -> ""
        Stub -> "/*\n"
                ++ "* TODO: This handler is a stub and should be edited manually.\n"
                ++ " */\n"
                ++ header ++ "\n" ++ body
        Auto -> header ++ "\n" ++ body
        where len = length as
              header = "static long int do_" ++ n ++ " (struct generic_syscall *gsp)"
              body   = "{\n" ++ indent ++ "return do_syscall" ++ (show len) ++ "(gsp);\n}"

genTab :: [Sys] -> [Char]
genTab ss = "long int (*syscalls[SYSCALL_MAX])(struct generic_syscall *) = {\n"
                ++ (intercalate "\n" $ map decl ss) ++ "\n};"
                where decl s = indent ++ "DECL_SYSCALL(" ++ sys_name s ++ ")"

genHandlerFile ss = (intercalate "\n" $ map genHandler ss) ++ "\n\n" ++ genTab ss
