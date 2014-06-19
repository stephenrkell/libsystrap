module Generators where

import Data.List(intercalate)

import Parse

indent :: String
indent = "        "

genArgStruct :: Sys -> [Char]
genArgStruct sys = "struct sys_"
                ++ (sys_name sys)
                ++ "_args {\n"
                ++ (intercalate "\n" $ map genPaddedArg (arguments sys))
                ++ "\n};"
        where genPaddedArg a = indent ++ "PADDED("
                      ++ arg_type a
                      ++ " "
                      ++ arg_name a
                      ++ ")"

genBigStruct :: [Sys] -> [Char]
genBigStruct ss =
        "struct syscall {\n"
             ++ indent ++ "PADDED(int syscall_number)\n"
             ++ indent ++ "union {\n"
                     ++ (intercalate "\n" $ map declArg ss)
             ++ "\n" ++ indent ++ "} syscall_args;\n};"
        where declArg (Sys n _) = indent ++ indent
                               ++ "struct sys_" ++ n ++ "_args "
                               ++ "sys_" ++ n ++ "args;"

genStructFile :: [Sys] -> [Char]
genStructFile ss = (intercalate "\n" $ map genArgStruct ss) ++ "\n\n" ++ genBigStruct ss

-- XXX At this time, this does nothing and is a bit stupid.
genHandler :: Sys -> [Char]
genHandler s = case sys_name s of
        -- Leave the possibility of special generation according to the name.
        _ -> intercalate "\n" [header, struct_shape, "\n{", body, "}"]
        where len = length (arguments s)
              header       = "static long int do_"
                          ++ sys_name s
                          ++ " (struct generic_syscall *gsp)"
              struct_shape = "/*\n * struct sys_"
                          ++ sys_name s
                          ++ "_args {\n * "
                          ++ intercalate ";\n * " (map genArg (arguments s))
                          ++ ";\n * };\n */"
              genArg a     = indent ++ arg_type a ++ " " ++ arg_name a
              body         = indent ++ intercalate ("\n" ++ indent) (
                                   ["long int ret;"]
                                ++ save_args (arguments s) 0
                                ++ ["ret = do_syscall"
                                 ++ (show len)
                                 ++ "(gsp);"]
                                ++ restore_args (arguments s) 0
                                ++ ["return ret;"])
              save_args [] _       = []
              save_args (a:as) num = case (arg_space a) of
                User -> ("REPLACE_ARGN("
                                ++ show num
                                ++ ", 0 /* XXX length */);")
                        : save_args as (num + 1)
                _    -> save_args as (num + 1)
              restore_args [] _ = []
              restore_args (a:as) num = case (arg_space a) of
                User -> ("RESTORE_ARGN("
                        ++ show num
                        ++ ", 0 /* XXX length */);")
                        :restore_args as (num + 1)
                _   -> restore_args as (num + 1)


genTab :: [Sys] -> [Char]
genTab ss = "long int (*syscalls[SYSCALL_MAX])(struct generic_syscall *) = {\n"
                ++ (intercalate "\n" $ map decl ss) ++ "\n};"
                where decl s = indent ++ "DECL_SYSCALL(" ++ sys_name s ++ ")"

genHandlerFile ss = (intercalate "\n" $ map genHandler ss) ++ "\n\n" ++ genTab ss
