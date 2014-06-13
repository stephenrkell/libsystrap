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
                     ++ (intercalate "\n" $ map declArg ss)
             ++ "\n" ++ indent ++ "} syscall_args;\n};"
        where declArg (Sys _ n _) = indent ++ indent ++ "struct sys_" ++ n ++ "_args "
                                        ++ "sys_" ++ n ++ "args;"

genStructFile :: [Sys] -> [Char]
genStructFile ss = (intercalate "\n" $ map genArgStruct ss) ++ "\n\n" ++ genBigStruct ss

-- XXX At this time, this does nothing and is a bit stupid.
genHandler :: Sys -> [Char]
genHandler (Sys gt n as) = case gt of
        None -> ""
        Stub -> "/*\n"
             ++ " * TODO: This handler is a stub and should be edited manually.\n"
             ++ " */\n" ++ genHandler (Sys Auto n as)
        Auto -> header ++ "\n" ++ struct_shape ++ "\n{\n" ++ body ++ "\n}"
        where len = length as
              header = "static long int do_" ++ n ++ " (struct generic_syscall *gsp)"
              struct_shape =
                        "/*\n * struct sys_" ++ n ++ "_args {\n * "
                                ++ (intercalate ";\n * " $ map genArg as)
                        ++ ";\n * };\n */"
              genArg a = indent ++ (from_mut $ mut a)
                      ++ argtype a ++ " " ++ argname a
                      where from_mut m = case m of
                              Const -> "const "
                              Mut   -> "mut "
                              _     -> ""
              body   = indent ++ intercalate ("\n" ++ indent) (
                                ["long int ret;"]
                             ++ save_args as 0
                             ++ ["ret = do_syscall" ++ (show len) ++ "(gsp);"]
                             ++ restore_args as 0
                             ++ ["return ret;"])
              save_args [] _ = []
              save_args (x:xs) num = case (mut x) of
                Mut -> ("REPLACE_ARGN("
                                ++ show num
                                ++ ", 0 /* XXX length */);")
                        : save_args xs (num + 1)
                _   -> save_args xs (num + 1)
              restore_args [] _ = []
              restore_args (x:xs) num = case (mut x) of
                Mut -> ("RESTORE_ARGN("
                        ++ show num
                        ++ ", 0 /* XXX length */);")
                        :restore_args xs (num + 1)
                _   -> restore_args xs (num + 1)


genTab :: [Sys] -> [Char]
genTab ss = "long int (*syscalls[SYSCALL_MAX])(struct generic_syscall *) = {\n"
                ++ (intercalate "\n" $ map decl ss) ++ "\n};"
                where decl s = indent ++ "DECL_SYSCALL(" ++ sys_name s ++ ")"

genHandlerFile ss = (intercalate "\n" $ map genHandler ss) ++ "\n\n" ++ genTab ss
