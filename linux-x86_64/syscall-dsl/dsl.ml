type argument_name = string  (* the argument names from the
                              * syscalls.h header *)

type member_name = string (* the C structure member names we're using *)
type index_name  = string

type struct_tag = string
type union_tag  = string
type member_id  = string
type qualifiers = string

type modifiable =
        | Modifiable_yes
        | Modifiable_no

type basicType =
        | Int
        | UInt
        | Int8
        | UInt8
        | Int16
        | UInt16
        | Int32
        | UInt32
        | Int64
        | UInt64

type ctype =
        | Void
        | Basic         of basicType
                (* use whatever variants of int you need *)
        | Array         of ctype * expression
        | Function      of ctype * (qualifiers * ctype) list *
                                bool (* true for variadic *)
                 (* Maybe not enough: AilTypes.qualifiers *)
        | Pointer       of qualifiers * ctype
        | Atomic        of ctype
        | Struct        of struct_tag   *
                                (member_id * modifiable * ctype) list
        | Union         of union_tag    *
                                (member_id * modifiable * ctype) list

and lvalue =
        | Argument              of argument_name
        | Array_access          of lvalue * ctype * expression
        | Pointer_deref         of lvalue * ctype
        | Member_access         of lvalue * member_name
        | Member_deref          of lvalue * member_name

and expression =
        | Int           of int
        | Index         of index_name
        | LValue        of lvalue
        | Sizeof        of ctype
        | Sum           of expression * expression
        | Product       of expression * expression
(*      | ...   *)

type footprint =
        | Void
        | Basic                         of lvalue * ctype
        | Struct                        of lvalue * ctype
        | Array                         of lvalue * ctype * expression
        | Separation_star               of footprint list
        | Indexed_separation_star       of index_name                   *
                                                expression (*base*)     *
                                                expression (*count*)    *
                                                footprint

type syscall_data = {
        name      : string;
        number    : int;
        arguments : (argument_name * ctype) list;
        footprint : footprint;
}
