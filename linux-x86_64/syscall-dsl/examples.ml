let struct_tms =
        Struct("struct_tms",
               [("tms_utime",  Modifiable_yes, Basic(UInt));
                ("tms_stime",  Modifiable_yes, Basic(UInt));
                ("tms_cutime", Modifiable_yes, Basic(UInt));
                ("tms_cstime", Modifiable_yes, Basic(UInt));
               ]);;

let tms_fp tms = Struct(tms, struct_tms);;

let sys_times = {
        name = "sys_times";
        number = 0;
        arguments = [("buf", Pointer((), struct_tms))];
        footprint = tms_fp Argument("buf");
}

let struct_iovec =
        Struct("struct_iovec",
               [("iov_base", Modifiable_yes, Pointer((), Basic(UInt)));
                ("iov_len",  Modifiable_no,  Basic(UInt));
               ]);;

let iovec_fp iovec = Separation_star([
        Struct(iovec, struct_iovec);
        Array(Member_access(iovec, "iov_base"), Basic(UInt),
                        LValue(Member_access(iovec, "iov_len")));
        ]);;

let struct_msghdr =
    Struct("struct_msghdr",
           [("msg_name",       Modifiable_yes, Pointer((), Basic(UInt)));
            ("msg_namelen",    Modifiable_no,  Basic(UInt));
            ("msg_iov",        Modifiable_yes, Pointer((), struct_iovec));
            ("msg_iovlen",     Modifiable_no,  Basic(UInt));
            ("msg_control",    Modifiable_yes, Pointer((), Basic(UInt)));
            ("msg_controllen", Modifiable_no,  Basic(UInt));
            ("msg_flags",      Modifiable_no,  Basic(Int));
           ]);;

let msghdr_fp msghdr = Separation_star([
    Struct(msghdr, struct_msghdr);
    Separation_star([
        Array(Member_access(msghdr, "msg_name"),
              Basic(UInt),
              LValue(Member_access(msghdr, "msg_namelen")));
        Indexed_separation_star(
            "i", Int(0), LValue(Member_access(msghdr, "msg_iovlen")),
            iovec_fp Array_access(
                Member_access(msghdr, "msg_iov"), struct_iovec, Index("i")));
]);]);;

let sys_recvmsg = {
        name = "sys_recvmsg";
        number = 0;
        arguments = [("sockfd", Basic(Int));
                     ("msg",    Pointer((), struct_msghdr));
                     ("flags",  Basic(Int));
                    ];
        footprint = msghdr_fp Argument("msg");
}
