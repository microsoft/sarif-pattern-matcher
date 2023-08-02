#define __allocator                         _SAL_L_Source_(__allocator, (), __inner_allocator)
#define __deallocate(kind)                  _SAL_L_Source_(__deallocate, (kind), _Pre_ __notnull __post_invalid)
#define __deallocate_opt(kind)              _SAL_L_Source_(__deallocate_opt, (kind), _Pre_ __maybenull __post_invalid)



__analysis_assume(IoControlCode == IOCTL_GPD_READ_PORT_UCHAR || \
    IoControlCode == IOCTL_GPD_READ_PORT_USHORT || \
    IoControlCode == IOCTL_GPD_READ_PORT_ULONG || \
    IoControlCode == IOCTL_GPD_WRITE_PORT_UCHAR || \
    IoControlCode == IOCTL_GPD_WRITE_PORT_USHORT || \


