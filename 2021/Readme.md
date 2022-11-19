# Introduction
After BleedingTooth, which was the first time I looked into Linux, I wanted to find a privilege escalation vulnerability as well. I started by looking at old vulnerabilities like CVE-2016-3134 and CVE-2016-4997 which inspired me to grep for memcpy() and memset() in the Netfilter code. This led me to some buggy code.

# Vulnerability
When IPT_SO_SET_REPLACE or IP6T_SO_SET_REPLACE is called in compatibility mode, which requires the CAP_NET_ADMIN capability that can however be obtained in a user+network namespace, structures need to be converted from user to kernel as well as 32bit to 64bit in order to be processed by the native functions. Naturally, this is destined to be error prone. Our vulnerability is in xt_compat_target_from_user() where memset() is called with an offset target->targetsize that is not accounted for during the allocation - leading to a few bytes written out-of-bounds

# Exploitation
Our primitive is limited to writing four bytes of zero up to 0x4C bytes out-of-bounds. With such a primitive, usual targets are:

Reference counter
Unfortunately, I could not find any suitable objects with a reference counter in the first 0x4C bytes.
Free list pointer
CVE-2016-6187: Exploiting Linux kernel heap off-by-one is a good example on how to exploit the free list pointer. However, this was already 5 years ago, and meanwhile, kernels have the CONFIG_SLAB_FREELIST_HARDENED option enabled which among other things protects free list pointers.
Pointer in a struct
This is the most promising approach, however four bytes of zero is too much to write. For example, a pointer 0xffff91a49cb7f000 could only be turned to 0xffff91a400000000 or 0x9cb7f000, where both of them would likely be invalid pointers. On the other hand, if we used the primitive to write at the very beginning of the adjacent block, we could write less bytes, e.g. 2 bytes, and for example turn a pointer from 0xffff91a49cb7f000 to 0xffff91a49cb70000.
Playing around with some victim objects, I noticed that I could never reliably allocate them around struct xt_table_info on kernel 5.4. I realized that it had something to do with the GFP_KERNEL_ACCOUNT flag, as other objects allocated with GFP_KERNEL_ACCOUNT did not have this issue. Jann Horn confirmed that before 5.9, separate slabs were used to implement accounting. Therefore, every heap primitive we use in the exploit chain should also use GFP_KERNEL_ACCOUNT.

The syscall msgsnd() is a well known primitive for heap spraying (which uses GFP_KERNEL_ACCOUNT) and has been utilized for multiple public exploits already. Though, its structure msg_msg has surprisingly never been abused. In this write-up, we will demonstrate how this data-structure can be abused to gain a use-after-free primitive which in turn can be used to leak addresses and fake other objects. Coincidentally, in parallel to my research in March 2021, Alexander Popov also explored the very same structure in Four Bytes of Power: exploiting CVE-2021-26708 in the Linux kernel.