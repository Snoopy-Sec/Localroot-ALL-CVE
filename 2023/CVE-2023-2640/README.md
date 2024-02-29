# GameOver(lay) Ubuntu Privilege Escalation

### CVE-2023-2640

https://www.cvedetails.com/cve/CVE-2023-2640/

On Ubuntu kernels carrying both c914c0e27eb0 and "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs", an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

### CVE-2023-32629

https://www.cvedetails.com/cve/CVE-2023-32629/

Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels.

### Vulnerable kernels

| Kernel version | Ubuntu release |
| --- | --- |
| 6.2.0 | Ubuntu 23.04 (Lunar Lobster) / Ubuntu 22.04 LTS (Jammy Jellyfish) |
| 5.19.0 | Ubuntu 22.10 (Kinetic Kudu) / Ubuntu 22.04 LTS (Jammy Jellyfish) |
| 5.4.0 | Ubuntu 22.04 LTS (Local Fossa) / Ubuntu 18.04 LTS (Bionic Beaver) |

### Usage
Tested on kernels 5.19.0 and 6.2.0.

1. Just run the script in the low-priv shell.
```
   ./exploit.sh
```
2. Remember to type "exit" to finish the root shell and leave the house cleaned.

### Example
![Untitled](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/assets/120142960/13f8463c-6c5f-400c-a4d9-ab19cb0e5738)

### License
Feel free to use or modify whenever and wherever you like.
