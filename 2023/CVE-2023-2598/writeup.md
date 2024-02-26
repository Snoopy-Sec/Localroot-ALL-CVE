# Conquering the memory through io_uring - Analysis of CVE-2023-2598

Two months ago, I decided to look into the [io_uring](https://unixism.net/loti/what_is_io_uring.html) subsystem of the Linux Kernel. 

Eventually, I stumbled upon an [email](https://www.openwall.com/lists/oss-security/2023/05/08/3) disclosing a vulnerability within io_uring. The email's subject was *"Linux kernel io_uring out-of-bounds access to physical memory"*. It immediately piqued my interest. 

I had to put my research on pause as preparation for this year's European Cyber Security Challenge was sucking up most of my free time. Anyway, now that ECSC is over, I was able to look into it and decided to do a write-up of this powerful vulnerability.

## Table of Contents
1. [The io_uring subsystem in a nutshell](#io_uring_intro)
    - [What is io_uring?](#io_uring)
    - [Submission and Completion Queues](#queues)
    - [Buffers](#buffers)
    - [liburing](#liburing)
2. [Vulnerability](#vulnerability)
	- [Root Cause](#rootcause)
		- [Understanding page folios](#folio)
3. [Exploitation](#exploitation)
    - [An Incredible Primitive](#primitive)
	- [Target Objects](#targetobjects)
		- [Sockets](#sockets)
		- [Two Eggs](#twoeggs)
		- [Identifying the sockets](#idsockets)
	- [Leaking KASLR](#kaslr)
	- [Privilege Escalation](#privesc)
		- [Peeling back tcp_sock](#tcp_sock)
		- [call_usermodehelper_exec](#call_usermodehelper_exec)
		- [Overlapping subprocess_info](#overlap_subprocess_info)
		- [Setting up the arguments](#arguments)
		- [Setting up subprocess_info](#subprocess_info)
	- [Proof of Concept](#poc)
4. [Acknowledgements](#acknowledgements)


## The io_uring subsystem in a nutshell <a name="io_uring_intro"></a>
I will try to provide a very short and basic introduction to the `io_uring` subsystem and its most integral components.

I recommend reading [Chompie's](https://twitter.com/chompie1337) amazing [introduction to the subsystem](https://chompie.rip/Blog+Posts/Put+an+io_uring+on+it+-+Exploiting+the+Linux+Kernel#io_uring+What+is+it%3F) if you want to get a more complete idea of how `io_uring` works.   

### What is io_uring?
In a nutshell, `io_uring` is an API for Linux allowing applications to perform "system calls" asynchronously. It provides significant performance improvements over using normal syscalls. It allows your program to not wait on blocking syscalls and because of how it is implemented, lowers the number of actual syscalls needed to be performed.

### Submission and Completion Queues <a name="queues"></a>
At the core of every `io_uring` implementation sit two ring buffers - the submission queue (SQ) and the completion queue (CQ). Those ring buffers are shared between the application and the kernel.

In the submission queue are put *Submission Queue Entries (SQEs)*, each describing a syscall you want to be performed. The application then performs an `io_uring_enter` syscall to effectively tell the kernel that there is work waiting to be done in the submission queue.
> It is even possible to set up submission queue polling that eliminates the need to use `io_uring_enter`, reducing the number of *real* syscalls needed to be performed to 0. 

After the kernel performs the operation it puts a *Completion Queue Entry (CQE)* into the completion queue ring buffer which can then be consumed by the application.

### Fixed buffers <a name="buffers"></a>
You can register fixed buffers to be used by operations that read or write data. The pages that those buffers span will be *[pinned](https://eric-lo.gitbook.io/memory-mapped-io/pin-the-page)* and mapped for use, avoiding future copies to and from user space.

Registration of buffers happens through the `io_uring_register` syscall with the [IORING_REGISTER_BUFFERS](https://manpages.debian.org/unstable/liburing-dev/io_uring_register.2.en.html#IORING_REGISTER_BUFFERS) operation and the selection of buffers for use with the [IOSQE_BUFFER_SELECT](https://manpages.debian.org/unstable/liburing-dev/io_uring_enter.2.en.html#IOSQE_BUFFER_SELECT) SQE flag.
For an example case of use, check [this](https://unixism.net/loti/tutorial/fixed_buffers.html) out.

As *fixed buffers* are the protagonist of our story, we will see more of them later.

### liburing <a name="liburing"></a>
Thankfully there is a library that provides helpers for setting up `io_uring` instances and interacting with the subsystem - [liburing](https://github.com/axboe/liburing). It makes easy, operations like setting up buffers, producing SQEs, collecting CQEs, and so on.

It provides a simplified interface to `io_uring` that developers (*including exploit developers*) can use to make their lives easier.

As `liburing` is maintained by Jens Axboe, the maintainer of `io_uring`, it can be relied upon to be up-to-date with the kernel-side changes.

## Vulnerability <a name="vulnerability"></a>
> A flaw was found in the fixed buffer registration code for io_uring (io_sqe_buffer_register in io_uring/rsrc.c) in the Linux kernel that allows out-of-bounds access to physical memory beyond the end of the buffer.

The vulnerability was introduced in version 6.3-rc1 (commit `57bebf807e2a`) and was patched in 6.4-rc1 (commit `776617db78c6`).

### Root Cause <a name="rootcause"></a>
The root cause of the vulnerability is a faulty optimization when buffers are registered.

Buffers get registered through an `io_uring_register` system call by passing the `IORING_REGISTER_BUFFERS` opcode. This invokes `io_sqe_buffers_register`, which in return calls `io_sqe_buffer_register` to register each of the buffers. This is where the vulnerability arises.

```c
/* io_uring/rsrc.c */
static int io_sqe_buffer_register(struct io_ring_ctx *ctx, struct iovec *iov,
				  struct io_mapped_ubuf **pimu,
				  struct page **last_hpage)
{
	struct io_mapped_ubuf *imu = NULL;
	struct page **pages = NULL; // important to remember: *struct page* refers to physical pages
	unsigned long off;
	size_t size;
	int ret, nr_pages, i;
	struct folio *folio = NULL;

	*pimu = ctx->dummy_ubuf;
	if (!iov->iov_base) // if base is NULL
		return 0;

	ret = -ENOMEM;
	pages = io_pin_pages((unsigned long) iov->iov_base, iov->iov_len,
				&nr_pages); // pins the pages that the iov occupies
	// returns a pointer to an array of *page* pointers 
	// and sets nr_pages to the number of pinned pages
	if (IS_ERR(pages)) {
		ret = PTR_ERR(pages);
		pages = NULL;
		goto done;
	}
    ...
```
Let's first make clear what our "building blocks" are and what they are used for.

To this function are passed four arguments - the context, an `iovec` pointer, an `io_mapped_ubuf` pointer and a pointer to `last_hpage` (this value is always `NULL`).

An `iovec` is just a structure that describes a buffer, with the start address of the buffer and its length. Nothing more.
```c
struct iovec
{
	void __user *iov_base;	// the address at which the buffer starts
	__kernel_size_t iov_len; // the length of the buffer in bytes
};
```
When we pass a buffer to be registered we pass it as an `iovec`. Here the `*iov` pointer in this function points to a structure, containing information about the buffer that the user wants to register.

An `io_mapped_ubuf` is a structure that holds the information about a buffer that has been registered to an `io_uring` instance.
```c
struct io_mapped_ubuf {
	u64		ubuf; // the address at which the buffer starts
	u64		ubuf_end; // the address at which it ends
	unsigned int	nr_bvecs; // how many bio_vec(s) are needed to address the buffer 
	unsigned long	acct_pages;
	struct bio_vec	bvec[]; // array of bio_vec(s)
};
```
The last member of `io_mapped_buf` is an array of `bio_vec(s)`. A `bio_vec` is kind of like an `iovec` but for physical memory. It defines a contiguous range of physical memory addresses. 
```c
struct bio_vec {
	struct page	*bv_page; // the first page associated with the address range
	unsigned int	bv_len; // length of the range (in bytes)
	unsigned int	bv_offset; // start of the address range relative to the start of bv_page
};
```
And `struct page` is of course just a structure describing a physical page of memory.

In the code snippet above, the pages that the `iov` spans get pinned to memory ensuring they stay in the main memory and are exempt from paging. An array `pages` is returned that contains pointers to the `struct page(s)` that the `iov` spans and `nr_pages` gets set to the number of pages. 

Let's now continue with `io_sqe_buffer_register`.
```c
    ...
	/* If it's a huge page, try to coalesce them into a single bvec entry */
	if (nr_pages > 1) { // if more than one page
		folio = page_folio(pages[0]); // converts from page to folio
		// returns the folio that contains this page
		for (i = 1; i < nr_pages; i++) {
			if (page_folio(pages[i]) != folio) { // different folios -> not physically contiguous 
				folio = NULL; // set folio to NULL as we cannot coalesce into a single entry
				break;
			}
		}
		if (folio) { // if all the pages are in the same folio
			folio_put_refs(folio, nr_pages - 1); 
			nr_pages = 1; // sets nr_pages to 1 as it can be represented as a single folio page
		}
	}
    ...
```
Here if the `iov` spans more than a single physical page, the kernel will loop through `pages` to check if they belong to the same `folio`. But what even is `folio`?

#### Understanding page folios <a name="folio"></a>
To understand what a `folio` is we need to first understand what a page really is *according to the kernel*. Usually by *a page* people mean the smallest block of physical memory which can be mapped by the kernel (most commonly 4096 bytes but might be larger). Well, that isn't really what a *page* is in the context of the kernel. The definition has been expanded to include compound pages which are multiple contiguous *single* pages - which makes things confusing. 

Compound pages have a "head page" that holds the information about the compound page and is marked to make clear the nature of the compound page. All the "tail pages" are marked as such and contain a pointer to the "head page". But that creates a problematic ambiguity - if a `page` pointer for a tail page is passed to a function, is the function supposed to act on just that singular page or the whole compound page? 

So to address this confusion the concept of "page folios" was introduced. A "page folio" is essentially a page that is *guaranteed* to **not** be a tail page. This clears out the ambiguity as functions meant to not operate on singular tail pages will take `struct *folio` as an argument instead of `struct *page`. 
```c
struct folio {
       struct page page;
};
```
The `folio` structure is just a wrapper around `page`. It should be noted that every page is a part of a `folio`. Non-compound page's "page folio" is the page itself. Now that we know what a page folio is we can dissect the code above.

The code above is meant to identify if the pages that the buffer being registered spans are part of a single compound page. It iterates through the pages and checks if their folio is the same. If so it sets the number of pages `nr_pages` to `1` and sets the `folio` variable. Now here comes the issue...

The code that checks if the pages are from the same folio doesn't actually check if they are consecutive. It can be the same page mapped multiple times. During the iteration `page_folio(page)` would return the same folio again and again passing the checks. This is an obvious logic bug. Let's continue with `io_sqe_buffer_register` and see what the fallout is. 
```c
    ...
	imu = kvmalloc(struct_size(imu, bvec, nr_pages), GFP_KERNEL); 
	// allocates imu with an array for nr_pages bio_vec(s)
	// bio_vec - a contiguous range of physical memory addresses
	// we need a bio_vec for each (physical) page
    // in the case of a folio - the array of bio_vec(s) will be of size 1
	if (!imu)
		goto done;

	ret = io_buffer_account_pin(ctx, pages, nr_pages, imu, last_hpage);
	if (ret) {
		unpin_user_pages(pages, nr_pages);
		goto done;
	}

	off = (unsigned long) iov->iov_base & ~PAGE_MASK;
	size = iov->iov_len; // sets the size to that passed by the user!
	/* store original address for later verification */
	imu->ubuf = (unsigned long) iov->iov_base; // user-controlled
	imu->ubuf_end = imu->ubuf + iov->iov_len; // calculates the end based on the length
	imu->nr_bvecs = nr_pages; // this would be 1 in the case of folio
	*pimu = imu;
	ret = 0;

	if (folio) { // in case of folio - we need just a single bio_vec (efficiant!)
		bvec_set_page(&imu->bvec[0], pages[0], size, off);
		goto done;
	}
	for (i = 0; i < nr_pages; i++) { 
		size_t vec_len;

		vec_len = min_t(size_t, size, PAGE_SIZE - off);
		bvec_set_page(&imu->bvec[i], pages[i], vec_len, off);
		off = 0;
		size -= vec_len;
	}
done:
	if (ret)
		kvfree(imu);
	kvfree(pages);
	return ret;
}
```
A single `bio_vec` is allocated as `nr_pages = 1`. The size of the buffer that is written in `pimu->iov_len` and `pimu->bvec[0].bv_len` is the one passed by the user in `iov->iov_len`. 

## Exploitation <a name="exploitation"></a>
Now that our logic bug is clear let's see how it can be exploited.

### An Incredible Primitive <a name="primitive"></a>
Let's now imagine that we are registering a buffer that spans multiple virtual pages but each of them is the same *page* mapped again and again. This buffer is virtually contiguous, as the virtual memory is contiguous, but it isn't *physically* contiguous. When the buffer goes through the faulty code that checks if the pages belong to a compound page - it will pass them, fooling the kernel that it spans multiple pages as part of a compound page while in reality, it is just a single page.

This means that `pimu->bvec.bv_len` will be set to the *virtual* length of the buffer because the kernel believes that the virtually contiguous memory is backed by physically contiguous memory. As we established, `bio_vec(s)` deal with physical ranges of memory. This buffer will be registered and give us access to the physical pages following the one that was mapped to construct the buffer.

We can register a buffer spanning `n` virtual pages but a single physical one. After registering this buffer we can use `io_uring` operations to read from the buffer as well as write to it - giving us an out-of-bound access to `n-1` physical pages. Here `n` could be as high as the limit set for mappings allowed to a single userland process. We have a multi-page out-of-bounds read and write.

This is an incredibly powerful primitive, perhaps even the most powerful I have seen yet.

### Target Objects <a name="targetobjects"></a>
We are looking for target objects that allow us to leak KASLR and get some kind of code execution. 

Thankfully as we have an OOB read and write to whole physical pages, we don't have any limits on the objects themselves, we don't care what slab they use, what their size is or anything like that. 

We do however have *some* requirements. We need to be able to find our target objects and identify them. We will be leaking thousands of pages and we need to be able to find our needle(s) in the haystack. We need to be able to place an [egg](https://fuzzysecurity.com/tutorials/expDev/4.html) in the object itself using which we can later identify the object.

#### Sockets <a name="sockets"></a>
Here sockets are our friend. They are pretty massive objects containing both user-controlled fields, which can be used to place an egg, as well as function pointers which can be used to leak KASLR.

```c
struct sock {
	struct sock_common         __sk_common;          /*     0   136 */
	/* --- cacheline 2 boundary (128 bytes) was 8 bytes ago --- */
	struct dst_entry *         sk_rx_dst;            /*   136     8 */
	int                        sk_rx_dst_ifindex;    /*   144     4 */
	u32                        sk_rx_dst_cookie;     /*   148     4 */
	socket_lock_t              sk_lock;              /*   152    32 */
	atomic_t                   sk_drops;             /*   184     4 */
	int                        sk_rcvlowat;          /*   188     4 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	struct sk_buff_head        sk_error_queue;       /*   192    24 */
	struct sk_buff_head        sk_receive_queue;     /*   216    24 */
	struct {
		atomic_t           rmem_alloc;           /*   240     4 */
		int                len;                  /*   244     4 */
		struct sk_buff *   head;                 /*   248     8 */
		/* --- cacheline 4 boundary (256 bytes) --- */
		struct sk_buff *   tail;                 /*   256     8 */
	} sk_backlog;                                    /*   240    24 */
	int                        sk_forward_alloc;     /*   264     4 */
	u32                        sk_reserved_mem;      /*   268     4 */
	unsigned int               sk_ll_usec;           /*   272     4 */
	unsigned int               sk_napi_id;           /*   276     4 */
	int                        sk_rcvbuf;            /*   280     4 */

	/* XXX 4 bytes hole, try to pack */

	struct sk_filter *         sk_filter;            /*   288     8 */
	union {
		struct socket_wq * sk_wq;                /*   296     8 */
		struct socket_wq * sk_wq_raw;            /*   296     8 */
	};                                               /*   296     8 */
	struct xfrm_policy *       sk_policy[2];         /*   304    16 */
	/* --- cacheline 5 boundary (320 bytes) --- */
	struct dst_entry *         sk_dst_cache;         /*   320     8 */
	atomic_t                   sk_omem_alloc;        /*   328     4 */
	int                        sk_sndbuf;            /*   332     4 */
	int                        sk_wmem_queued;       /*   336     4 */
	refcount_t                 sk_wmem_alloc;        /*   340     4 */
	long unsigned int          sk_tsq_flags;         /*   344     8 */
	union {
		struct sk_buff *   sk_send_head;         /*   352     8 */
		struct rb_root     tcp_rtx_queue;        /*   352     8 */
	};                                               /*   352     8 */
	struct sk_buff_head        sk_write_queue;       /*   360    24 */
	/* --- cacheline 6 boundary (384 bytes) --- */
	__s32                      sk_peek_off;          /*   384     4 */
	int                        sk_write_pending;     /*   388     4 */
	__u32                      sk_dst_pending_confirm; /*   392     4 */
	u32                        sk_pacing_status;     /*   396     4 */
	long int                   sk_sndtimeo;          /*   400     8 */
	struct timer_list          sk_timer;             /*   408    40 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 7 boundary (448 bytes) --- */
	__u32                      sk_priority;          /*   448     4 */
	__u32                      sk_mark;              /*   452     4 */
	long unsigned int          sk_pacing_rate;       /*   456     8 */
	long unsigned int          sk_max_pacing_rate;   /*   464     8 */
    // .. many more fields
	/* size: 760, cachelines: 12, members: 92 */
	/* sum members: 754, holes: 1, sum holes: 4 */
	/* sum bitfield members: 16 bits (2 bytes) */
	/* paddings: 2, sum paddings: 6 */
	/* forced alignments: 1 */
	/* last cacheline: 56 bytes */
} __attribute__((__aligned__(8)));
```
Taking a look at `sk_setsockopt` in [net/core/sock.c](https://elixir.bootlin.com/linux/latest/source/net/core/sock.c#L1942) we can see what fields of the sock structure we can set. 

Some fields we could potentially set like `sk_mark` would require us to drop into a network namespace to obtain `CAP_NET_ADMIN`. Thankfully there are some options that don't have such requirements to set them.

Some good options that we could utilize are `SO_MAX_PACING_RATE` (sets `sk_max_pacing_rate`), `SO_SNDBUF` (sets `sk_sndbuf`) and `SO_RCVBUF` (sets `sk_rcvbuf`).

#### Two eggs <a name="twoeggs"></a>
Here perhaps the best option that we could pick is `SO_MAX_PACING_RATE`. It has one obvious advantage - we can use it to place *two eggs*, one at `sk_max_pacing_rate` and one at `sk_pacing_rate`. When the option `SO_MAX_PACING_RATE` is being set, the value of `sk_pacing_rate` is set to the new value of `sk_max_pacing_rate` if it is lower than the current value of `sk_pacing_rate`. Looking at the function [sock_init_data_uid](https://elixir.bootlin.com/linux/latest/source/net/core/sock.c#L3477) we see that `sk_pacing_rate` is initialized to `~0UL = 0xffffffffffffffff`.

The obvious question is - why would we need two eggs? As we are leaking many pages we could meet our egg outside the context of a `sock` object. I tested it and indeed sometimes the first egg found was not a one in a `sock` object. By looking for two eggs at a fixed distance from one another, we are ensuring that the matches we find will be the `sock` objects we are looking for.

#### Identifying the sockets <a name="idsockets"></a>
We want to have a way to identify which socket we have found in memory. We can do that through the `SO_SNDBUF` option by storing the file descriptor of the socket in it. In reality, we have to kind of "encode" the value by doing `fd + SOCK_MIN_SNDBUF` and "decode" it on read by doing `val / 2 - SOCK_MIN_SNDBUF`.

Now the value of `SOCK_MIN_SNDBUF` is calculated using the following formula `2 * (2048 + ALIGN(sizeof(sk_buff), 1 << L1_CACHE_SHIFT))`. The exact value depends on the value of [L1_CACHE_SHIFT](https://elixir.bootlin.com/linux/v6.3-rc1/source/arch/x86/include/asm/cache.h#L9). In my case `L1_CACHE_SHIFT = 6`, therefore `SOCK_MIN_SNDBUF = 4608`.

### Leaking KASLR <a name="kaslr"></a>
At the end of `struct sock`, there are quite a few function pointers. 
```c
struct sock {
    ...
	void                       (*sk_state_change)(struct sock *); /*   672     8 */
	void                       (*sk_data_ready)(struct sock *); /*   680     8 */
	void                       (*sk_write_space)(struct sock *); /*   688     8 */
	void                       (*sk_error_report)(struct sock *); /*   696     8 */
	/* --- cacheline 11 boundary (704 bytes) --- */
	int                        (*sk_backlog_rcv)(struct sock *, struct sk_buff *); /*   704     8 */
	void                       (*sk_destruct)(struct sock *); /*   712     8 */
    ...
} __attribute__((__aligned__(8)));
```
Leaking any of them is sufficient to defeat KASLR. For a TCP socket, they will be set to the following functions:
```
sk_state_change <-> <sock_def_wakeup>,
sk_data_ready <-> <sock_def_readable>,
sk_write_space <-> <sk_stream_write_space>,
sk_error_report <-> <sock_def_error_report>,
sk_backlog_rcv <-> <tcp_v4_do_rcv>,
sk_destruct <-> <inet_sock_destruct>
```

### Privilege Escalation <a name="privesc"></a>
Our ultimate goal is to achieve privilege escalation. With KASLR out of the way, we can move towards it.

As we already have control over a `sock` object we can use the same object to escalate.
The first member of the `sock` object is `struct sock_common` which is the minimal network layer representation of sockets in the kernel.

```c
struct sock_common {
	union {
		__addrpair         skc_addrpair;         /*     0     8 */
		struct {
			__be32     skc_daddr;            /*     0     4 */
			__be32     skc_rcv_saddr;        /*     4     4 */
		};                                       /*     0     8 */
	};                                               /*     0     8 */
	union {
		unsigned int       skc_hash;             /*     8     4 */
		__u16              skc_u16hashes[2];     /*     8     4 */
	};                                               /*     8     4 */
	union {
		__portpair         skc_portpair;         /*    12     4 */
		struct {
			__be16     skc_dport;            /*    12     2 */
			__u16      skc_num;              /*    14     2 */
		};                                       /*    12     4 */
	};                                               /*    12     4 */
	short unsigned int         skc_family;           /*    16     2 */
	volatile unsigned char     skc_state;            /*    18     1 */
	unsigned char              skc_reuse:4;          /*    19: 0  1 */
	unsigned char              skc_reuseport:1;      /*    19: 4  1 */
	unsigned char              skc_ipv6only:1;       /*    19: 5  1 */
	unsigned char              skc_net_refcnt:1;     /*    19: 6  1 */

	/* XXX 1 bit hole, try to pack */

	int                        skc_bound_dev_if;     /*    20     4 */
	union {
		struct hlist_node  skc_bind_node;        /*    24    16 */
		struct hlist_node  skc_portaddr_node;    /*    24    16 */
	};                                               /*    24    16 */
	struct proto *             skc_prot;             /*    40     8 */

	...

	/* size: 136, cachelines: 3, members: 25 */
	/* sum members: 135 */
	/* sum bitfield members: 7 bits, bit holes: 1, sum bit holes: 1 bits */
	/* last cacheline: 8 bytes */
};
```
We can see at offset 40 bytes from its start, a pointer to a `struct proto` object. A `proto` object describes how operations should be handled at the transport layer. It is primarily a collection of function pointers.
```c
struct proto {
	void                       (*close)(struct sock *, long int); /*     0     8 */
	int                        (*pre_connect)(struct sock *, struct sockaddr *, int); /*     8     8 */
	int                        (*connect)(struct sock *, struct sockaddr *, int); /*    16     8 */
	int                        (*disconnect)(struct sock *, int); /*    24     8 */
	struct sock *              (*accept)(struct sock *, int, int *, bool); /*    32     8 */
	int                        (*ioctl)(struct sock *, int, long unsigned int); /*    40     8 */
	int                        (*init)(struct sock *); /*    48     8 */
	void                       (*destroy)(struct sock *); /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	void                       (*shutdown)(struct sock *, int); /*    64     8 */
	int                        (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int); /*    72     8 */
	int                        (*getsockopt)(struct sock *, int, int, char *, int *); /*    80     8 */

	...

	/* size: 432, cachelines: 7, members: 54 */
	/* sum members: 425, holes: 2, sum holes: 7 */
	/* last cacheline: 48 bytes */
};
```
Here we have quite a few candidates but the one we are really interested in is the `ioctl`. By writing our "gadget" to `ioctl` we will be able to invoke it by just invoking an ioctl call to the socket. 

However in order to write our gadget at `proto->ioctl` we first need to set up a fake `proto` object. This is easy enough, we can write it below our `sock` object. To do this safely, we need to ensure that right after the `sock` object we aren't overwriting anything that we shouldn't be. 

Making the sockets TCP sockets (`tcp_sock`), for example, gives us quite a bit of leeway. 

#### Peeling back tcp_sock <a name="tcp_sock"></a>
`tcp_sock` is the top_level object.\
&nbsp;`struct inet_connection_sock inet_conn` is the first member of `tcp_sock`\
&nbsp;&nbsp;`struct inet_sock icsk_inet` is the first member of `inet_connection_sock`\
&nbsp;&nbsp;&nbsp;`struct sock sk` is the first member of `inet_sock`

So in memory, stuff is set up the following way:
```
--- sock @0
----- inet_sock 
------ inet_connection_sock 
------- tcp_sock @1400
```
In total `tcp_sock` is of size 2208 bytes (on v6.3-rc1).

We have the freedom to place our fake proto object below `sock` proper, writing over the `inet_sock`. We will only need to restore the `tcp_sock` after making our `ioctl` call to its initial state so as to not accidentally panic the kernel when the socket gets destroyed.

#### call_usermodehelper_exec <a name="call_usermodehelper_exec"></a>
A very clean gadget that we could use is [call_usermodehelper_exec](https://elixir.bootlin.com/linux/v6.3-rc1/source/kernel/umh.c#L385). It allows us to start a user-mode process from kernel space. It takes two arguments - `(struct subprocess_info *sub_info, int wait)`.

Looking at `struct proto` we can see that the ioctl is defined as `(*ioctl)(struct sock *, int, long unsigned int);`. We cannot control `sub_info` - it will always be a pointer to our `sock` object.

So now the question is - are we able to write a fake `subprocess_info` object over the beginning of our socket without breaking it? 

```c
struct subprocess_info {
	struct work_struct         work;                 /*     0    32 */
	struct completion *        complete;             /*    32     8 */
	const char  *              path;                 /*    40     8 */
	char * *                   argv;                 /*    48     8 */
	char * *                   envp;                 /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	int                        wait;                 /*    64     4 */
	int                        retval;               /*    68     4 */
	int                        (*init)(struct subprocess_info *, struct cred *); /*    72     8 */
	void                       (*cleanup)(struct subprocess_info *); /*    80     8 */
	void *                     data;                 /*    88     8 */

	/* size: 96, cachelines: 2, members: 10 */
	/* last cacheline: 32 bytes */
};
```
The first member of `subprocess_info` is a [work_struct](https://elixir.bootlin.com/linux/v6.3-rc1/source/include/linux/workqueue.h#L97) - an object that describes *deferred work*. Then we have parameters like `path` which holds a pointer to the path of our executable, `argv` which is a pointer to the array of pointers to each of the arguments and `envp` which is the same but for environment variables. The function pointer `init` holds the function that will be called on initialization to set up the credentials of the process - if it is set to null, it will start with the credentials of system workqueues (as root). Likewise, if `cleanup` is set, it gets executed after the subprocess exits.

#### Overlapping subprocess_info <a name="overlap_subprocess_info"></a>
As we established, our `subprocess_info` will need to overlap with the start of the `sock` object as the first argument of the `ioctl` is `sock *`. However, the first 136 bytes of `struct sock` are occupied by  `struct sock_common`. 

```txt
struct sock[sock_common]      | subprocess_info
============================================================
0x0: skc_addrpair             | work.data
0x8: skc_hash, skc_u16hashes  | work.entry.next
0x10: skc_portpair, ..., ...  | work.entry.prev
0x18: skc_bind_node[0:7]      | work.func
0x20: skc_bind_node[8:15]     | complete
0x28: skc_prot (struct proto) | path
0x30: skc_net                 | argv
0x38: skc_v6_daddr            | envp
0x40: *padding*               | wait, retval
0x48: skc_v6_rcv_saddr[0:7]   | *init
0x50: skc_v6_rcv_saddr[8:15]  | *cleanup
0x58: skc_cookie              | data
============================================================
```

As we see the value of `skc_prot` overlaps with `path`. If we set `path` to anything else we will be overwriting `skc_prot` which will break our exploit as we need `skc_prot` to point to our fake `proto` structure at the end of `sock` proper. So, can we overlap `path` with the start of our `proto` structure?

```c
struct proto {
	void                       (*close)(struct sock *, long int); /*     0     8 */
	int                        (*pre_connect)(struct sock *, struct sockaddr *, int); /*     8     8 */
	int                        (*connect)(struct sock *, struct sockaddr *, int); /*    16     8 */
	int                        (*disconnect)(struct sock *, int); /*    24     8 */
	struct sock *              (*accept)(struct sock *, int, int *, bool); /*    32     8 */
	int                        (*ioctl)(struct sock *, int, long unsigned int); /*    40     8 */
	...
};
```
The only value in `proto` we need to keep is `ioctl` as it holds `call_usermodehelper_exec`. We don't care about all other values as we won't be connecting, disconnecting or closing the socket - so we can freely write over those members. This leaves us with 40 bytes free at the start of `proto` for our path. More than enough :)

#### Setting up the arguments <a name="arguments"></a>
We also need to set up our arguments for `subprocess_info`. Our goal is to execute something like `/bin/sh -c /bin/sh &>/dev/ttyS0 </dev/ttyS0`. Let's break it down.
```
/bin/sh -c /bin/sh &>/dev/ttyS0 </dev/ttyS0
 ^      ^  |______________________________|	
 |      |               |
 |      |               |
path   arg1            arg2
arg0	
```
We are essentially asking `/bin/sh` to spawn us another `/bin/sh` process but we redirect its `stdin` and `stdout` to our virtual console/serial port. 

However, all of those strings need to go somewhere. We already established that `path` will need to go at the start of `proto` but there isn't enough space there for all of those strings. A convenient location for them is overlapping with `inet_sock / inet_connection_sock / tcp_sock` after `sock` proper. There we can write both the strings and the `argv` array of pointers.

This though, presents another problem. In order to set up `argv` we need to know the addresses in memory of all the arguments we set up. So aside from KASLR, we need to also leak the address of our `sock` object in memory so we can calculate the location at which our arguments are.

Two members in `sock` from which we can obtain a *self-pointer* are `sk_error_queue` and `sk_receive_queue` - both are the doubly linked list nodes. Both nodes *should* be in a linked list by themselves and therefore should contain pointers to themselves. It should be said that while I observed that both were in empty linked lists, `sk_error_queue` is said in the documentation to be "rarely used" - so it is the wiser choice for the leak. 

After obtaining the address of our `sock` structure in memory, the rest is just a simple matter of calculating offsets.

#### Setting up subprocess_info <a name="subprocess_info"></a>
Let's see how we are going to set the `subprocess_info` to escalate.
```
work.data          <-> set to 0
work.entry.next    <-> set to it's own address
work.entry.prev    <-> set to the address of work.entry.next
work.func          <-> set to call_usermodehelper_exec_work
complete           <-> irrelevant
path               <-> don't overwrite or overwrite it with the same value
argv               <-> write the address where the argv array was set up
envp               <-> set to 0, we have no env variables
wait               <-> irrelevant
retval             <-> irrelevant
*init              <-> set to 0
*cleanup           <-> set to 0
data               <-> irrelevant
```
We must write `work.func` to hold `call_usermodehelper_exec_work`. As you remember we wrote the value of `proto->ioctl` to be `call_usermodehelper_exec`. The function `call_usermodehelper_exec` is responsible for queuing up our deferred work while `call_usermodehelper_exec_work` is called to handle the deferred work, when it comes time for it - so the function `call_usermodehelper_exec_work` is the one responsible for spawning our new process.

We write `path` to remain the same, the address of our `proto` structure.

After this is done, making an `ioctl` call to our socket to spawn our new shell is all that is left :)

### Proof of Concept <a name="poc"></a>
Due to the astonishing primitive that this vulnerability gives us, the proof of concept is *extremely* reliable by nature.
```
$ id
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
$ ./exploit
[*] CVE-2023-2598 Exploit by anatomic (@YordanStoychev)
memfd: 0, page: 0 at virt_addr: 0x4247000000, reading 266240000 bytes
memfd: 0, page: 500 at virt_addr: 0x42470001f4, reading 266240000 bytes
memfd: 0, page: 1000 at virt_addr: 0x42470003e8, reading 266240000 bytes
memfd: 0, page: 1500 at virt_addr: 0x42470005dc, reading 266240000 bytes
memfd: 0, page: 2000 at virt_addr: 0x42470007d0, reading 266240000 bytes
memfd: 0, page: 2500 at virt_addr: 0x42470009c4, reading 266240000 bytes
memfd: 0, page: 3000 at virt_addr: 0x4247000bb8, reading 266240000 bytes
memfd: 0, page: 3500 at virt_addr: 0x4247000dac, reading 266240000 bytes
memfd: 0, page: 4000 at virt_addr: 0x4247000fa0, reading 266240000 bytes
memfd: 0, page: 4500 at virt_addr: 0x4247001194, reading 266240000 bytes
memfd: 0, page: 5000 at virt_addr: 0x4247001388, reading 266240000 bytes
memfd: 0, page: 5500 at virt_addr: 0x424700157c, reading 266240000 bytes
memfd: 0, page: 6000 at virt_addr: 0x4247001770, reading 266240000 bytes
memfd: 0, page: 6500 at virt_addr: 0x4247001964, reading 266240000 bytes
memfd: 0, page: 7000 at virt_addr: 0x4247001b58, reading 266240000 bytes
memfd: 0, page: 7500 at virt_addr: 0x4247001d4c, reading 266240000 bytes
memfd: 0, page: 8000 at virt_addr: 0x4247001f40, reading 266240000 bytes
memfd: 0, page: 8500 at virt_addr: 0x4247002134, reading 266240000 bytes
memfd: 0, page: 9000 at virt_addr: 0x4247002328, reading 266240000 bytes
memfd: 0, page: 9500 at virt_addr: 0x424700251c, reading 266240000 bytes
memfd: 0, page: 10000 at virt_addr: 0x4247002710, reading 266240000 bytes
memfd: 0, page: 10500 at virt_addr: 0x4247002904, reading 266240000 bytes
memfd: 0, page: 11000 at virt_addr: 0x4247002af8, reading 266240000 bytes
memfd: 0, page: 11500 at virt_addr: 0x4247002cec, reading 266240000 bytes
memfd: 0, page: 12000 at virt_addr: 0x4247002ee0, reading 266240000 bytes
memfd: 0, page: 12500 at virt_addr: 0x42470030d4, reading 266240000 bytes
Found value 0xdeadbeefdeadbeef at offset 0x21c8
Socket object starts at offset 0x2000
kaslr_leak: 0xffffffffb09503f0
kaslr_base: 0xffffffffafe00000
found socket is socket number 1950
our struct sock object starts at 0xffff9817ff400000
fake proto structure set up at 0xffff9817ff400578
args at 0xffff9817ff400728
argv at 0xffff9817ff400750
subprocess_info set up at beginning of sock at 0xffff9817ff400000
calling ioctl...
/bin/sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0(root)
/ # w00t w00t
```
You can find my Proof of Concept - [here](https://github.com/ysanatomic/io_uring_LPE-CVE-2023-2598).

## Acknowledgements <a name="acknowledgements"></a>
[Tobias Holl](https://tholl.xyz/), for outstanding research, discovering the vulnerability and PoC'ing it. Took the idea from him to use the the pacing rate of the socket as an egg :)

[Valentina Palmiotti (chompie)](https://chompie.rip/Home), for her amazing introduction to the `io_uring` subsystem in her article, [Put an io_uring on it - Exploiting the Linux Kernel](https://chompie.rip/Blog+Posts/Put+an+io_uring+on+it+-+Exploiting+the+Linux+Kernel#io_uring%20What%20is%20it?).
