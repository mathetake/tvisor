# tvisor: a Tiny Thread-level syscall interception framework

> [!WARNING]
> I stopped working on this project because I realized that almost the same thing can be achieved
> with [Kernel runtime security instrumentation](https://lwn.net/Articles/798157/) very easily, though it is _not_
> userspace mechanism.
> Therefore, the sole purpose of this repository is to show how to build an *userspace* syscall interception framework
> by only relying on the (classic) seccomp-bpf.
>
> The code is not complete at all but at least 95% of basic musl-libc tests are passing for "no-op" syscall
> interception.
> The one
> of the most
> difficult parts that I have not implemented is proper signal handling of blocked signals while executing
*interruptible* syscalls.
>
> I am not sure if I will continue this project, but I will keep this repository as a reference for the future.


tvisor is a tiny _100% userspace_ syscall interception _framework_ that can be used to build a program to monitor
syscalls.
"T" indicates both "Tiny" and "Thread-level". Only available on Linux.

A program built with tvisor will be a single-binary, and it does not spawn guest in a separate process, but it directly
runs the guest in
the same process.
It runs in a higher address space than the guest, and injects a tiny monitor in the process, then starts running the
guest
in the same process. The monitor is responsible for intercepting the syscall and forwarding it to the host while
rejecting/modifying
the syscall arguments if necessary.
It spawns a "kernel" thread which corresponds to each guest program thread. A kernel is responsible for handling
syscalls
in the corresponding guest thread.

tvisor is able to run **any binary** either statically or dynamically(TODO but should be possible) linked, without any
modification (with some exceptions).

## How it works

First of all, the tvisor binaries are running in a higher address space than the guest by passing `--image-base` linker
flag when building the tvisor binary. Tvisor users run the guest binary
as `./tvisor <tvisor_args> -- <guest_binary> <guest_args>`. Tvisor binary does the following things:

1. Parse the ELF binary and load it into the same virtual memory space.
2. Installs special signal handlers to handle *all* signals.
3. Spawns the "kernel thread" corresponding to each guest thread. Each kernel thread is responsible
   for handling _target_ syscalls in the corresponding guest thread. It spawns the corresponding guest thread and starts
   running
   the guest thread.
4. Each guest thread installs sigaltstack to handle any signals raised in the guest thread. The sigalt stack contains
   the various data structures that allow each signal handler can communicate with the corresponding kernel thread.
5. Each guest thread also
   installs [`seccomp-bpf`](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html) filter to intercept
   syscalls, which
   raises `SIGSYS` signals. Which syscall is intercepted is determined by users of tvisor library.
6. After all the setup is done, the guest thread start running the guest executable code.

## Example

There are two tvisor usage example programs in [tvisor/bin](./tvisor/bin). To build them,
run `make build`. You see the binary `./tvisor/target/aarch64-unknown-none/release/tvisor-fs` which is a freestanding
linux ELF binary.

tvisor-fs example program is a simple program that modifies the current working directory and root directory of the
guest program by intercepting getcwd and open kind system calls. For example, for the example program that prints the
current working directory `getcwd`,
tvisor-fs runs as a file system sandbox program that changes the current working directory to `/tmp`:

```
$ ./getcwd
Current working directory: /Users/mathetake/tvisor
$ tvisor-fs --cwd /anydir -- ./getcwd
Current working directory: /anydir
```
