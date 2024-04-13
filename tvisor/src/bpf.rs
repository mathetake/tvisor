#![allow(dead_code)]

pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xa0;
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

const BPF_MAXINSNS: u16 = 4096;

pub const SECCOMP_RET_KILL: u32 = 0x00000000;
pub const SECCOMP_RET_TRAP: u32 = 0x00030000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

#[repr(C)]
#[derive(Default, Copy, Clone, Debug)]
pub struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl sock_filter {
    pub fn serialize(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&self.code.to_le_bytes());
        buf[2] = self.jt;
        buf[3] = self.jf;
        buf[4..8].copy_from_slice(&self.k.to_le_bytes());
        buf
    }
}

#[repr(C)]
pub struct sock_fprog {
    pub len: u16,
    pub filter: *const sock_filter,
}

impl Default for sock_fprog {
    fn default() -> Self {
        sock_fprog {
            len: 0,
            filter: core::ptr::null(),
        }
    }
}

impl sock_filter {
    pub fn load_syscall_no() -> Self {
        sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        }
    }

    pub fn jeq_k(syscall_no: u32, jt: u8, jf: u8) -> Self {
        sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf,
            k: syscall_no,
        }
    }

    pub fn return_trap() -> Self {
        sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_TRAP,
        }
    }

    pub fn return_allow() -> Self {
        sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        }
    }
}
