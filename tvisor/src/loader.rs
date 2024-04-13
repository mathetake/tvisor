use crate::{debug_println, sys, util, PAGE_SIZE};
use xmas_elf::program::ProgramHeader;
use xmas_elf::sections::{SectionData, ShType};
use xmas_elf::symbol_table::Entry;
use xmas_elf::{program, ElfFile};

pub struct Loader {
    base: u64,
    tail: u64,
    guest_addr: *mut u8,
    guest_size: u64,
    phdr_addr: u64,
    phdr_size: u64,
    phdr_num: u64,
}

impl Loader {
    pub fn new() -> Self {
        Loader {
            base: 0,
            tail: 0,
            guest_addr: core::ptr::null_mut::<u8>(),
            guest_size: 0,
            phdr_addr: 0,
            phdr_size: 0,
            phdr_num: 0,
        }
    }

    pub fn load_from_file(&mut self, program_name: &str) -> *mut u8 {
        // Read the program into a temporary buffer.
        let (elf_ptr, elf_size) = util::read_elf(program_name);

        // Load the elf file.
        let entry_point = {
            let elf = unsafe { core::slice::from_raw_parts(elf_ptr, elf_size) };
            let file = ElfFile::new(elf).unwrap();

            // First walk through the loadable segments to allocate the memory.
            self.allocate_segments(&file);

            // Allocate content for the loadable segments.
            self.load_segments(&file);

            // Then walk through the relocations to apply them.
            self.relocations(&file);

            file.header.pt2.entry_point()
        };

        // We no longer need the elf file.
        sys::munmap(elf_ptr, elf_size);

        entry_point as *mut u8
    }

    pub fn phdr(self) -> (usize, usize, usize) {
        (
            self.phdr_addr as usize,
            self.phdr_size as usize,
            self.phdr_num as usize,
        )
    }

    fn allocate_segments(&mut self, file: &ElfFile) {
        self.phdr_size = file.header.pt2.ph_entry_size() as u64;
        self.phdr_num = file.program_iter().count() as u64;

        debug_println!("--- allocation ---");
        for header in file.program_iter() {
            match header.get_type() {
                Ok(program::Type::Load) => {}
                // pHdr is included in a loadable segment, but we need to the address because
                // guest programs might access it via auxv.
                Ok(program::Type::Phdr) => {
                    self.phdr_addr = header.virtual_addr();
                    continue;
                }
                _ => continue,
            }

            let base = header.virtual_addr();
            if self.base == 0 || self.base > base {
                self.base = base;
            }
            let tail = base + header.mem_size();
            if self.tail < tail {
                self.tail = tail;
            }
            debug_println!(
                "load segment at = {:#x} -- {:#x}",
                base,
                base + header.mem_size(),
            );
        }

        self.guest_addr = sys::mmap(
            self.base as usize,
            (self.tail - self.base) as usize,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_FIXED,
        );
        self.guest_size = self.tail - self.base;
        debug_println!("load segments at = {:#x} -- {:#x}", self.base, self.tail);
    }

    pub fn load_segments(&mut self, file: &ElfFile) {
        for header in file.program_iter() {
            let raw = match header {
                ProgramHeader::Ph32(inner) => inner.raw_data(file),
                ProgramHeader::Ph64(inner) => inner.raw_data(file),
            };
            let typ = header.get_type().unwrap();
            match typ {
                program::Type::Load => {
                    self.load(header.flags(), header.virtual_addr(), raw);
                }
                program::Type::Tls => {
                    self.load_tls(
                        header.virtual_addr(),
                        header.file_size(),
                        header.mem_size(),
                        header.align(),
                        raw,
                    );
                }
                _ => {} // skip for now
            }
        }
    }

    fn load(&mut self, flags: program::Flags, base: u64, region: &[u8]) {
        debug_println!("--- load ---");
        unsafe {
            core::ptr::copy(region.as_ptr(), base as *mut u8, region.len());
        }

        let end = base + region.len() as u64;
        debug_println!(
            "load region into [{:#x}..{:#x}] ({}{}{})",
            base,
            end,
            if flags.is_read() { "r" } else { "-" },
            if flags.is_write() { "w" } else { "-" },
            if flags.is_execute() { "x" } else { "-" },
        );

        // Align base to PAGE_SIZE.
        let aligned_base = base & !(PAGE_SIZE as u64 - 1);
        let adjusted_region = region.len() + (base - aligned_base) as usize;

        // Set the proper permission which at this point is rw.
        let mut prot = sys::PROT_NONE;
        if flags.is_read() {
            prot |= sys::PROT_READ;
        }
        if flags.is_write() {
            prot |= sys::PROT_WRITE;
        }
        if flags.is_execute() {
            prot |= sys::PROT_EXEC;
        }
        sys::mprotect(aligned_base as *mut u8, adjusted_region, prot);
    }

    fn load_tls(
        &mut self,
        tdata_start: u64,
        _tdata_length: u64,
        total_size: u64,
        _align: u64,
        region: &[u8],
    ) {
        debug_println!("--- load tls ---");
        let tls_end = tdata_start + total_size;
        debug_println!("tlt region is at = {:#x} -- {:#x}", tdata_start, tls_end);
        unsafe { core::ptr::copy(region.as_ptr(), tdata_start as *mut u8, region.len()) };
    }

    fn relocations(&mut self, file: &ElfFile) {
        let symbols = if let Some(tab) = file.find_section_by_name(".symtab") {
            if let SectionData::SymbolTable64(tab) = tab.get_data(file).unwrap() {
                debug_println!("Found symbol table");
                tab
            } else {
                return;
            }
        } else {
            return;
        };

        // Iterate over the sections
        for section in file.section_iter() {
            let sh_type = section.get_type().expect("Failed to get section type");

            let _name = if let Ok(name) = section.get_name(file) {
                name
            } else {
                continue;
            };

            // Check if this is a relocation section
            match sh_type {
                ShType::Rela | ShType::Rel => {
                    debug_println!("\tFound relocation");
                    // Read the relocation entries
                    match section.get_data(file) {
                        Ok(SectionData::Rela64(relocations)) => {
                            for rela in relocations {
                                let symbol_index = rela.get_symbol_table_index();
                                let symbol = {
                                    let sym_ent = symbols.get(symbol_index as usize).unwrap();
                                    let a = sym_ent.name();
                                    file.get_string(a).unwrap()
                                };
                                // https://reverseengineering.stackexchange.com/questions/6213/associating-symbol-names-with-plt-entries
                                debug_println!(
                                    "\t\tRela: Offset {:#x} +{:#x}, Symbol {:#x} ({})",
                                    rela.get_offset(),
                                    rela.get_addend(),
                                    symbol_index,
                                    symbol,
                                );
                                // Process each Rela entry...
                            }
                        }
                        Ok(SectionData::Rel64(relocations)) => {
                            for rel in relocations {
                                let symbol_index = rel.get_symbol_table_index();
                                let symbol = symbols.get(symbol_index as usize).unwrap().name();
                                debug_println!(
                                    "\t\tRel: Offset {:x}, Symbol {:x} ({})",
                                    rel.get_offset(),
                                    symbol_index,
                                    symbol,
                                );
                                // Process each Rel entry...
                            }
                        }
                        _ => {
                            debug_println!("Unknown relocation type");
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
