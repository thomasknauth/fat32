// 2020-05-12
//
// Trying to change the API. Create a single structure Fat32Media that
// contains file, BIOS parameter block, Fat32 table and Master Boot
// Record. Only need to pass one parameter to each funtion. Not sure
// if this is a clever idea given Rust's ownership semantics. Fixing
// errors thrown by the compiler as I go.
//
// I would like to implement a simple file system traversal. The idea
// is to have a simple correctness check as follows. The content of
// each file is checksummed and recored in its file name. Similarly,
// all file names (and attributes) are checksummed into the parent
// directory's name. Use a Python script to generate valid inputs,
// i.e., mount a disk image on the host, create files, and read the
// resulting image using the Rust FAT32 implementation.

// 0x00	0x80 if active (bootable), 0 otherwise	1
// 0x01	start of the partition in CHS-addressing	3
// 0x04	type of the partition, see below	1
// 0x05	end of the partition in CHS-addressing	3
// 0x08	relative offset to the partition in sectors (LBA)	4
// 0x0C	size of the partition in sectors	4

#[derive(Debug,Copy,Clone)]
#[repr(C)]
#[repr(packed)]
struct PartitionTable {
    active: u8,
    start_c: u8,
    start_h: u8,
    start_s: u8,
    partition_type: u8,
    end_c: u8,
    end_h: u8,
    end_s: u8,
    offset_lba: u32,
    size_sectors: u32
}

// BytesPerSector	2	0x000B
// SectorsPerCluster	1	0x000D
// ReservedSectors	2	0x000E
// FatCopies	1	0x0010
// RootDirEntries	2	0x0011
// NumSectors	2	0x0013
// MediaType	1	0x0015
// SectorsPerFAT	2	0x0016
// SectorsPerTrack	2	0x0018
// NumberOfHeads	2	0x001A
// HiddenSectors	4	0x001C
// SectorsBig	4	0x0020

// 0x024	0x19	DWORD	Logical sectors per FAT
// 0x028	0x1D	WORD	Mirroring flags etc.
// 0x02A	0x1F	WORD	Version
// 0x02C	0x21	DWORD	Root directory cluster
// 0x030	0x25	WORD	Location of FS Information Sector
// 0x032	0x27	WORD	Location of backup sector(s)
// 0x034	0x29	12 BYTEs	Reserved (Boot file name)
// 0x040	0x35	BYTE	Physical drive number
// 0x041	0x36	BYTE	Flags etc.
// 0x042	0x37	BYTE	Extended boot signature (0x28)
// 0x043	0x38	DWORD	Volume serial number

// size: 36 bytes
// Stored in first sector of a FAT volume.
#[derive(Debug,Copy,Clone)]
#[repr(C)]
#[repr(packed)]
struct BIOSParameterBlock {
    jmp: [u8; 3],
    oem_name: [u8; 8],
    bytes_per_sec: u16,
    sectors_per_cluster: u8,    // Must be power of 2.
    reserved_sectors: u16,
    fat_copies: u8,
    root_dir_entries: u16,
    total_secs_16: u16,       // <- This 16 bit field limited the size of early FAT versions.
    media_type: u8,
    secs_per_fat_16: u16,
    sectors_per_track: u16,
    number_of_heads: u16,
    hidden_sectors: u32,
    total_secs_32: u32
}

#[derive(Debug,Copy,Clone)]
#[repr(C)]
struct Fat12and16Block {
    drive_nr: u8,
    reserved1: u8,
    boot_sig: u8,
    vol_id: u32,
    vol_label: [u8; 11],
    file_sys_type: [u8; 8]
}

#[derive(Debug,Copy,Clone)]
#[repr(C)]
#[repr(packed)]
struct Fat32 {
    secs_per_fat_32: u32,
    ext_flags: u16,
    fs_ver: u16,
    root_cluster: u32,      // First cluster of root directory
    fs_info: u16,
    backup_boot_sector: u16,
    reserved: [u8; 12],
    drive_nr: u8,
    reserved1: u8,
    boot_sig: u8,
    vol_id: u32,
    vol_label: [u8; 11],
    file_sys_type: [u8; 8]
}

#[derive(Debug,Copy,Clone)]
#[repr(C)]
#[repr(packed)]
struct MasterBootRecord {
    bootstrap_code_1: [u64; 32],
    bootstrap_code_2: [u32; 32],
    bootstrap_code_3: [u32; 15],
    bootstrap_code_4: [u16; 1],      // Skip first 446 bytes. Cannot use bootstrap_code: [u8; 446] for some reason.
    partitions: [PartitionTable; 4],
    sig: [u8; 2]
}

#[repr(C, packed)]
#[derive(Debug,Copy,Clone)]
struct DirEntry {              // offset in bytes
    name: [u8; 11],            // 0
    attr: u8,                  // 11
    nt_reserved: u8,           // 12
    create_time_tenth: u8,     // 13
    create_time: u16,          // 14
    create_date: u16,          // 16
    last_access_date: u16,     // 18
    first_cluster_high: u16,   // 20
    write_time: u16,           // 22
    write_date: u16,           // 24
    first_cluster_low: u16,    // 26
    file_size: u32             // 28
}

struct Fat32Media {
     f: std::fs::File,
     mbr: MasterBootRecord,
     bpb: BIOSParameterBlock,
     fat32: Fat32
}

const ATTR_READ_ONLY:u8 = 0x1;
const ATTR_HIDDEN   :u8 = 0x2;
const ATTR_SYSTEM   :u8 = 0x4;
const ATTR_VOLUME_ID:u8 = 0x8;
const ATTR_DIRECTORY:u8 = 0x10;
const ATTR_ARCHIVE  :u8 = 0x20;

const ATTR_LONG_NAME:u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
const ATTR_LONG_NAME_MASK:u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID |
                               ATTR_DIRECTORY | ATTR_ARCHIVE;

const LAST_LONG_ENTRY:u8 = 0x40;
const LONG_ENTRY_ORD_MASK: u8 = 0x3F;

// A long file name can have a maximum of 255 (UTF16 encoded)
// characters.
const LONG_NAME_MAX_CHARS: usize = 255;
const CHARS_PER_LONG_ENTRY: u32 = 13;

// A long entry can store 26 bytes of a file name. Since each
// character is encoded in 2 bytes (UTF16), this makes 13 characters
// per long entry.

#[repr(C, packed)]
#[derive(Debug,Copy,Clone)]
struct LongEntry { // offset (byte)
  ord:u8,          // 0
  name1:[u8;10],   // 1
  attr:u8,         // 11
  dir_type:u8,     // 12
  checksum:u8,     // 13
  name2:[u8;12],   // 14
  unused:[u8;2],   // 26
  name3:[u8;4]     // 28
}

impl LongEntry {
    fn name(&self) -> [u16;13] {
        let mut n: [u16;13] = [0;13];
        n[0] = self.name1[0] as u16 | (self.name1[1] as u16) << 8;
        n[1] = self.name1[2] as u16 | (self.name1[3] as u16) << 8;
        n[2] = self.name1[4] as u16 | (self.name1[5] as u16) << 8;
        n[3] = self.name1[6] as u16 | (self.name1[7] as u16) << 8;
        n[4] = self.name1[8] as u16 | (self.name1[9] as u16) << 8;

        n[5]  = self.name2[0]  as u16 | (self.name2[1]  as u16) << 8;
        n[6]  = self.name2[2]  as u16 | (self.name2[3]  as u16) << 8;
        n[7]  = self.name2[4]  as u16 | (self.name2[5]  as u16) << 8;
        n[8]  = self.name2[6]  as u16 | (self.name2[7]  as u16) << 8;
        n[9]  = self.name2[8]  as u16 | (self.name2[9]  as u16) << 8;
        n[10] = self.name2[10] as u16 | (self.name2[11] as u16) << 8;

        n[11] = self.name3[0] as u16 | (self.name3[1] as u16) << 8;
        n[12] = self.name3[2] as u16 | (self.name3[3] as u16) << 8;

        return n;
    }
}

impl DirEntry {

    fn new(name: String) -> DirEntry {
        assert!(name.len() <= 11);
        // Beware, the date/time format does not record time zone
        // information! Also, if the system outputs a time outside the
        // FAT range (1980 - 2100), the system likely uses a different
        // epoch start to fill the missing date in.
        let default_date = 0x21; // Jan 1st, 1980
        let mut x = DirEntry {name: [0x20; 11],
                              attr: 0,
                              nt_reserved: 0,
                              create_time_tenth: 0,
                              create_time: 0,
                              create_date: default_date,
                              last_access_date: default_date,
                              first_cluster_high: 0,
                              write_time: 1,
                              write_date: default_date,
                              first_cluster_low: 0,
                              file_size: 0 };
        x.name[0..name.len()].copy_from_slice(name.as_bytes());
        return x;
    }

    fn print(&self) {

       if (self.attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME {
           println!("ATTR_LONG_NAME");
       }
       if (self.attr & ATTR_LONG_NAME_MASK) != ATTR_LONG_NAME && self.name[0] != 0xE5 {
           if (self.attr & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) == 0x00 {
               // Create a local copy to prevent "warning: borrow of
               // packed field is unsafe and requires unsafe function or
               // block (error E0133)"
               let file_size = self.file_size;
               println!("{} [size {} byte(s), 1st cluster #: {}]", self.short_name_as_str(), file_size, self.cluster_number());
           } else if (self.attr & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) == ATTR_DIRECTORY {
               println!("{} (dir), cluster #: {}", self.short_name_as_str(), self.cluster_number());
           } else if (self.attr & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) == ATTR_VOLUME_ID {
               println!("Volume name is {}", self.short_name_as_str());
           } else {
               println!("Invalid entry");
           }
        }
    }

    fn is_file(&self) -> bool {
        (self.attr & ATTR_DIRECTORY) == 0 && (self.attr & ATTR_VOLUME_ID) == 0
    }

    fn is_directory(&self) -> bool {
        !self.is_long_name() &&
            (self.attr & ATTR_DIRECTORY) != 0
    }

    fn is_long_name(&self) -> bool {
        (self.attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME
    }

    fn is_dot_entry(&self) -> bool {
        // 46 is '.' (dot); 32 is ' ' (space)
        let dot_name : [u8; 11] = [46, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32];
        return self.name == dot_name;
    }

    fn is_dot_dot_entry(&self) -> bool {
        // 46 is '.' (dot); 32 is ' ' (space)
        let dot_dot_name : [u8; 11] = [46, 46, 32, 32, 32, 32, 32, 32, 32, 32, 32];
        return self.name == dot_dot_name;
    }

    fn cluster_number(&self) -> u32 {
        return self.first_cluster_low as u32 + ((self.first_cluster_high as u32) << 16);
    }

    fn short_name_as_str(&self) -> String {
        let mut main_part_len: usize = 8;

        for (i, elem) in self.name[0..8].iter().enumerate() {
            if *elem == 0x20 {
                    main_part_len = i;
                    break;
            }
        }

        let mut extension_part_len: usize = 3;
        for (i, elem) in self.name[8..11].iter().enumerate() {
            if *elem == 0x20 {
                    extension_part_len = i;
                    break;
            }
        }

        let main_part = str::from_utf8(&self.name[0..main_part_len]).unwrap().to_string();
        let ext_part = str::from_utf8(&self.name[8..8+extension_part_len]).unwrap().to_string();
        if ext_part.len() > 0 {
            return main_part + "." + &ext_part;
        } else {
            return main_part;
        }
    }

    fn is_free(&self) -> bool {
        let magic_free_entry_byte: u8 = 0xE5;
        self.name[0] == magic_free_entry_byte ||
            self.name[0] == 0x0
    }

    fn is_free_and_following(&self) -> bool {
        let magic_free_entry_byte: u8 = 0x0;
        self.name[0] == magic_free_entry_byte
    }

    fn to_bytes(&self) -> [u8; 32] {
        let x: [u8; 32] = unsafe { mem::transmute(*self) };
        assert_eq!(core::mem::size_of::<Self>(), x.len());
        return x;
    }
}

use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{self, Write};
use std::mem;
use std::str;

extern crate clap;
use clap::Clap;
extern crate sha2;
use sha2::{Sha256, Digest};

extern crate libc;

#[derive(Clap)]
#[clap(version = "0.1", author = "Thomas K.")]
struct Opts {
    #[clap(short,long, default_value = "test.img")]
    diskimage: String,
    #[clap(subcommand)]
    subcmd: SubCommand
}

#[derive(Clap)]
enum SubCommand {
    #[clap(version = "0.1")]
    Cat(Cat),
    Info(Info),
    Ls(Ls),
    ListFsCommand(ListFsCommand),
    Selftest(Selftest)
}

#[derive(Clap)]
struct Cat {
    #[clap(short)]
    path: String
}

#[derive(Clap)]
struct Info {
}

#[derive(Clap)]
struct Ls {
    #[clap(short, default_value = "/")]
    path: String
}

#[derive(Clap)]
struct ListFsCommand {
}

#[derive(Clap)]
struct Mkdir {
    path: String
}

#[derive(Clap)]
struct Selftest {
}

fn root_dir_sectors(bpb: &BIOSParameterBlock) -> u32 {
   return (((bpb.root_dir_entries * 32) + (bpb.bytes_per_sec - 1)) / bpb.bytes_per_sec) as u32;
}

///
///
/// Relative to first sector of volume that contains the BIOS Parameter Block
fn first_data_sector(fat: &Fat32Media) -> u32 {
   return fat.bpb.reserved_sectors as u32 + (fat.fat32.secs_per_fat_32 * fat.bpb.fat_copies as u32) + root_dir_sectors(&fat.bpb);
}

fn fat_size(bpb: &BIOSParameterBlock, fat32: &Fat32) -> u32 {
    if bpb.secs_per_fat_16 != 0 {
        return bpb.secs_per_fat_16 as u32;
    } else {
        assert!(fat32.secs_per_fat_32 != 0);
        return fat32.secs_per_fat_32;
    }
}

fn total_secs(bpb: &BIOSParameterBlock) -> u32 {
    if bpb.total_secs_16 != 0 {
        return bpb.total_secs_16 as u32;
    } else {
        assert!(bpb.total_secs_32 != 0);
        return bpb.total_secs_32;
    }
}

fn data_secs(bpb: &BIOSParameterBlock, fat32: &Fat32) -> u32 {
    return total_secs(&bpb) - (bpb.reserved_sectors as u32 +
                              (bpb.fat_copies as u32 * fat_size(&bpb, &fat32)) +
                               root_dir_sectors(&bpb));
}

fn count_of_clusters(bpb: &BIOSParameterBlock, fat32: &Fat32) -> u32 {
    // NB: This rounds *down*!
    return data_secs(&bpb, &fat32) / bpb.sectors_per_cluster as u32;
}

// Restrictions: Only handle FAT32.

// Note: each cluster consists of N sectors; N is determined when
// formatting the disk; it depends on the FAT type (12 vs 16 vs 32)
// and the disk's total size

// Note: The File Allocation Table consists of 32 bit entries; one for each cluster.

// Resources
// - https://blog.rust-lang.org/2015/05/11/traits.html
// - 

const FAT32_BYTES_PER_FAT_ENTRY: u32 = 4;

// Most-significant 4 bits of a FAT32 entry are to be ignored.
fn is_eof(fat_entry: u32) -> bool {
    return fat_entry >= 0x0FFFFFFE;
}

enum FatEntryState {
    NEXT, VISIT
}

trait FileAction {
    // All of a file's bytes pass through this.
    fn consume(&mut self, data: &[u8; 512], size: usize);

    fn handle_file(&mut self, e: &DirEntry) -> FatEntryState;
    fn handle_dir(&mut self, e: &DirEntry) -> FatEntryState;

    // Called when descending down a directory.
    fn enter(&mut self, e: DirEntry);
    // Called when ascending from a directory.
    fn exit(&mut self);
}

// List a specific directory.
struct LsCommand {
    path: String,
    prefix: String,
    entries: Vec<DirEntry>
}

impl LsCommand {
    fn new(path: String) -> LsCommand {
        LsCommand { path: path, prefix: "/".to_string(), entries: vec![] }
    }
}

impl FileAction for LsCommand {

    fn consume(&mut self, _data: &[u8; 512], _size: usize) {
        panic!("");
    }

    fn handle_file(&mut self, e: &DirEntry) -> FatEntryState {
        // println!("{}: self.path = {}, self.prefix= {}", line!(), self.path, self.prefix);

        // self.path == self.prefix is true when ls'ing a directory.
        // self.path == concat(...) is true when ls'ing a file.
        if (self.path == self.prefix) ||
            (self.path == concat(&self.prefix, &e.short_name_as_str())) {
            self.entries.push(*e);
        }
        return FatEntryState::NEXT;
    }

    fn handle_dir(&mut self, e: &DirEntry) -> FatEntryState {
        // println!("{}: self.path = {}, self.prefix= {}", line!(), self.path, self.prefix);
        if self.path == self.prefix {
            self.entries.push(*e);
            return FatEntryState::NEXT;
        } else {
            // let path: Vec<&str> = self.path.split('/').collect();
            //if path[1] == e.short_name_as_str() {
            //    self.path = path[1..].join("/");
            if self.path.starts_with(&(concat(&self.prefix, &e.short_name_as_str()) + "/")) {
                return FatEntryState::VISIT;
            } else {
                return FatEntryState::NEXT;
            }
        }
    }

    fn enter(&mut self, dir: DirEntry) {
        self.prefix += &(dir.short_name_as_str() + &"/".to_owned());
        // println!("enter self.prefix= {}", self.prefix);
    }

    fn exit(&mut self) {
        let mut p: Vec<&str> = self.prefix.split('/').collect();
        p.pop();
        self.prefix = p.join("/");
        // println!("exit self.prefix= {}", self.prefix);
    }
}

// Output a file to standard out.
struct CatCommand {
    path: String,
    prefix: String
}

impl FileAction for CatCommand {
    fn consume(&mut self, data: &[u8; 512], size: usize) {
        assert!(io::stdout().write_all(&data[0..size]).is_ok());
    }

    fn handle_file(&mut self, e: &DirEntry) -> FatEntryState {
        // println!("handle_file: self.prefix= {}", self.prefix);
        if self.path == [self.prefix.clone(), e.short_name_as_str()].concat() {
            return FatEntryState::VISIT;
        }
        return FatEntryState::NEXT;
    }
    fn handle_dir(&mut self, e: &DirEntry) -> FatEntryState {
        if self.path.starts_with(&[self.prefix.clone(), e.short_name_as_str(), "/".to_string()].concat()) {
            return FatEntryState::VISIT;
        } else {
            return FatEntryState::NEXT;
        }
    }
    fn enter(&mut self, dir: DirEntry) {
        self.prefix += &(dir.short_name_as_str() + &"/".to_owned());
    }
    fn exit(&mut self) {
        let mut p: Vec<&str> = self.prefix.split('/').collect();
        p.pop();
        self.prefix = p.join("/");
    }
}

// List the entire file system.
struct ListFs {
    prefix: Vec<String>,
}

impl FileAction for ListFs {
    fn consume(&mut self, _data: &[u8; 512], _size: usize) {
        panic!("");
    }

    fn handle_file(&mut self, e: &DirEntry) -> FatEntryState {
        for x in &self.prefix {
            print!("{}/", x);
        }
        e.print();
        return FatEntryState::NEXT;
    }
    fn handle_dir(&mut self, e: &DirEntry) -> FatEntryState {
        e.print();
        return FatEntryState::VISIT;
    }
    fn enter(&mut self, dir: DirEntry) {
        self.prefix.push(dir.short_name_as_str());
    }
    fn exit(&mut self) {
        self.prefix.pop();
    }
}

struct SelftestCommand {
    prefix: Vec<DirEntry>,
    hasher: Sha256
}

impl FileAction for SelftestCommand {

    fn consume(&mut self, data: &[u8; 512], size: usize) {
        self.hasher.input(data[..size].as_ref());
    }

    fn handle_file(&mut self, entry: &DirEntry) -> FatEntryState {
        // On OSX, some services create files on the volume in the
        // background, e.g., the file system indexer. Ignore
        // files, that do not consist of 8 hexadecimal characters.
        for c in entry.short_name_as_str().chars() {
            if !c.is_digit(16) {
                return FatEntryState::NEXT;
            }
        }
        return FatEntryState::VISIT;
    }

    fn handle_dir(&mut self, _e: &DirEntry) -> FatEntryState {
        return FatEntryState::VISIT;
    }

    fn enter(&mut self, name: DirEntry) {
        println!("enter: {}", name.short_name_as_str());
        self.prefix.push(name);
    }

    fn exit(&mut self) {
        let entry = self.prefix.pop().unwrap();
        println!("exit: {}", entry.short_name_as_str());
        if entry.is_file() {
            let old_hasher = mem::replace(&mut self.hasher, Sha256::new());
            let result = old_hasher.result();
            // Convert binary hash into hex string and compare with file name.
            let s = format!("{:02X?}{:02X?}{:02X?}{:02X?}", result[0], result[1], result[2], result[3]);
            assert_eq!(s, entry.short_name_as_str());
        }
    }
}

struct FindCommand {
    path: String,
    prefix: String,
    entry: Option<DirEntry>
}

fn concat(a: &str, b: &str) -> String {
    if a == "" {
        return b.to_string();
    }
    if a.ends_with(&"/".to_string()) {
        return [a, b].concat();
    }
    return [a, &"/".to_string(), b].concat();
}

impl FileAction for FindCommand {

    fn consume(&mut self, _data: &[u8; 512], _size: usize) {
        panic!("");
    }

    fn handle_file(&mut self, e: &DirEntry) -> FatEntryState {
        if self.path == concat(&self.prefix, &e.short_name_as_str()) {
            assert!(self.entry.is_none());
            self.entry = Some(*e);
        }
        return FatEntryState::NEXT;
    }

    fn handle_dir(&mut self, e: &DirEntry) -> FatEntryState {
        println!("self.path = {}, self.prefix= {}", self.path, self.prefix);
        if self.path == concat(&self.prefix, &e.short_name_as_str()) {
            assert!(self.entry.is_none());
            self.entry = Some(*e);
            return FatEntryState::NEXT;
        } else {
            // let path: Vec<&str> = self.path.split('/').collect();
            //if path[1] == e.short_name_as_str() {
            //    self.path = path[1..].join("/");
            if self.path.starts_with(&(concat(&self.prefix, &e.short_name_as_str()) + "/")) {
                return FatEntryState::VISIT;
            } else {
                return FatEntryState::NEXT;
            }
        }
    }

    fn enter(&mut self, dir: DirEntry) {
        self.prefix += &(dir.short_name_as_str() + &"/".to_owned());
        //println!("enter self.prefix= {}", self.prefix);
    }

    fn exit(&mut self) {
        let mut p: Vec<&str> = self.prefix.split('/').collect();
        p.pop();
        self.prefix = p.join("/");
        //println!("exit self.prefix= {}", self.prefix);
    }
}

impl DirEntry {

}

struct ClusterItr<'a> {
    fat: &'a mut Fat32Media,
    entry: FatEntry,
    sector: u32,
}

struct FileItr<'a> {
    cluster_itr: ClusterItr<'a>,
    remaining: u32
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct FatEntry {
    val: u32,
}

impl FatEntry {
    fn new(val: u32) -> FatEntry {
        FatEntry { val: val }
    }

    fn read(&self) -> u32 {
        return self.val & 0x0FFFFFFF;
    }

    fn update(&mut self, new_val: u32) {
        self.val = (self.val & 0xF0000000) | (new_val & 0x0FFFFFFF);
    }

    fn is_empty(&self) -> bool {
        self.read() == 0
    }

    fn is_end_of_chain(&self) -> bool {
        self.read() >= 0x0FFFFFF8
    }
}

impl PartialEq for FatEntry {
    fn eq(&self, other: &Self) -> bool {
        return self.read() == other.read();
    }
}

impl Fat32Media {

    fn first_sector_of_cluster(&self, n: u32) -> u32 {
        return ((n - 2) * self.bpb.sectors_per_cluster as u32) + first_data_sector(self);
    }

    fn touch(&mut self, path: String) -> Result<DirEntry, i32> {
        assert!(!path.ends_with("/"));

        // get parent
        let parent = std::path::Path::new(&path).parent().unwrap();
        let file_name = std::path::Path::new(&path).file_name().unwrap().to_str().unwrap().to_string();
        assert!(file_name.len() <= 8);
        let e = self.get_entry(parent.to_str().unwrap().to_string());
        if !e.is_some() {
            return Err(libc::ENOENT);
        }

        // allocate entry in parent.cluster_id
        for sector in 0..self.bpb.sectors_per_cluster {
            let mut data = [0u8; 512];

            self.read_sector_of_cluster(sector, e.unwrap().cluster_number(), &mut data);
            for i in 0..data.len() / core::mem::size_of::<DirEntry>() {
                let entry: DirEntry = unsafe {
                    mem::transmute_copy(&data[core::mem::size_of::<DirEntry>()*i])
                };
                // println!("{} {} {:?} is_long= {}", line!(), i, entry, entry.is_long_name());

                if !entry.is_free() {
                    continue;
                }

                data[i*32..(i+1)*32].copy_from_slice(&(DirEntry::new(file_name.clone()).to_bytes()));
                self.write_sector_of_cluster(sector, e.unwrap().cluster_number(), data);
                return Ok(entry);
            }
        }

        // if insufficient space {
        //     extend cluster chain for cluster id by 1 cluster
        //     allocate entry in cluster id
        // }
        Err(libc::ENOSPC)
    }

    fn mkdir(&mut self, path: String) -> Result<DirEntry, i32> {
        // get parent
        // allocate entry in parent.cluster_id
        // if insufficient space {
        //    extend cluster chain for parent.cluster_id by 1 cluster
        //    allocate entry in parent.cluster_id
        // }
        Err(-1)
    }

    /// Return the FAT32 entry for a given cluster number.
    fn cluster_number_to_fat32_entry(&mut self, cluster_nr: u32) -> FatEntry {
        let offset_within_fat: u32 = cluster_nr * FAT32_BYTES_PER_FAT_ENTRY;
        let sector = self.bpb.reserved_sectors as u32 + offset_within_fat / (self.bpb.bytes_per_sec as u32);
        let offset_within_sector = offset_within_fat % self.bpb.bytes_per_sec as u32;
        let mut buf = [0; 4];

        let mut entries: Vec<FatEntry> = vec![];
        for i in 0..self.bpb.fat_copies {
            let offset_within_diskimage =
                512 * (self.mbr.partitions[0].offset_lba + i as u32 * self.fat32.secs_per_fat_32 + sector ) +
                offset_within_sector;
            assert!(self.f.seek(SeekFrom::Start(offset_within_diskimage.into())).is_ok());
            self.f.read_exact(&mut buf).expect("Error reading FAT32 entry.");

            let entry: FatEntry = { unsafe { mem::transmute(buf) } };
            entries.push(entry);
        }
        let first_entry = entries.pop().unwrap();
        for x in entries.into_iter() {
            assert_eq!(first_entry, x);
        }

        return first_entry;
    }

    fn find_free_fat32_entries(&mut self, count: usize) -> Option<Vec<u32>> {
        let fat_entry_size: u32 = 4;
        let sector_size: u32 = 512;
        let max_cluster_id = sector_size * self.fat32.secs_per_fat_32 / fat_entry_size;
        let mut entries: Vec<u32> = vec![];
        for i in 0..max_cluster_id {
            let entry = self.cluster_number_to_fat32_entry(i);
            if entry.is_empty() {
                entries.push(i);
                if entries.len() == count {
                    return Some(entries);
                }
            }
        }
        return None;
    }

    pub fn cluster_iter(&mut self, entry: FatEntry) -> ClusterItr {
        ClusterItr {fat: self, entry: entry, sector: 0}
    }

    pub fn file_iter(&mut self, cluster_id: FatEntry, remaining: u32) -> FileItr {
        FileItr {cluster_itr: ClusterItr {fat: self, entry: cluster_id, sector: 0},
                 remaining: remaining}
    }
}

// Iterate over all sectors of a cluster chain. Used, for example, for
// directories.
impl Iterator for ClusterItr<'_> {
    type Item = [u8; 512];
    fn next(&mut self) -> Option<Self::Item> {
        if self.entry.is_end_of_chain() {
            return None
        }
        let mut data = [0; 512];
        let sector = self.fat.first_sector_of_cluster(self.entry.read()) + self.sector as u32;
        let file_offset = 512 * self.fat.mbr.partitions[0].offset_lba as u64 + sector as u64 * 512;
        assert!(self.fat.f.seek(SeekFrom::Start(file_offset.into())).is_ok());
        self.fat.f.read_exact(&mut data).expect("Error reading sector.");

        self.sector += 1;
        if self.sector == self.fat.bpb.sectors_per_cluster as u32 {
            self.entry = self.fat.cluster_number_to_fat32_entry(self.entry.read());
            self.sector = 0;
        }
        Some(data)
    }
}

// Iterate over all sectors of a file. Must explicitly specify the
// file's size when instantiating the iterator. Uses ClusterItr under
// the hood.
impl Iterator for FileItr<'_> {
    type Item = [u8; 512];
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            None
        } else {
            if self.remaining < 512 {
                self.remaining = 0;
            } else {
                self.remaining -= 512;
            }
            self.cluster_itr.next()
        }
    }
}

// For FAT32 even the root directory is a variable-sized cluster
// chain. Read the sectors and follow the chain to visit each
// directory entry.
impl<'a> Fat32Media {

    // `filename` of disk image
    fn new(filename: String) -> Fat32Media {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&filename).expect("Unable to open file");

        let mbr: MasterBootRecord = {
            let mut data = [0; 512];
            f.read_exact(&mut data).expect("Unable to read data");
            unsafe { mem::transmute(data) }
        };

        let bpb: BIOSParameterBlock = {
            let mut bpb_data = [0; 36];
            assert!(f.seek(SeekFrom::Start((512 * mbr.partitions[0].offset_lba) as u64)).is_ok());
            f.read_exact(&mut bpb_data).expect("Unable to read bpb data");
            unsafe { mem::transmute(bpb_data) }
        };

        let fat32: Fat32 = {
            let mut fat32_data = [0; 54];
            assert!(f.seek(SeekFrom::Start(((512 * mbr.partitions[0].offset_lba) + 36) as u64)).is_ok());
            f.read_exact(&mut fat32_data).expect("Unable to read fat32 data");
            unsafe { mem::transmute(fat32_data) }
        };

        assert!(bpb.bytes_per_sec == 512);

        Fat32Media { f: f, mbr: mbr, bpb: bpb, fat32: fat32, }
    }

    fn parse_directory(&'a mut self, cluster_id: u32, handler: &mut dyn FileAction) {

        let mut long_name: [u16;LONG_NAME_MAX_CHARS] = [0;LONG_NAME_MAX_CHARS];
        let mut visit_dir: Vec<DirEntry> = vec![];
        let mut visit_files: Vec<DirEntry> = vec![];

        for sector_data in self.cluster_iter(FatEntry::new(cluster_id)) {
            let entries_per_sector = sector_data.len() / core::mem::size_of::<DirEntry>();
            for i in 0..entries_per_sector {
                let dir_entry: DirEntry = unsafe {
                    mem::transmute_copy(&sector_data[core::mem::size_of::<DirEntry>()*i])
                };
                let long_entry: LongEntry = unsafe {
                    mem::transmute_copy(&sector_data[core::mem::size_of::<LongEntry>()*i])
                };

                // Special case where all subsequent entries are free and need
                // not be examined.
                if dir_entry.name[0] == 0x0 {
                    break;
                }

                let free_entry: u8 = 0xE5;
                if dir_entry.name[0] != free_entry {
                    // dir_entry.print();

                    if dir_entry.is_long_name() {
                        // assemble long name
                        if (long_entry.ord & LAST_LONG_ENTRY) != 0 {
                            long_name = [0; LONG_NAME_MAX_CHARS];
                        }

                        let ord = long_entry.ord & LONG_ENTRY_ORD_MASK;
                        let start: usize = (CHARS_PER_LONG_ENTRY*(ord-1) as u32).try_into().unwrap();
                        let end  : usize = (CHARS_PER_LONG_ENTRY*(ord) as u32).try_into().unwrap();
                        // print!("start={} end={} ", start, end);
                        let slc = &mut long_name[start..end];
                        slc.copy_from_slice(&long_entry.name());

                        if ord == 1 {
                            // String::from_utf16() will happily build
                            // a string containing a NUL character in
                            // the middle. Hence, we need to find the
                            // NUL character (if any) and only output
                            // the characters up to that point. In
                            // case the file name is a multiple of 13
                            // characters long, there will not be a
                            // terminating NUL character.
                            let mut long_name_len = LONG_NAME_MAX_CHARS;
                            for (i, elem) in long_name.iter().enumerate() {
                                if *elem == 0x0 {
                                    long_name_len = i;
                                    break;
                                }
                            }
                            // println!("long name is {}", String::from_utf16(&long_name[0..long_name_len]).unwrap());
                        }
                    }

                    if dir_entry.is_file() {
                        match handler.handle_file(&dir_entry) {
                            FatEntryState::NEXT => (),
                            FatEntryState::VISIT => visit_files.push(dir_entry)
                        }

                    } else if dir_entry.is_directory() {
                        // Skip . and ..

                        if dir_entry.is_dot_entry() || dir_entry.is_dot_dot_entry() {
                            continue;
                        }

                        match handler.handle_dir(&dir_entry) {
                            FatEntryState::VISIT => visit_dir.push(dir_entry),
                            FatEntryState::NEXT => (),
                        }
                    }
                }
                if dir_entry.name[0] == 0x00 {
                    break;
                }
            }
            // println!("");
        }

        for dir in visit_dir {
            handler.enter(dir);
            self.parse_directory(dir.cluster_number(), handler);
            handler.exit();
        }

        for f in visit_files {
            handler.enter(f);
            // println!("visit_file {:?}", f);
            let mut remaining: usize = f.file_size.try_into().unwrap();
            for sector_data in self.file_iter(FatEntry::new(f.cluster_number()), f.file_size) {
                assert!(remaining > 0);
                handler.consume(&sector_data, std::cmp::min(remaining, 512));
                if remaining >= 512 {
                    remaining -= 512;
                } else {
                    remaining = 0;
                }
            }
            handler.exit();
        }
    }

    /// Construct a DirEntry with the root directory cluster id.  The
    /// root directory's cluster id is *not* stored in the File
    /// Allocate Table.
    fn root(&self) -> DirEntry {
        let mut e = DirEntry::new("".to_string());
        e.first_cluster_low = self.fat32.root_cluster.try_into().unwrap();
        e
    }

    /// Returns DirEntry for a given file or directory or None if no
    /// such entry exists.
    fn get_entry(&'a mut self, path: String) -> Option<DirEntry> {
        let p = std::path::Path::new(&path);
        let mut entry: Option<DirEntry> = Some(self.root());

        for component in p.components() {
            if component == std::path::Component::RootDir {
                continue;
            }

            println!("{} {} {:?}", line!(), entry.unwrap().cluster_number(), component.as_os_str().to_str());
            entry = self.get_entry_in_dir(entry.unwrap().cluster_number(), component.as_os_str().to_str().unwrap().to_string());
            println!("{} {:?}", line!(), entry);

            if !entry.is_some() {
                return None
            }
        }
        return entry;
    }

    /// Returns DirEntry for a file or directory within a specific directory (cluster_id).
    fn get_entry_in_dir(&'a mut self, cluster_id: u32, short_name: String) -> Option<DirEntry> {
        assert!(short_name.len() <= 12);
        assert!(short_name.contains("/") == false);

        let mut action = FindCommand { path: short_name, prefix: "".to_string(), entry: None };
        self.parse_directory(cluster_id, &mut action);
        return action.entry;
    }

    /// Updates a specific sector of a cluster.
    fn write_sector_of_cluster(&mut self, sector: u8, cluster: u32, data: [u8; 512]) {
        assert!(sector < self.bpb.sectors_per_cluster);
        assert!(cluster < count_of_clusters(&self.bpb, &self.fat32));

        let file_offset = (self.first_sector_of_cluster(cluster) +
                           sector as u32 + self.mbr.partitions[0].offset_lba) * 512;
        assert!(self.f.seek(SeekFrom::Start(file_offset.into())).is_ok());

        let mut r = self.f.write_all(&data);
        assert!(r.is_ok());
        r = self.f.sync_all();
        assert!(r.is_ok());
    }

    fn read_sector_of_cluster(&mut self, sector: u8, cluster: u32, data: &mut [u8; 512]) {
        let file_offset = (self.first_sector_of_cluster(cluster) +
                           sector as u32 + self.mbr.partitions[0].offset_lba) * 512;
        assert!(self.f.seek(SeekFrom::Start(file_offset.into())).is_ok());

        let r = self.f.read_exact(data);
        assert!(r.is_ok());
    }
}

// http://stackoverflow.com/questions/31192956/whats-the-de-facto-way-of-reading-and-writing-files-in-rust-1-x
fn main() {
    let opts: Opts = Opts::parse();
    let mut fat = Fat32Media::new(opts.diskimage);

    assert!(fat.mbr.sig[0] == 0x55);
    assert!(fat.mbr.sig[1] == 0xAA);
    
    // FAT12/16 size. Must be zero for FAT32.
    assert!(fat.bpb.total_secs_16 == 0);
    assert!(fat.bpb.secs_per_fat_16 == 0);
    assert!(fat.bpb.total_secs_32 != 0);

    // println!("{:?}", fat.fat32);
    // Can only handle FAT32 major:minor equal to 0:0.
    assert!(fat.fat32.fs_ver == 0);
    // println!("struct MasterBootRecord has {:?} bytes", core::mem::size_of::< MasterBootRecord >());
    // println!("struct BIOSParameterBlock has {:?} bytes", core::mem::size_of::< BIOSParameterBlock >());

    assert!(core::mem::size_of::<DirEntry>() == 32);

    // println!("Cluster count is {:?}", count_of_clusters(&fat.bpb, &fat.fat32));
    // println!("First data sector is {:?}", first_data_sector(&fat));
    // println!("First sector of root directory cluster {:?}",
    //         first_sector_of_cluster(fat.fat32.root_cluster, &fat));

    let root_cluster = fat.fat32.root_cluster;
    match opts.subcmd {
        SubCommand::Cat(t) => {
            let mut action = CatCommand {
                path: t.path,
                prefix: "".to_string()
            };
            fat.parse_directory(root_cluster, &mut action);
        },
        SubCommand::Info(_t) => {
            println!("{:?}", fat.mbr);
            println!("{:?}", fat.bpb);
            println!("{:?}", fat.fat32);
            println!("Volume label: {}", str::from_utf8(&fat.fat32.vol_label).unwrap());
        },
        SubCommand::Ls(t) => {
            let mut action: LsCommand = LsCommand {
                path: t.path,
                prefix: "/".to_string(),
                entries: vec![]
            };
            fat.parse_directory(root_cluster, &mut action);
            for e in &action.entries {
                e.print();
            }
        },
        SubCommand::ListFsCommand(_t) => {
            let mut action = ListFs {
                prefix: vec![]
            };
            fat.parse_directory(root_cluster, &mut action);
        },
        SubCommand::Selftest(_t) => {
            let mut action = SelftestCommand {
                prefix: vec![],
                hasher: Sha256::new()
            };
            fat.parse_directory(root_cluster, &mut action);
        },
    }
}

#[cfg(test)]
mod test {
    use super::Fat32Media;
    use LsCommand;

    #[test]
    fn basics() {
        let mut fat = Fat32Media::new("test.img".to_string());
        // let entry = fat.get_entry("0".to_string());;
        // assert!(entry.is_some());
        // println!("{:?}", entry.unwrap());

        let entry = fat.get_entry("/0/B4913481".to_string());
        assert!(entry.is_some());

        // let entry = fat.get_entry_in_dir(fat.fat32.root_cluster, "0".to_string());
        // assert!(entry.is_some());
    }

    #[test]
    fn test_ls_01() {
        let mut fat = Fat32Media::new("testcase_01.img".to_string());
        let mut action: LsCommand = LsCommand::new("/".to_string());
        fat.parse_directory(fat.fat32.root_cluster, &mut action);

        let mut x = action.entries.iter().map(|x| x.short_name_as_str()).collect::<Vec<String>>();
        x.sort();
        assert_eq!(x, (0..10).map(|x| x.to_string()).collect::<Vec<String>>());
        for e in &action.entries {
            assert!(e.is_directory());
        }

        action = LsCommand::new("/1/".to_string());
        fat.parse_directory(fat.fat32.root_cluster, &mut action);
        let x = action.entries.iter().map(|x| x.short_name_as_str()).collect::<Vec<String>>();
        let expected_entries = ["66EC94BA", "83186062", "590D2E74", "EE45872D", "897965E7", "E4CB5817"].iter().map(|x| x.to_string()).collect::<Vec<String>>();
        for expected in &expected_entries {
            assert!(x.contains(expected));
        }

        action = LsCommand::new("/nonexist/".to_string());
        fat.parse_directory(fat.fat32.root_cluster, &mut action);
        assert!(action.entries.is_empty());

        action = LsCommand::new("/4/E9068190".to_string());
        fat.parse_directory(fat.fat32.root_cluster, &mut action);
        let x = action.entries.iter().map(|x| x.short_name_as_str()).collect::<Vec<String>>();
        assert!(x.contains(&"E9068190".to_string()));
    }

    #[test]
    fn test_find_free_fat32_entry() {
        let mut fat = Fat32Media::new("testcase_01.img".to_string());
        println!("{:?} ", fat.find_free_fat32_entries(10));
        println!("FAT[0]= {:X?} ", fat.cluster_number_to_fat32_entry(0));
        println!("FAT[1]= {:X?} ", fat.cluster_number_to_fat32_entry(1));
    }

    use DirEntry;
    #[test]
    #[should_panic]
    fn test_DirEntry_new() {
        let e = DirEntry::new("thisnameistoolong".to_string());
    }

    #[test]
    fn test_touch() {
        let mut fat = Fat32Media::new("testcase_02.img".to_string());
        assert_eq!(fat.touch("/0/1".to_string()).unwrap_err(), libc::ENOENT);
        // On OSX, the newly formatted volume can hold 13 additional
        // entries in its root directory before we need to allocate a
        // new cluster. Each 512 byte sector can hold 16 `DirEntry`
        // entries. One entry is occopied by the VOLUME_ID. Two more
        // entries (one long!) are occupied by the FSEVEN~1 directory
        // which gets automatically created by OSX. Hence, we can
        // create 13 more entries, we need to allocate a new cluster
        // to hold additional entries.
        for i in 0..13 {
            assert!(fat.touch("/".to_string()+&i.to_string()).is_ok());
        }
        assert_eq!(fat.touch("/14".to_string()).unwrap_err(), libc::ENOSPC);
    }
}
