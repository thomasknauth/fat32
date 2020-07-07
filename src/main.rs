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
struct DirEntry {
   name: [u8; 11],
   attr: u8,
   nt_reserved: u8,
   create_time_tenth: u8,
   create_time: u16,
   create_date: u16,
   last_access_date: u16,
   first_cluster_high: u16,
   write_time: u16,
   write_date: u16,
   first_cluster_low: u16,
   file_size: u32
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

// fn is_attr_long_name(e: &DirEntry) -> bool {
//     return (e.attr & ( ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID ));
// }

impl DirEntry {
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
}

use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{self, Write};
use std::mem;
use std::str;

extern crate clap;
use clap::Clap;
extern crate sha2;
use sha2::{Sha256, Digest};

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
struct Ls {
    #[clap(short, default_value = "/")]
    path: String
}

#[derive(Clap)]
struct Cat {
    #[clap(short)]
    path: String
}

#[derive(Clap)]
struct ListFsCommand {
}

#[derive(Clap)]
struct Selftest {
}

#[derive(Clap)]
struct Info {
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

fn first_sector_of_cluster(n: u32, fat: &Fat32Media) -> u32 {
   return ((n - 2) * fat.bpb.sectors_per_cluster as u32) + first_data_sector(fat);
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

/// Visit each element once.
///
/// 
trait Traverse {
    fn depth_first(&self);
}


impl Traverse for Fat32Media {
     fn depth_first(&self) {
         // for each entry E in directory D
             // if file: print E
             // else if directory: depth_first(E)
     }
}

const FAT32_BYTES_PER_FAT_ENTRY: u32 = 4;

/// Return the FAT32 entry for a given cluster number.
fn cluster_number_to_fat32_entry(fat: &mut Fat32Media, cluster_nr: u32) -> u32 {
   let fat_offset: u32 = cluster_nr * FAT32_BYTES_PER_FAT_ENTRY;
   let sector = fat.bpb.reserved_sectors as u32 + fat_offset / (fat.bpb.bytes_per_sec as u32);
   let offset = fat_offset % fat.bpb.bytes_per_sec as u32;
   let mut buf = [0; 4];

   let file_offset = 512 * fat.mbr.partitions[0].offset_lba + sector * 512 + offset;
   assert!(fat.f.seek(SeekFrom::Start(file_offset.into())).is_ok());
   fat.f.read_exact(&mut buf).expect("Error reading FAT32 entry.");

   let mut entry: u32 = unsafe { mem::transmute(buf) };
   entry &= 0x0FFFFFFF;
   return entry;
}

impl DirEntry {
    fn cluster_number(&self) -> u32 {
        return self.first_cluster_low as u32 + ((self.first_cluster_high as u32) << 16);
    }
}

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
    prefix: String
}

impl FileAction for LsCommand {

    fn consume(&mut self, _data: &[u8; 512], _size: usize) {
        panic!("");
    }

    fn handle_file(&mut self, e: &DirEntry) -> FatEntryState {
        if self.path == self.prefix {
            e.print();
        }
        return FatEntryState::NEXT;
    }

    fn handle_dir(&mut self, e: &DirEntry) -> FatEntryState {
        // println!("self.path = {}, self.prefix= {}", self.path, self.prefix);
        if self.path == self.prefix {
            e.print();
            return FatEntryState::NEXT;
        } else {
            // let path: Vec<&str> = self.path.split('/').collect();
            //if path[1] == e.short_name_as_str() {
            //    self.path = path[1..].join("/");
            if self.path.starts_with(&[self.prefix.clone(), e.short_name_as_str(), "/".to_string()].concat()) {
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

// Output a file to standard out.
struct CatCommand {
    path: String,
    prefix: String
}

impl FileAction for CatCommand {
    fn consume(&mut self, data: &[u8; 512], size: usize) {
        io::stdout().write_all(&data[0..size]);
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

impl DirEntry {

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
}

struct ClusterItr<'a> {
    fat: &'a mut Fat32Media,
    cluster_id: u32,
    sector: u32,
}

struct FileItr<'a> {
    cluster_itr: ClusterItr<'a>,
    remaining: u32
}

impl Fat32Media {

    pub fn cluster_iter(&mut self, cluster_id: u32) -> ClusterItr {
        ClusterItr {fat: self, cluster_id: cluster_id, sector: 0}
    }

    pub fn file_iter(&mut self, cluster_id: u32, remaining: u32) -> FileItr {
        FileItr {cluster_itr: ClusterItr {fat: self, cluster_id: cluster_id, sector: 0},
                 remaining: remaining}
    }
}

// Iterate over all sectors of a cluster chain. Used, for example, for
// directories.
impl Iterator for ClusterItr<'_> {
    type Item = [u8; 512];
    fn next(&mut self) -> Option<Self::Item> {
        if is_eof(self.cluster_id) {
            return None
        }
        let mut data = [0; 512];
        let sector = first_sector_of_cluster(self.cluster_id, &self.fat) + self.sector as u32;
        let file_offset = 512 * self.fat.mbr.partitions[0].offset_lba as u64 + sector as u64 * 512;
        assert!(self.fat.f.seek(SeekFrom::Start(file_offset.into())).is_ok());
        self.fat.f.read_exact(&mut data).expect("Error reading sector.");

        self.sector += 1;
        if self.sector == self.fat.bpb.sectors_per_cluster as u32 {
            self.cluster_id = cluster_number_to_fat32_entry(&mut self.fat, self.cluster_id);
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
impl Fat32Media {

    fn parse_directory(&mut self, cluster_id: u32, handler: &mut dyn FileAction) {

        let mut long_name: [u16;LONG_NAME_MAX_CHARS] = [0;LONG_NAME_MAX_CHARS];
        let mut visit_dir: Vec<DirEntry> = vec![];
        let mut visit_files: Vec<DirEntry> = vec![];

        for sector_data in self.cluster_iter(cluster_id) {
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
            for sector_data in self.file_iter(f.cluster_number(), f.file_size) {
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
}

// http://stackoverflow.com/questions/31192956/whats-the-de-facto-way-of-reading-and-writing-files-in-rust-1-x
fn main() {
    let opts: Opts = Opts::parse();

    let mut f = File::open(&opts.diskimage).expect("Unable to open file");
    let mbr: MasterBootRecord = {
       let mut data = [0; 512];
       f.read_exact(&mut data).expect("Unable to read data");
       unsafe { mem::transmute(data) }
    };
    let bpb = {
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
    
    let mut fat = Fat32Media {
        f: f,
        mbr: mbr,
        bpb: bpb,
        fat32: fat32
    };

    // assert!(data[510] == 0x55);
    // assert!(data[511] == 0xAA);
    assert!(fat.mbr.sig[0] == 0x55);
    assert!(fat.mbr.sig[1] == 0xAA);
    
    // println!("{:?}", fat.mbr.partitions[0]);

    // let mut bpb_data = [0; 36];
    // f.seek(SeekFrom::Start((512 * fat.mbr.partitions[0].offset_lba) as u64));
    // f.read_exact(&mut bpb_data).expect("Unable to read bpb data");
    // let mut bpb: BIOSParameterBlock = unsafe { mem::transmute(bpb_data) };
    
    // FAT12/16 size. Must be zero for FAT32.
    assert!(fat.bpb.total_secs_16 == 0);
    assert!(fat.bpb.secs_per_fat_16 == 0);
    assert!(fat.bpb.total_secs_32 != 0);

    // root_dir_secs = ((
    // println!("{:?}", str::from_utf8(&bpb.oem_name).unwrap());
    // println!("{:?}", fat.bpb);

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

    // Read first sector of root directory
    // let mut first_data_sec = [0; 512];
    // let offset = 512 * fat.mbr.partitions[0].offset_lba as u64 +
    //              first_sector_of_cluster(fat.fat32.root_cluster, &fat) as u64 * 512;
    let root_cluster = fat.fat32.root_cluster;
    match opts.subcmd {
        SubCommand::Info(_t) => {
            println!("{:?}", fat.mbr);
        },
        SubCommand::Selftest(_t) => {
            let mut action = SelftestCommand {
                prefix: vec![],
                hasher: Sha256::new()
            };
            fat.parse_directory(root_cluster, &mut action);
        },
        SubCommand::Ls(t) => {
            let mut action = LsCommand {
                path: t.path,
                prefix: "/".to_string()
            };
            fat.parse_directory(root_cluster, &mut action);
        },
        SubCommand::ListFsCommand(_t) => {
            let mut action = ListFs {
                prefix: vec![]
            };
            fat.parse_directory(root_cluster, &mut action);
        },
        SubCommand::Cat(t) => {
            let mut action = CatCommand {
                path: t.path,
                prefix: "/".to_string()
            };
            fat.parse_directory(root_cluster, &mut action);
        }
    }

    // let first_fat_entry = (first_data_sec[0] as u32) +
    //                       ((first_data_sec[1] as u32) << 8) +
    //                       ((first_data_sec[2] as u32) << 16) +
    //                       ((first_data_sec[3] as u32) << 24);
    // print!("{:?},", first_data_sec);
    // println!("");
}
