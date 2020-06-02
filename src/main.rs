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

#[derive(Debug)]
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
#[derive(Debug)]
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

#[derive(Debug)]
#[repr(C)]
struct Fat12and16Block {
    drive_nr: u8,
    reserved1: u8,
    boot_sig: u8,
    vol_id: u32,
    vol_label: [u8; 11],
    file_sys_type: [u8; 8]
}

#[derive(Debug)]
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

#[derive(Debug)]
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
#[derive(Debug)]
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

const ATTR_LONG_NAME:u8 = (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID );
const ATTR_LONG_NAME_MASK:u8 = (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID |
                                ATTR_DIRECTORY | ATTR_ARCHIVE);

// fn is_attr_long_name(e: &DirEntry) -> bool {
//     return (e.attr & ( ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID ));
// }

fn print_DirEntry(e: &DirEntry) {
   let r = str::from_utf8(&e.name);
   if r.is_err() {
      println!("name contains invalid charaters.");
      return;
   }

   if e.attr == ATTR_LONG_NAME_MASK {
       println!("ATTR_LONG_NAME_MASK");
   } else if e.attr == ATTR_LONG_NAME {
       println!("ATTR_LONG_NAME");
   } else if (e.attr & ATTR_VOLUME_ID) != 0 {
       println!("Volume name is {}", r.unwrap());
   } else if (e.attr & ATTR_DIRECTORY) != 0 {
       println!("{} {} {} (dir), cluster #: {}", r.unwrap(), e.name[0], e.name[1], cluster_number(e));
   } else {
       println!("{} [size {} byte(s), 1st cluster #: {}]", r.unwrap(), e.file_size, cluster_number(e));
   }
}

//use std::io;
use std::io::prelude::*;
use std::fs::File;
// use std::io::Read;
//use std::slice;
use std::mem;
use std::io::SeekFrom;
use std::str;
use std::cmp;

extern crate sha2;
use sha2::{Sha256, Digest};

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

fn total_secs(bpb: &BIOSParameterBlock, fat32: &Fat32) -> u32 {
    if bpb.total_secs_16 != 0 {
        return bpb.total_secs_16 as u32;
    } else {
        assert!(bpb.total_secs_32 != 0);
        return bpb.total_secs_32;
    }
}

fn data_secs(bpb: &BIOSParameterBlock, fat32: &Fat32) -> u32 {
    return total_secs(&bpb, &fat32) - (bpb.reserved_sectors as u32 +
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

const FAT32_Bytes_Per_Fat_Entry: u32 = 4;

/// Return the FAT32 entry for a given cluster number.
fn cluster_number_to_fat32_entry(fat: &mut Fat32Media, cluster_nr: u32) -> u32 {
   let fat_offset: u32 = cluster_nr * FAT32_Bytes_Per_Fat_Entry;
   let sector = fat.bpb.reserved_sectors as u32 + fat_offset / (fat.bpb.bytes_per_sec as u32);
   let offset = fat_offset % fat.bpb.bytes_per_sec as u32;
   let mut buf = [0; 4];

   let file_offset = 512 * fat.mbr.partitions[0].offset_lba + sector * 512 + offset;
   fat.f.seek(SeekFrom::Start(file_offset.into()));
   fat.f.read_exact(&mut buf).expect("Error reading FAT32 entry.");

   let mut entry: u32 = unsafe { mem::transmute(buf) };
   entry &= 0x0FFFFFFF;
   return entry;
}

fn cluster_number(e: &DirEntry) -> u32 {
   return e.first_cluster_low as u32 + ((e.first_cluster_high as u32) << 16);
}

// Most-significant 4 bits of a FAT32 entry are to be ignored.
fn is_eof(fat_entry: u32) -> bool {
    return fat_entry >= 0x0FFFFFFE;
}

fn check_file(e: &DirEntry, fat: &mut Fat32Media) -> bool {

    let mut hasher = Sha256::new();

    // Assume that our test case generator only creates files that are
    // a multiple of 512 in size.
    assert!(e.file_size % 512 == 0);
    let mut size = e.file_size;

    let mut cluster = cluster_number(&e);
    assert!(cluster != 0); // TODO handle empty files properly

    while !is_eof(cluster) {
        print!("{} ", cluster);
        for i in 0..fat.bpb.sectors_per_cluster {
            let mut sector_data = [0; 512];
            let sector = first_sector_of_cluster(cluster, fat) + i as u32;
            let file_offset = 512 * fat.mbr.partitions[0].offset_lba as u64 + sector as u64 * 512;
            fat.f.seek(SeekFrom::Start(file_offset.into()));
            fat.f.read_exact(&mut sector_data).expect("Error reading sector.");
            hasher.input(sector_data.as_ref());
            // println!("Sector {} data: {:x?}", i, &sector_data[0..32]);
        }
        cluster = cluster_number_to_fat32_entry(fat, cluster);
    }

    let result = hasher.result();

    // Convert binary hash into hex string and compare with file name.
    let s = format!("{:02X?}{:02X?}{:02X?}{:02X?}", result[0], result[1], result[2], result[3]);
    return s == str::from_utf8(&e.name[0..8]).ok().unwrap();
}

fn read_directory(fat: &mut Fat32Media, first_sector: u64) {
    let mut first_data_sec = [0; 512];
    let offset = 512 * fat.mbr.partitions[0].offset_lba as u64 +
                 first_sector * 512;
    fat.f.seek(SeekFrom::Start(offset));
    fat.f.read_exact(&mut first_data_sec).expect("Unable to read first_data_sec");

    for i in 0..16 {
        let mut dir_entry: DirEntry = unsafe { mem::transmute_copy(&first_data_sec[core::mem::size_of::<DirEntry>()*i]) };
        // println!("{:?}", dir_entry);

        // Special case where all subsequent entries are free and need
        // not be examined.
        if dir_entry.name[0] == 0x0 {
            break;
        }

        let free_entry: u8 = 0xE5;
        if dir_entry.name[0] != free_entry {
            print_DirEntry(&dir_entry);

            // This is a file.
            if (dir_entry.attr & ATTR_DIRECTORY) == 0 && (dir_entry.attr & ATTR_VOLUME_ID) == 0 {
                // let sec: u32 = first_sector_of_cluster(cluster_number(&dir_entry), &fat);
                // let mut data = [0; 512];
                // let offset: u64 = 512 * fat.mbr.partitions[0].offset_lba as u64 + (512 * sec) as u64;
                // fat.f.seek(SeekFrom::Start(offset));
                // fat.f.read_exact(&mut data).expect("Unable to read sector");
                // println!("{}", str::from_utf8(&data[0 .. cmp::min(512, dir_entry.file_size) as usize]).unwrap());
                assert!(check_file(&dir_entry, fat));
            } else if (dir_entry.attr & ATTR_LONG_NAME) != 0 {
                // skip long name entries
            } else if (dir_entry.attr & ATTR_DIRECTORY) != 0 {
                // Skip . and ..
                // 46 is '.' (dot); 32 is ' ' (space)
                let dot_name : [u8; 11] = [46, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32];
                let dotdot_name : [u8; 11] = [46, 46, 32, 32, 32, 32, 32, 32, 32, 32, 32];

                if (dir_entry.name != dot_name && dir_entry.name != dotdot_name) {
                    read_directory(fat, first_sector_of_cluster(cluster_number(&dir_entry), fat) as u64);
                }
            }
        }
        if dir_entry.name[0] == 0x00 {
            break;
        }
    }
    println!("");
}

// http://stackoverflow.com/questions/31192956/whats-the-de-facto-way-of-reading-and-writing-files-in-rust-1-x
fn main() {
    let mut f = File::open("test.img").expect("Unable to open file");
    let mbr: MasterBootRecord = {
       let mut data = [0; 512];
       f.read_exact(&mut data).expect("Unable to read data");
       unsafe { mem::transmute(data) }
    };
    let bpb = {
        let mut bpb_data = [0; 36];
        f.seek(SeekFrom::Start((512 * mbr.partitions[0].offset_lba) as u64));
        f.read_exact(&mut bpb_data).expect("Unable to read bpb data");
        unsafe { mem::transmute(bpb_data) }
    };

    let fat32: Fat32 = {
        let mut fat32_data = [0; 54];
        f.seek(SeekFrom::Start(((512 * mbr.partitions[0].offset_lba) + 36) as u64));
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
    
    println!("{:?}", fat.mbr.partitions[0]);

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
    println!("{:?}", fat.bpb);

    println!("{:?}", fat.fat32);
    // Can only handle FAT32 major:minor equal to 0:0.
    assert!(fat.fat32.fs_ver == 0);
    println!("struct MasterBootRecord has {:?} bytes", core::mem::size_of::< MasterBootRecord >());
    println!("struct BIOSParameterBlock has {:?} bytes", core::mem::size_of::< BIOSParameterBlock >());

    assert!(core::mem::size_of::<DirEntry>() == 32);

    println!("Cluster count is {:?}", count_of_clusters(&fat.bpb, &fat.fat32));
    println!("First data sector is {:?}", first_data_sector(&fat));
    println!("First sector of root directory cluster {:?}",
             first_sector_of_cluster(fat.fat32.root_cluster, &fat));

    // Read first sector of root directory
    let mut first_data_sec = [0; 512];
    let offset = 512 * fat.mbr.partitions[0].offset_lba as u64 +
                 first_sector_of_cluster(fat.fat32.root_cluster, &fat) as u64 * 512;
    let sector = first_sector_of_cluster(fat.fat32.root_cluster, &fat) as u64;
    read_directory(&mut fat, sector);

    // let first_fat_entry = (first_data_sec[0] as u32) +
    //                       ((first_data_sec[1] as u32) << 8) +
    //                       ((first_data_sec[2] as u32) << 16) +
    //                       ((first_data_sec[3] as u32) << 24);
    // print!("{:?},", first_data_sec);
    // println!("");
}
