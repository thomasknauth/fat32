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

// 2020-08-14 OSX creates files in .fseventsd when unmounting the
// volume. I was confused by my implementation showing files that did
// not show up when the volume was mounted on OSX (e.g.,
// /.fseventsd/000000~1). Indeed, these files are only present in the
// unmounted volume. I suppose they contain OSX meta-data; The `file`
// utility reports the files to contain gzip'ed data.
//
// Also learned a bit about how OSX implements long file names for
// FAT. Essentially, mapping long names to short names is a best
// effort. A crazy implementation could even just generate random
// short names for each long name. The only hard restriction is that
// names must be unique in each directory. The only problem with this
// underspecified process of mapping long names to short names is that
// files created with an implementation that supports long names may
// be difficult to find when accessed with an implementation that only
// supports short names.
//
// For example, OSX maps the long name "README.diskdefines" to the
// short name READM~1.DIS. I would have expected the short name to be
// README.DIS. Not sure why OSX uses tail numbers in this case. There
// is also no file with a similar name in the directory. Similarly,
// OSX maps the long name "A B C" to the short name "AB~1".
//
// According to the specification it is perfectly fine to map "this is
// my long file name.ext" to "42.ext". I think I will use that freedom
// to keep my implementation of mapping long names to short names
// simple.


#[derive(Debug,Default,Copy,Clone)]
#[repr(C)]
#[repr(packed)]
struct PartitionTable { // Offset in bytes
    active: u8,         // 0
    start_c: u8,        // 1
    start_h: u8,        // 2
    start_s: u8,        // 3
    partition_type: u8, // 4
    end_c: u8,          // 5
    end_h: u8,          // 6
    end_s: u8,          // 7
    offset_lba: u32,    // 8
    size_sectors: u32   // 12
}

const PART_TYPE_FAT32_WITH_LBA_ADDRESSING: u8 = 11;

impl PartitionTable {
    /// Construct a new partition table entry covering `sz` bytes.
    fn new(sz: usize) -> PartitionTable {
        let mut x = PartitionTable::default();
        x.start_c = 254;
        x.start_h = 255;
        x.start_s = 255;
        x.partition_type = PART_TYPE_FAT32_WITH_LBA_ADDRESSING;
        x.end_c = 254;
        x.end_h = 255;
        x.end_s = 255;
        // This value seems to grow with parition size. 128M disk has 63 here, while 2G disk has 2048.
        x.offset_lba = 63;
        x.size_sectors = (sz / 512) as u32 - x.offset_lba;
        x
    }
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

const _: [u8; 36] = [0; std::mem::size_of::<BIOSParameterBlock>()];

impl BIOSParameterBlock {
    fn new(p: &PartitionTable) -> BIOSParameterBlock {
        BIOSParameterBlock {
            jmp: [0xEB, 0x00, 0x90],
            oem_name: [0; 8],
            bytes_per_sec: 512,
            sectors_per_cluster: 4,
            reserved_sectors: 32,
            fat_copies: 1, // Who needs redundancy? No risk, no fun.
            root_dir_entries: 0,
            total_secs_16: 0,
            media_type: 0xF8,
            secs_per_fat_16: 0,
            sectors_per_track: 0,
            number_of_heads: 0,
            hidden_sectors: p.offset_lba,
            total_secs_32: p.size_sectors
        }
    }

    /// Calculate size (in sectors) of a single FAT32 data structure. Base
    /// on (adapted for FAT32 only) formula from p21 of fatgen103.pdf.
    fn fat32_size(&self) -> u32 {

        let tmpval1: u32 = self.total_secs_32 - (self.reserved_sectors as u32);
        let tmpval2: u32 = ((256 * (self.sectors_per_cluster as u32)) + (self.fat_copies as u32)) / 2;

        (tmpval1 + (tmpval2 - 1)) / tmpval2
    }
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

const _: [u8; 54] = [0; std::mem::size_of::<Fat32>()];

/// Determine number of sectors per cluster based on
/// `disk_size_bytes`.
///
/// See p20 of fatgen103.pdf for an explanation.
fn size_to_sectors_per_cluster(disk_size_bytes: u32) -> u8 {

    const DiskTblFat32: [(u32, u8); 6] = [
        (66600, 0),
        (532480, 1),
        (16777216, 8),
        (33554432, 16),
        (67108864, 32),
        (u32::MAX, 64)
    ];

    for (sz, secs) in DiskTblFat32 {
        if sz <= disk_size_bytes {
            return secs;
        }
    }
    unreachable!();
}

impl Fat32 {
    fn new(bpb: &BIOSParameterBlock) -> Fat32 {
        Fat32 {
            secs_per_fat_32: bpb.fat32_size(),
            ext_flags: 0,
            fs_ver: 0,
            root_cluster: 2,
            fs_info: 1,
            backup_boot_sector: 0,
            reserved: [0; 12],
            drive_nr: 0x80,
            reserved1: 0,
            boot_sig: 0x29,
            vol_id: 0xDEADBEEF,
            vol_label: "MYRUSTYLOVE".as_bytes().try_into().unwrap(),
            file_sys_type: "FAT32   ".as_bytes().try_into().unwrap()
        }
    }
}

#[derive(Debug,Copy,Clone)]
#[repr(C)]
#[repr(packed)]
struct FsInfo {
    head_sig: [u8; 4],
    reserved_1: [u8; 480],
    struct_sig: [u8; 4],
    free_count: u32,
    next_free: u32,
    reserved_2: [u8; 12],
    tail_sig: [u8; 4]
}

impl FsInfo {
    fn default() -> FsInfo {
        FsInfo {
            head_sig: [0x52, 0x52, 0x61, 0x41],
            reserved_1: [0; 480],
            struct_sig: [0x72, 0x72, 0x41, 0x61],
            free_count: 0xFFFFFFFF,
            next_free: 0xFFFFFFFF,
            reserved_2: [0; 12],
            tail_sig: [0x00, 0x00, 0x55, 0xAA]
        }
    }
}

// Compile-time assert for the size of struct.
const _: [u8; 512] = [0; std::mem::size_of::<FsInfo>()];

#[derive(Debug,Copy,Clone)]
#[repr(C)]
#[repr(packed)]
struct MasterBootRecord {
    bootstrap_code: [u8; 446],
    partitions: [PartitionTable; 4],
    sig: [u8; 2]
}

// Compile-time assert for the size of struct MasterBootRecord.
const _: [u8; 512] = [0; std::mem::size_of::<MasterBootRecord>()];

impl MasterBootRecord {
    fn new(pt: &PartitionTable) -> MasterBootRecord {
        MasterBootRecord {
            bootstrap_code: [0; 446],
            partitions: [pt.clone(),
                         PartitionTable::default(),
                         PartitionTable::default(),
                         PartitionTable::default()],
            sig: [0x55, 0xAA]
        }
    }

    /// Create a new disk with a master boot record and a single partition.
    fn new_disk(f: &mut std::fs::File, size_byte: usize) -> io::Result<MasterBootRecord> {
        let pt = PartitionTable::new(size_byte);
        let mbr = MasterBootRecord::new(&pt);

        let bytes: [u8; 512] = unsafe { mem::transmute(mbr) };
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&bytes)?;

        Ok(mbr)
    }
}

/// Size of a DirEntry in bytes.
const DIR_ENTRY_SIZE: usize = 32;

#[repr(C, packed)]
#[derive(Debug,Copy,Clone,PartialEq)]
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
    file_size: u32,            // 28
}

#[derive(Clone, Debug)]
struct HybridEntry {
    e: DirEntry,
    long_name: String
}

// %%%%%%% Toying around with what a data structure for the FAT could
// look like. Keeping the entire FAT in memory is only sensible if it
// is small. With potentially 2^28 entries it can grow quite large in
// the general case.

struct Fat {
    entries: Vec<FatEntry>,
}

impl Fat {
    // fn from_bytes(&mut self, &[u8]) {

    // }
    // fn to_bytes(&mut self) -> &[u8] {
    // }
}

use std::ops::Index;

impl Index<usize> for Fat {
    type Output = FatEntry;
    fn index<'a>(&'a self, i: usize) -> &'a FatEntry {
        &self.entries[i]
    }
}

// %%%%%%%%% End of playground

struct Fat32Media {
    f: std::fs::File,
    bpb: BIOSParameterBlock,
    fat32: Fat32,
    fsinfo: FsInfo
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

const FREE_ENTRY_MARKER: u8 = 0xE5;

const FAT_CLUSTER_FREE: u32 = 0x0;
const FAT_END_OF_CHAIN: u32 = 0x0FFFFFF8;

// A long entry can store 26 bytes of a file name. Since each
// character is encoded in 2 bytes (UTF16), this makes 13 characters
// per long entry.

//#[repr(C, packed)]
#[derive(Debug,Copy,Clone)]
struct LongEntry { // offset (byte)
  ord:u8,          // 0
  name1:[u16;5],   // 1
  attr:u8,         // 11
  dir_type:u8,     // 12
  checksum:u8,     // 13
  name2:[u16;6],   // 14
  unused:[u8;2],   // 26
  name3:[u16;2]    // 28
}

impl LongEntry {

    fn new() -> LongEntry {
        LongEntry {
            ord: 0,
            name1: [0,0,0,0,0],
            attr: ATTR_LONG_NAME,
            dir_type: 0,
            checksum: 0,
            name2: [0,0,0,0,0,0],
            unused: [0,0],
            name3: [0,0],
        }
    }

    fn set_char(&mut self, idx: usize, b: u16) {
        assert!(idx < self.name1.len() + self.name2.len() + self.name3.len());

        if idx < self.name1.len() {
            self.name1[idx] = b;
        } else if idx >= self.name1.len() && idx < self.name1.len() + self.name2.len() {
            self.name2[idx-self.name1.len()] = b;
        } else {
            self.name3[idx-self.name1.len()-self.name2.len()] = b;
        }
    }

    fn terminate_and_pad(&mut self) {
        let mut pad = false;
        for b in self.name1.iter_mut().chain(self.name2.iter_mut()).chain(self.name3.iter_mut()) {
            if pad {
                *b = 0xFFFF;
            }
            if *b == 0 {
                pad = true;
            }
        }
    }

    fn to_bytes(&self) -> [u8; 32] {
        let mut x: [u8; DIR_ENTRY_SIZE] = [0u8; DIR_ENTRY_SIZE];
        let off: usize = 0;
        x[0] = self.ord;
        for i in 0..5 {
            let y = self.name1[i].to_le_bytes();
            x[(1+i*2)..1+(i+1)*2].copy_from_slice(&y);
        }
        x[11] = self.attr;
        x[12] = self.dir_type;
        x[13] = self.checksum;
        for i in 0..6 {
            let y = self.name2[i].to_le_bytes();
            x[(14+i*2)..14+(i+1)*2].copy_from_slice(&y);
        }
        x[26] = self.unused[0];
        x[27] = self.unused[1];
        x[28..30].copy_from_slice(&self.name3[0].to_le_bytes());
        x[30..32].copy_from_slice(&self.name3[1].to_le_bytes());
        return x;
    }

    fn name(&self) -> [u16;13] {
        let mut n: [u16;13] = [0;13];
        n[0] = self.name1[0];
        n[1] = self.name1[1];
        n[2] = self.name1[2];
        n[3] = self.name1[3];
        n[4] = self.name1[4];

        n[5]  = self.name2[0];
        n[6]  = self.name2[1];
        n[7]  = self.name2[2];
        n[8]  = self.name2[3];
        n[9]  = self.name2[4];
        n[10] = self.name2[5];

        n[11] = self.name3[0];
        n[12] = self.name3[1];

        return n;
    }

    /// Populate long entry from raw bytes.
    fn from_bytes(raw: &[u8]) -> Option<LongEntry> {
        let mut e = LongEntry::new();

        let mut r = raw.split_at(1);
        e.ord = u8::from_le_bytes(r.0.try_into().unwrap());
        for i in 0..5 {
            r = r.1.split_at(2);
            e.name1[i] = u16::from_le_bytes(r.0.try_into().unwrap());
        }
        r = r.1.split_at(1);
        e.attr = u8::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(1);
        e.dir_type = u8::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(1);
        e.checksum = u8::from_le_bytes(r.0.try_into().unwrap());
        for i in 0..6 {
            r = r.1.split_at(2);
            e.name2[i] = u16::from_le_bytes(r.0.try_into().unwrap());
        }
        for i in 0..2 {
            r = r.1.split_at(1);
            e.unused[i] = u8::from_le_bytes(r.0.try_into().unwrap());
        }
        for i in 0..2 {
            r = r.1.split_at(2);
            e.name3[i] = u16::from_le_bytes(r.0.try_into().unwrap());
        }
        return Some(e);
    }

    fn to_string(&self) -> String {
        let n = self.name();
        let mut name_len = n.len();
        for (idx, chr) in n.iter().enumerate() {
            if *chr == 0x0 {
                name_len = idx;
                break;
            }
        }
        return String::from_utf16(&n[0..name_len]).unwrap();
    }

    fn is_last_long_entry(&self) -> bool {
        (self.ord & LAST_LONG_ENTRY) != 0
    }
}

impl DirEntry {

    fn default() -> DirEntry {
        // Beware, the date/time format does not record time zone
        // information! Also, if the system outputs a time outside the
        // FAT range (1980 - 2100), the system likely uses a different
        // epoch start to fill the missing date in.
        let default_date = 0x21; // Jan 1st, 1980
        DirEntry {name: [FREE_ENTRY_MARKER; 11],
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
                  file_size: 0 }
    }

    fn dot_entry() -> DirEntry {
        let mut e = DirEntry::default();
        e.name = [b' '; 11];
        e.name[0] = b'.';
        return e;
    }

    fn dotdot_entry() -> DirEntry {
        let mut e = DirEntry::dot_entry();
        e.name[1] = b'.';
        return e;
    }

    // @param name File name in human readable format, e.g., "LETTER01.DOC".
    fn new(name: String) -> DirEntry {
        assert!(is_valid_short_name(&name));

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

        x.name.copy_from_slice(&short_name_to_bytes(&name));
        return x;
    }

    fn print(&self) -> String {
        let mut s = String::new();

        if (self.attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME {
            s.push_str("ATTR_LONG_NAME\n");
        }
        if (self.attr & ATTR_LONG_NAME_MASK) != ATTR_LONG_NAME && self.name[0] != FREE_ENTRY_MARKER {
            if (self.attr & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) == 0x00 {
                // Create a local copy to prevent "warning: borrow of
                // packed field is unsafe and requires unsafe function or
                // block (error E0133)"
                let file_size = self.file_size;
                let attr = self.attr;
                s.push_str(&format!("{} [size {} byte(s), attr {}, 1st cluster #: {}]\n",
                               self.short_name_as_str(), file_size, attr, self.cluster_number()));
            } else if (self.attr & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) == ATTR_DIRECTORY {
                s.push_str(&format!("{} {:X?} (dir), cluster #: {}\n",
                               self.short_name_as_str(), self.name, self.cluster_number()));
            } else if (self.attr & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) == ATTR_VOLUME_ID {
                s.push_str(&format!("Volume name is {}\n", self.short_name_as_str()));
            } else {
                s.push_str(&format!("Invalid entry\n"));
            }
        }

        return s;
    }

    fn is_volume_label(&self) -> bool {
        (self.attr & ATTR_VOLUME_ID) != 0
    }

    fn is_file(&self) -> bool {
        assert!(!self.is_free());

        (self.attr & ATTR_DIRECTORY) == 0 && (self.attr & ATTR_VOLUME_ID) == 0
    }

    fn is_directory(&self) -> bool {
        assert!(!self.is_free());

        !self.is_long_name() && (self.attr & ATTR_DIRECTORY) != 0
    }

    fn is_long_name(&self) -> bool {
        assert!(!self.is_free());

        (self.attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME
    }

    fn is_dot_entry(&self) -> bool {
        assert!(!self.is_free());
        // 46 is '.' (dot); 32 is ' ' (space)
        let dot_name : [u8; 11] = [46, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32];
        return self.name == dot_name;
    }

    fn is_dot_dot_entry(&self) -> bool {
        assert!(!self.is_free());
        // 46 is '.' (dot); 32 is ' ' (space)
        let dot_dot_name : [u8; 11] = [46, 46, 32, 32, 32, 32, 32, 32, 32, 32, 32];
        return self.name == dot_dot_name;
    }

    fn cluster_number(&self) -> u32 {
        return self.first_cluster_low as u32 + ((self.first_cluster_high as u32) << 16);
    }

    fn set_cluster_number(&mut self, cluster: u32) {
        self.first_cluster_low  = (cluster & 0x0000FFFF).try_into().unwrap();
        self.first_cluster_high = (cluster >> 16).try_into().unwrap();
    }

    fn short_name_as_str(&self) -> String {
        let mut main_part_len: usize = 8;

        // println!("{:?}", self);

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

        // println!("fn short_name_as_str(), {}, main_part_len= {}, extension_part_len= {}",
        //          line!(), main_part_len, extension_part_len);
        let main_part = str::from_utf8(&self.name[0..main_part_len]).unwrap().to_string();
        let ext_part = str::from_utf8(&self.name[8..8+extension_part_len]).unwrap().to_string();
        if ext_part.len() > 0 {
            return main_part + "." + &ext_part;
        } else {
            return main_part;
        }
    }

    fn is_free(&self) -> bool {
        self.name[0] == FREE_ENTRY_MARKER || self.name[0] == 0x0
    }

    fn mark_free(&mut self) {
        self.name[0] = FREE_ENTRY_MARKER;
    }

    fn is_free_and_following(&self) -> bool {
        let magic_free_entry_byte: u8 = 0x0;
        self.name[0] == magic_free_entry_byte
    }

    fn checksum(&self) -> u8 {
        let mut sum = 0u8;
        for c in &self.name {
            sum = sum.rotate_right(1).wrapping_add(*c);
        }
        sum
    }

    /// Serialize into a short entry.
    fn to_bytes(&self) -> [u8; 32] {
        let x: [u8; 32] = unsafe { mem::transmute(*self) };
        assert_eq!(core::mem::size_of::<Self>(), x.len());
        return x;
    }

    /// Populate short entry from raw bytes.
    fn from_bytes_short(raw: &[u8]) -> Option<DirEntry> {
        let mut e = DirEntry::default();

        let mut r = raw.split_at(11);
        e.name.copy_from_slice(r.0);
        r = r.1.split_at(1);
        e.attr = u8::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(1);
        e.nt_reserved = u8::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(1);
        e.create_time_tenth = u8::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(2);
        e.create_time = u16::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(2);
        e.create_date = u16::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(2);
        e.last_access_date = u16::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(2);
        e.first_cluster_high = u16::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(2);
        e.write_time = u16::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(2);
        e.write_date = u16::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(2);
        e.first_cluster_low = u16::from_le_bytes(r.0.try_into().unwrap());
        r = r.1.split_at(4);
        e.file_size = u32::from_le_bytes(r.0.try_into().unwrap());

        return Some(e);
    }
}

impl HybridEntry {

    fn from_name(name: &str) -> Option<HybridEntry> {
        if is_valid_short_name(name) {
            return Some(HybridEntry::from_short(&DirEntry::new(name.to_string())));
        } else if is_valid_long_name(name) {
            return Some(HybridEntry {
                e: DirEntry::default(),
                long_name: name.to_string()
            });
        }
        return None;
    }

    // Serialize the entry. Produces zero or more `LongEntry`s and the
    // corresponding `DirEntry`. Since the output size is unknown,
    // return a vector of `u8`s.
    fn to_bytes(&self) -> Vec<u8> {
        let mut long_entries: Vec<LongEntry> = vec![];

        if self.long_name.len() == 0 {
            return self.e.to_bytes().to_vec();
        }

        for (i, b) in self.long_name.encode_utf16().enumerate() {
            if (i % 13) == 0 {
                long_entries.insert(0, LongEntry::new());
                long_entries.get_mut(0).unwrap().checksum = self.e.checksum();
                long_entries.get_mut(0).unwrap().ord = ((i / 13) + 1).try_into().unwrap();
            }
            long_entries.get_mut(0).unwrap().set_char(i%13, b);
        }

        long_entries.get_mut(0).unwrap().terminate_and_pad();
        long_entries.get_mut(0).unwrap().ord |= LAST_LONG_ENTRY;

        let mut bytes: Vec<u8> = vec![];
        for long_entry in &long_entries {
            bytes.extend(long_entry.to_bytes().iter());
        }
        bytes.extend(self.e.to_bytes().iter());
        return bytes;
    }

    fn new(name: &str) -> HybridEntry {

        let mut e = HybridEntry {
            e: DirEntry::default(),
            long_name: String::new()
        };

        if is_valid_short_name(name) {
            e.e.name.copy_from_slice(&short_name_to_bytes(name));
        } else {
            assert!(is_valid_long_name(name));
            // e.e.name.copy_from_slice(&gen_short_name(name, &vec![]).unwrap());
            e.long_name = name.to_string();
        }
        return e;
    }

    fn from_short(e: &DirEntry) -> HybridEntry {
        HybridEntry { e: *e, long_name: String::new() }
    }

    fn cmp(&self, s: &str) -> bool {
        return self.e.short_name_as_str() == s || self.long_name == s;
    }

    fn print(&self) -> String {
        let mut s = String::new();
        // s.push_str(&self.e.print());
        if self.long_name.len() > 0 {
            s.push_str(&format!("{} [{}]", self.long_name, self.e.short_name_as_str()));
        } else {
            s.push_str(&self.e.short_name_as_str());
        }
        if self.e.is_directory() {
            s.push_str("/");
        }
        if self.e.is_file() {
            s.push_str(&format!(" size {} byte(s)", self.e.file_size));
        }
        s.push_str("\n");
        return s;
    }
}

fn is_valid_long_name(name: &str) -> bool {

    let special_short_chars = "$%'-_@~`!(){}^#& ";
    let special_long_chars  = "+,;=[].";

    if !name.chars().all(|b| b.is_alphanumeric() || special_short_chars.contains(b) ||
                         special_long_chars.contains(b)) {
        return false;
    }

    return true;
}

fn short_name_to_bytes(name: &str) -> [u8; 11] {
    assert!(is_valid_short_name(name));
    let tokens = name.split(".").collect::<Vec<&str>>();
    let mut r = [b' '; 11];
    for (idx, byte) in tokens[0].as_bytes().iter().enumerate() {
        r[idx] = *byte;
    }

    if tokens.len() == 1 {
        return r;
    }

    for (idx, byte) in tokens[1].as_bytes().iter().enumerate() {
        r[idx+8] = *byte;
    }

    return r;
}

fn short_name_as_str(bytes: &[u8; 11]) -> String {

    let mut s = String::from_utf8(bytes[0..8].to_vec()).unwrap().trim_end_matches(' ').to_string();
    let suffix = String::from_utf8(bytes[8..11].to_vec()).unwrap().trim_end_matches(' ').to_string();
    if suffix.len() > 0 {
        s.push('.');
        s.push_str(&suffix);
    }
    return s;
}

fn gen_short_name(long_name: &str, existing: &Vec<String>) -> Option<[u8;11]> {

    if !is_valid_long_name(long_name) {
        return None;
    }

    let upper_cased_name = long_name.to_uppercase();

    // TODO replace illegal glyphs with _ (underscore).

    let spaces_removed = upper_cased_name.replace(" ", "");
    let no_leading_periods = spaces_removed.trim_start_matches(".");

    let mut basis = [b' '; 11];
    let mut copied = 0;
    let mut truncated = false;
    let last_dot_idx = match no_leading_periods.rfind('.') {
        Some(x) => x,
        None => no_leading_periods.len()
    };

    for c in no_leading_periods[0..last_dot_idx].as_bytes().iter() {

        if copied == 8 {
            truncated = true;
            break;
        }

        if *c == b'.' {
            continue;
        }

        basis[copied] = *c;
        copied += 1;
    }

    match no_leading_periods.rfind(".") {
        Some(idx) => for i in 1..4 {
            if no_leading_periods.len() > idx+i {
                basis[8+i-1] = no_leading_periods.as_bytes()[idx+i];
            }
        },
        None => (),
    };

    if truncated {
        basis[6] = b'~';
        basis[7] = b'1';
    }

    // TODO Take existing names into account to avoid clashing short
    // names.
    if !existing.is_empty() {
        unimplemented!();
    }

    return Some(basis);
}

use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{self, Write};
use std::mem;
use std::str;

extern crate clap;
use clap::Parser;
extern crate sha2;
use sha2::{Sha256, Digest};
extern crate log;
use log::{trace};

extern crate libc;

extern crate rand;
use rand::Rng;
use rand::distributions::Alphanumeric;

#[derive(Parser)]
#[clap(version = "0.1", author = "Thomas K.")]
struct Opts {
    #[clap(short,long, default_value = "/Volumes/RAMDisk/test.img")]
    diskimage: String,
    #[clap(subcommand)]
    subcmd: SubCommand
}

#[derive(Parser)]
enum SubCommand {
    #[clap(version = "0.1")]
    Cat(Cat),
    Info(Info),
    Ls(Ls),
    ListFsCommand(ListFsCommand),
    Interactive(InteractiveCommand),
    Selftest(Selftest)
}

#[derive(Parser)]
struct Cat {
    #[clap(short)]
    path: String
}

#[derive(Parser)]
struct Info {
}

#[derive(Parser)]
struct Ls {
    #[clap(short, default_value = "/")]
    path: String
}

#[derive(Parser)]
struct ListFsCommand {
}

#[derive(Parser)]
struct Selftest {
}

#[derive(Parser)]
struct InteractiveCommand {
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

    fn handle_file(&mut self, e: &HybridEntry) -> FatEntryState;
    fn handle_dir(&mut self, e: &HybridEntry) -> FatEntryState;

    // Called when descending down a directory.
    fn enter(&mut self, e: &HybridEntry);
    // Called when ascending from a directory.
    fn exit(&mut self);
}

fn ls(fs: &mut Fat32Media, path: &str) -> Result<Vec<HybridEntry>, Errno> {
    let e = match fs.get_entry(path) {
        None => return Err(Errno::ENOENT),
        Some(x) => x
    };

    if e.e.is_file() {
        return Ok(vec![e]);
    }

    let mut v = Vec::new();
    for (range, entry) in fs.dir_entry_iter(e.e.cluster_number()) {
        if entry.e.is_free() {
            continue;
        }
        if entry.e.is_volume_label() {
            continue;
        }
        v.push(entry);
    }

    return Ok(v);
}

// List the entire file system.
struct ListFs {
    prefix: Vec<String>,
}

impl FileAction for ListFs {
    fn consume(&mut self, _data: &[u8; 512], _size: usize) {
        panic!("");
    }

    fn handle_file(&mut self, e: &HybridEntry) -> FatEntryState {
        for x in &self.prefix {
            print!("{}/", x);
        }
        print!("{}", e.print());
        return FatEntryState::NEXT;
    }
    fn handle_dir(&mut self, e: &HybridEntry) -> FatEntryState {
        for x in &self.prefix {
            print!("{}/", x);
        }
        print!("{}", e.print());
        return FatEntryState::VISIT;
    }
    fn enter(&mut self, dir: &HybridEntry) {
        self.prefix.push(dir.e.short_name_as_str());
    }
    fn exit(&mut self) {
        self.prefix.pop();
    }
}

struct SelftestCommand {
    prefix: Vec<HybridEntry>,
    hasher: Sha256
}

impl FileAction for SelftestCommand {

    fn consume(&mut self, data: &[u8; 512], size: usize) {
        self.hasher.input(data[..size].as_ref());
    }

    fn handle_file(&mut self, entry: &HybridEntry) -> FatEntryState {
        println!("{} SelftestCommand::handle_file()", line!());

        // On OSX, some services create files on the volume in the
        // background, e.g., the file system indexer. Ignore
        // files, that do not consist of 8 hexadecimal characters.
        for c in entry.e.short_name_as_str().chars() {
            if !c.is_digit(16) {
                return FatEntryState::NEXT;
            }
        }
        return FatEntryState::VISIT;
    }

    fn handle_dir(&mut self, _e: &HybridEntry) -> FatEntryState {
        return FatEntryState::VISIT;
    }

    fn enter(&mut self, name: &HybridEntry) {
        trace!("enter: {}", name.e.short_name_as_str());
        self.prefix.push(name.clone());
    }

    fn exit(&mut self) {
        let entry = self.prefix.pop().unwrap().e;
        trace!("exit: {}", entry.short_name_as_str());
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
    entry: Option<HybridEntry>
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

    fn handle_file(&mut self, e: &HybridEntry) -> FatEntryState {
        if self.path == concat(&self.prefix, &e.e.short_name_as_str()) ||
            self.path == concat(&self.prefix, &e.long_name) {
            assert!(self.entry.is_none());
            self.entry = Some(e.clone());
        }
        return FatEntryState::NEXT;
    }

    fn handle_dir(&mut self, e: &HybridEntry) -> FatEntryState {
        // trace!("fn handle_dir(), line= {}, self.path = {}, self.prefix= {}",
        //         line!(), self.path, self.prefix);

        if self.path == concat(&self.prefix, &e.e.short_name_as_str()) ||
            self.path == concat(&self.prefix, &e.long_name) {
            assert!(self.entry.is_none());
            self.entry = Some(e.clone());
            return FatEntryState::NEXT;
        } else {
            // let path: Vec<&str> = self.path.split('/').collect();
            //if path[1] == e.short_name_as_str() {
            //    self.path = path[1..].join("/");
                if self.path.starts_with(&(concat(&self.prefix, &e.e.short_name_as_str()) + "/")) ||
                    self.path.starts_with(&(concat(&self.prefix, &e.long_name) + "/")) {
                return FatEntryState::VISIT;
            } else {
                return FatEntryState::NEXT;
            }
        }
    }

    fn enter(&mut self, dir: &HybridEntry) {
        self.prefix += &(dir.e.short_name_as_str() + &"/".to_owned());
        //trace!("enter self.prefix= {}", self.prefix);
    }

    fn exit(&mut self) {
        let mut p: Vec<&str> = self.prefix.split('/').collect();
        p.pop();
        self.prefix = p.join("/");
        //trace!("exit self.prefix= {}", self.prefix);
    }
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

struct DirEntryItr<'a> {
    cluster_itr: ClusterItr<'a>,
    data: [u8; 512],
    // Counts directory entries for the directory (across sector and
    // cluster boundaries).
    idx: usize,
}

/// Iterator over directory entries. Combines long entries and short
/// entry into one `HybridEntry`. Other entries, e.g., free and volume
/// name, are returned as is.
impl Iterator for DirEntryItr<'_> {
    type Item = (std::ops::Range<usize>, HybridEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let mut long_name = String::new();
        let mut prev_ord  = 0u8;
        let mut checksum  = 0u8;

        loop {
            let entries_per_sector = self.data.len() / DIR_ENTRY_SIZE;
            if self.idx % entries_per_sector == 0 {
                match self.cluster_itr.next() {
                    Some(x) => self.data = x,
                    None => return None
                }
                trace!("{}, DirEntryItr::next(), next cluster", line!());
                // self.idx = 0;
            }

            let idx = self.idx;

            let sector_idx_low  = (idx % entries_per_sector) * DIR_ENTRY_SIZE;
            let sector_idx_high = sector_idx_low + DIR_ENTRY_SIZE;
            let slice = &self.data[sector_idx_low..sector_idx_high];
            self.idx += 1;

            let short = DirEntry::from_bytes_short(slice).unwrap();
            trace!("{}, DirEntryItr::next(), short={:X?}", line!(), short);
            if short.is_free() {
                assert!(long_name.len() == 0);
                return Some((idx..idx+1,
                             HybridEntry::from_short(&short)));
            }

            if !short.is_long_name() {
                if long_name.len() == 0 {
                    return Some((idx..idx+1,
                                 HybridEntry::from_short(&short)));
                }
                assert!(short.checksum() == checksum);
                let idx_low = idx - round_up_div(long_name.len() as u64, 13) as usize;
                let idx_high = idx + 1;
                return Some((idx_low..idx_high, HybridEntry {e: short, long_name: long_name}));
            }

            let long = LongEntry::from_bytes(slice).unwrap();
            // On first long entry, `long_name` must be empty.
            trace!("{}, DirEntryItr::next(), long={:X?}", line!(), long);

            if long.is_last_long_entry() {
                assert!(long_name.len() == 0);
                assert!(checksum == 0);
                assert!(prev_ord == 0);
                checksum = long.checksum;
            } else {
                // On all but the first long entry in a chain,
                // `long_name` must be non-empty.
                assert!(long_name.len() != 0);
                // On all but the first long entry in a chain,
                // `long.ord` must be one less than previous long
                // entry's ord.
                assert!(long.ord == prev_ord - 1);
            }

            long_name.insert_str(0, &long.to_string());

            assert!(long.checksum == checksum);

            prev_ord = long.ord & LONG_ENTRY_ORD_MASK;
        }
    }
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
        self.read() >= FAT_END_OF_CHAIN
    }
}

impl PartialEq for FatEntry {
    fn eq(&self, other: &Self) -> bool {
        return self.read() == other.read();
    }
}

#[derive(Debug, PartialEq)]
enum Errno {
    SUCCESS, ENOENT, EEXIST, ENOSPC, ENOSYS, EINVAL
}

/// If `dividend` is not an exact multiple of `divisor`, always round
/// up to nearest integer. For example, 6 / 3 = 2 and 5 / 2 = 3.
// fn round_up_div<T: std::ops::Add<Output = T> + std::ops::Sub<Output = T>>(dividend: T, divisor: T) -> T {
fn round_up_div(dividend: u64, divisor: u64) -> u64 {
    (dividend + divisor - 1) / divisor
}

fn is_valid_short_name(name: &str) -> bool {
    let tokens = name.split(".").collect::<Vec<&str>>();

    if tokens.len() > 2 {
        return false;
    }

    if tokens[0].len() > 8 {
        return false;
    }

    if tokens[0].len() == 0 {
        return false;
    }

    if tokens.len() == 2 {
        if tokens[1].len() > 3 {
            return false;
        }
    }

    let special_short_chars = "$%'-_@~`!(){}^#& ";
    if !name.chars().all(|c| (c.is_ascii_alphabetic() && c.is_ascii_uppercase()) ||
                         c.is_ascii_digit() || special_short_chars.contains(c)) {
        return false;
    }

    return true;
}

impl Fat32Media {

    fn first_sector_of_cluster(&self, n: u32) -> u32 {
        return ((n - 2) * self.bpb.sectors_per_cluster as u32) + first_data_sector(self);
    }

    /// @return In addition to the DirEntry created, also returns the
    /// index within the directory at which the entry was written. The
    /// index can be used with Fat32Media::write_dir_entry() to update
    /// the entry later (cf. Fat32Media::cp()).
    fn touch(&mut self, path: &str) -> Result<HybridEntry, Errno> {
        assert!(!path.ends_with("/"));

        // get parent
        let parent = std::path::Path::new(&path).parent().unwrap();
        let file_name = std::path::Path::new(&path).file_name().unwrap().to_str().unwrap().to_string();

        let e = self.get_entry(&parent.to_str().unwrap().to_string());
        let cluster = match e {
            None => return Err(Errno::ENOENT),
            Some(x) => x.e.cluster_number()
        };

        let new_entry = match HybridEntry::from_name(&file_name) {
            Some(e) => e,
            None => return Err(Errno::EINVAL),
        };

        match self.add_dir_entry(cluster, &new_entry) {
            Errno::SUCCESS => return Ok(new_entry),
            e => return Err(e),
        };
    }

    /// Writes all-zeroes to a cluster.
    fn clear_cluster(&mut self, cluster: u32) {
        trace!("fn clear_cluster() {} cluster= {}", line!(), cluster);

        let zeroes = [0u8; 512];
        for i in 0..self.bpb.sectors_per_cluster {
            self.write_sector_of_cluster(i, cluster, &zeroes);
        }
    }

    /// @param cluster: any cluster in a chain
    /// @param free_fat_entries: clusters to append to the chain
    fn append_to_chain(&mut self, cluster: u32, free_fat_entries: &Vec<u32>) {
        assert!(free_fat_entries.len() > 0);

        trace!("{} cluster= {}, free_fat_entries= {:?}", line!(), cluster, free_fat_entries);

        let mut prev = cluster;
        let mut fat_entry = self.cluster_number_to_fat32_entry(prev);
        while !fat_entry.is_end_of_chain() {
            trace!("{} FAT[{}] = {}", line!(), prev, fat_entry.read());
            prev = fat_entry.read();
            fat_entry = self.cluster_number_to_fat32_entry(fat_entry.read());
        }

        assert!(fat_entry.is_end_of_chain());

        for x in free_fat_entries {
            self.write_fat_entry(prev, *x);
            prev = *x;
        }

        self.write_fat_entry(prev, FAT_END_OF_CHAIN);
    }

    // Only delete empty files for now. Cannot unlink/free FAT entries/clusters yet.
    fn rm(&mut self, path: String) -> Errno {
        if path.ends_with("/") {
            return Errno::ENOSYS;
        }

        // get parent
        let parent = std::path::Path::new(&path).parent().unwrap();
        let file_name = std::path::Path::new(&path).file_name().unwrap().to_str().unwrap().to_string();

        let cluster = match self.get_entry(&parent.to_str().unwrap().to_string()) {
            None => return Errno::ENOENT,
            Some(x) => x.e.cluster_number()
        };

        let mut idx_entry_pair: Option<(std::ops::Range<usize>, HybridEntry)> = None;

        // TODO Cannot just enumerate() the entries in a directory
        // anymore to find the index within the directory. A long
        // entry may span multiple directory entries (N long entries
        // plus one short entry for N+1 entries in total).
        //
        // How to adapt the interface? Have a lookup operation return the index range as well as the entry, e.g.,
        // (std::ops::Range, HybridEntry)?
        for (r, x) in self.dir_entry_iter(cluster) {

            trace!("{}, rm(), {:?}", line!(), x);

            if x.e.is_free() {
                continue;
            }

            if !(x.e.is_file() || x.e.is_directory()) {
                continue;
            }

            if x.e.short_name_as_str() == file_name || x.long_name == file_name {
                idx_entry_pair = Some((r, x));
                break;
            }
        }

        let (range, e) = match idx_entry_pair {
            None => return Errno::ENOENT,
            Some(x) => (x.0, x.1)
        };

        if e.e.is_directory() {
            return Errno::ENOSYS;
        }

        if e.e.file_size > 0 {
            return Errno::ENOSYS;
        }

        for i in range {
            let empty = DirEntry::default().to_bytes().to_vec();
            self.write_dir_entry(cluster, i, &empty);
        }

        return Errno::SUCCESS;
    }

    /// For now, `src` must refer to a file on the host and `dst` to a
    /// file on the FAT.
    fn cp(&mut self, src: &str, dst: &str) -> Errno {
        if !src.starts_with(&"host://".to_string()) {
            return Errno::EINVAL;
        }

        let dst_path = std::path::Path::new(&dst);
        if !dst_path.has_root() {
            return Errno::EINVAL;
        }
        if dst_path.parent().is_none() {
            return Errno::EINVAL;
        }

        let parent_cluster = match self.get_entry(&dst_path.parent().unwrap().to_str().unwrap().to_string()) {
            Some(e) => e.e.cluster_number(),
            None => return Errno::ENOENT
        };

        let src_path = src.strip_prefix(&"host://".to_string()).unwrap();
        let src_meta = std::fs::metadata(src_path).expect("");
        if !src_meta.is_file() {
            // Only handle files for now.
            return Errno::EINVAL;
        }

        match self.get_entry(dst) {
            None => (),
            Some(_) => return Errno::EEXIST,
        };

        // let touch_result = self.touch(dst);
        // let (mut dst_entry, dst_entry_idx) = match touch_result {
        //     Ok((e, idx)) => (e, idx),
        //     Err(v) => return v,
        // };
        let dst_file_name = std::path::Path::new(dst).file_name().unwrap().to_str().unwrap().to_string();
        if !(is_valid_long_name(&dst_file_name) || is_valid_short_name(&dst_file_name)) {
            return Errno::EINVAL;
        }
        let mut dst_entry = match HybridEntry::from_name(&dst_file_name) {
            None => panic!(),
            Some(x) => x
        };

        // TODO preserve metadata such as creation/access/modification
        // time.

        let len_in_clusters = round_up_div(src_meta.len(),
                                           (self.bpb.bytes_per_sec * self.bpb.sectors_per_cluster as u16).into());

        if len_in_clusters > 0 {
            let clusters =
                match self.find_free_fat32_entries(len_in_clusters.try_into().unwrap()) {
                    Some(v) => v,
                    None => return Errno::ENOSPC,
                };
        // trace!("fn cp(), {}, src size= {}, clusters= {:?}", line!(), src_meta.len(), clusters);

            dst_entry.e.set_cluster_number(clusters[0]);
            dst_entry.e.file_size = src_meta.len().try_into().unwrap();

            // copy content from host to FAT
            let mut left: u64 = src_meta.len();
            let mut src_f = std::fs::File::open(src_path).expect("");
            let mut src_reader = io::BufReader::new(src_f);
            for cluster in &clusters {
                assert!(left > 0);
                for sector in 0..self.bpb.sectors_per_cluster {
                    let mut buf: [u8; 512] = [0u8; 512];

                    // trace!("fn cp(), {}, left= {}", line!(), left);

                    if left >= 512 {
                        src_reader.read_exact(&mut buf).expect("");
                    } else {
                        let mut x = Vec::new();
                        src_reader.read_to_end(&mut x).expect("");
                        assert!(x.len() == left.try_into().unwrap());
                        for (i, b) in x.iter().enumerate() {
                            buf[i] = *b;
                        }
                    }

                    self.write_sector_of_cluster(sector, *cluster, &buf);

                    if left <= 512 {
                        left = 0;
                        break;
                    }
                    left -= 512;
                }
            }

            // Link clusters into a chain.
            let mut prev_cluster = dst_entry.e.cluster_number();
            for cluster in &clusters[1..] {
                self.write_fat_entry(prev_cluster, *cluster);
                prev_cluster = *cluster;
            }
            self.write_fat_entry(prev_cluster, FAT_END_OF_CHAIN);
        }

        match self.add_dir_entry(parent_cluster, &dst_entry) {
            Errno::SUCCESS => return Errno::SUCCESS,
            err => return err
        }
    }

    fn cat(&mut self, path: String) -> Errno {
        let entry: HybridEntry = match self.get_entry(&path) {
            None => return Errno::EINVAL,
            Some(x) => x,
        };
        let mut remaining: u32 = entry.e.file_size;
        for data in self.file_iter(FatEntry::new(entry.e.cluster_number()), remaining) {
            assert!(remaining > 0);

            let size: usize = std::cmp::min(remaining, 512u32).try_into().unwrap();
            io::stdout().write_all(&data[0..size]).expect("");

            if remaining >= 512 {
                remaining -= 512;
            } else {
                remaining = 0;
            }
        }
        return Errno::SUCCESS;
    }

    fn mkdir(&mut self, path: String) -> Result<HybridEntry, Errno> {
        // Idea 1:
        // touch(path) - creates entry in parent(path)
        // alloc cluster
        // clear cluster
        // entry(path).set_cluster(cluster)
        // cluster[0] = entry(path)
        // cluster[1] = entry(parent(path))
        // write cluster

        // Idea 2:
        // Only write new entry into parent's directory as the very last step.
        // data = alloc cluster
        // data[0] = dot entry
        // data[1] = dotdot entry

        let (parent_path, file_name) = {
            let p = std::path::Path::new(&path);
            let parent_path = match p.parent() {
                None => return Err(Errno::EINVAL),
                Some(x) => x.to_str().unwrap().to_string(),
            };
            let file_name = match p.file_name() {
                None => return Err(Errno::EINVAL),
                Some(x) => x.to_str().unwrap().to_string(),
            };
            (parent_path, file_name)
        };

        let dir_cluster = match self.find_free_fat32_entries(1) {
            Some(v) => v[0],
            None => return Err(Errno::ENOSPC),
        };
        self.clear_cluster(dir_cluster);
        self.write_fat_entry(dir_cluster, FAT_END_OF_CHAIN);

        let mut data = [0u8; 512];
        let mut dot_entry = DirEntry::dot_entry();
        dot_entry.set_cluster_number(dir_cluster);
        dot_entry.attr = ATTR_DIRECTORY;

        let parent_entry = match self.get_entry(&parent_path) {
            Some(v) => v,
            None => return Err(Errno::ENOENT),
        };
        trace!("fn mkdir(), line= {}, parent_entry= {:?}", line!(), parent_entry);
        let dotdot_cluster = {
            if parent_path.clone() == "/" {
                0
            } else {
                parent_entry.e.cluster_number()
            }
        };
        let mut dotdot_entry = DirEntry::dotdot_entry();
        // dotdot_entry.name[0] = b'.';
        // dotdot_entry.name[1] = b'.';
        dotdot_entry.set_cluster_number(dotdot_cluster);
        dotdot_entry.attr = ATTR_DIRECTORY;

        data[0..32].copy_from_slice(&dot_entry.to_bytes());
        data[32..64].copy_from_slice(&dotdot_entry.to_bytes());

        self.write_sector_of_cluster(0, dir_cluster, &data);

        let mut entry = HybridEntry::new(&file_name);
        entry.e.set_cluster_number(dir_cluster);
        entry.e.attr = ATTR_DIRECTORY;

        match self.add_dir_entry(parent_entry.e.cluster_number(), &entry) {

            Errno::SUCCESS => return Ok(entry),
            _ => {
                self.write_fat_entry(dir_cluster, FAT_CLUSTER_FREE);
                return Err(Errno::ENOSPC);
            },
        }
    }

    /// Return the FAT32 entry for a given cluster number.
    /// Reads all copies of the FAT and asserts their equality.
    fn cluster_number_to_fat32_entry(&mut self, cluster_nr: u32) -> FatEntry {
        let offset_within_fat: u32 = cluster_nr * FAT32_BYTES_PER_FAT_ENTRY;
        let sector = self.bpb.reserved_sectors as u32 + offset_within_fat / (self.bpb.bytes_per_sec as u32);
        let offset_within_sector = offset_within_fat % self.bpb.bytes_per_sec as u32;
        let mut buf = [0; 4];

        let mut entries: Vec<FatEntry> = vec![];
        for i in 0..self.bpb.fat_copies {
            let offset_within_diskimage =
                512 * (self.bpb.hidden_sectors + i as u32 * self.fat32.secs_per_fat_32 + sector ) +
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

    /// Returns the number of clusters marked "free" in the FAT.
    fn free_clusters(&mut self) -> u32 {
        let mut cnt = 0;
        for i in 0..count_of_clusters(&self.bpb, &self.fat32) {
            let fat_entry = self.cluster_number_to_fat32_entry(i);
            if fat_entry.is_empty() {
                cnt += 1;
            }
        }
        return cnt;
    }

    fn write_fat_entry(&mut self, cluster: u32, fat_entry: u32) -> io::Result<()> {

        // trace!("write_fat_entry {} cluster= {}, fat_entry= {:X}", line!(), cluster, fat_entry);

        let offset_within_fat: u32 = cluster * FAT32_BYTES_PER_FAT_ENTRY;
        let sector = self.bpb.reserved_sectors as u32 + offset_within_fat / (self.bpb.bytes_per_sec as u32);
        let offset_within_sector = offset_within_fat % self.bpb.bytes_per_sec as u32;
        let mut buf = [0; 4];

        for i in 0..self.bpb.fat_copies {
            let offset_within_diskimage =
                512 * (self.bpb.hidden_sectors + i as u32 * self.fat32.secs_per_fat_32 + sector ) +
                offset_within_sector;
            self.f.seek(SeekFrom::Start(offset_within_diskimage.into()))?;
            self.f.read_exact(&mut buf)?;

            let mut existing_entry = FatEntry::new(u32::from_le_bytes(buf));
            existing_entry.update(fat_entry);
            self.f.seek(SeekFrom::Start(offset_within_diskimage.into()))?;
            self.f.write_all(&existing_entry.val.to_le_bytes())?;
        }
        Ok(())
    }

    fn find_free_fat32_entries(&mut self, count: usize) -> Option<Vec<u32>> {
        let fat_entry_size: u32 = 4;
        let sector_size: u32 = 512;
        let max_cluster_id = sector_size * self.fat32.secs_per_fat_32 / fat_entry_size;
        let mut entries: Vec<u32> = vec![];
        for i in self.fsinfo.next_free..max_cluster_id {
            let entry = self.cluster_number_to_fat32_entry(i);
            if entry.is_empty() {
                entries.push(i);
                if entries.len() == count {
                    self.fsinfo.next_free = i;
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

    /// Create an iterator over all DirEntry's in a directory. Use in
    /// combination with std::iter::Iterator::enumerate() to get the
    /// index of the DirEntry. Use index to write a new DirEntry in a
    /// directory with Fat32Media::write_dir_entry(cluster, idx, DirEntry).
    pub fn dir_entry_iter(&mut self, cluster: u32) -> DirEntryItr {
        let mut cluster_itr = self.cluster_iter(FatEntry::new(cluster));
        // let data = cluster_itr.next().unwrap();
        DirEntryItr { cluster_itr: cluster_itr,
                      data: [0u8; 512],
                      idx: 0 }
    }

    /// Creates a new entry in a directory.
    ///
    /// First, find the index within the cluster chain pointed to by
    /// `cluster` at which to write the new entry. If there is
    /// insufficient space, allocate and append a new cluster to this
    /// directory's cluster chain.
    ///
    /// @param cluster Usually the first cluster of a directory.
    ///
    /// Since this function iterates over all directory entries, it is
    /// a good spot to determine a unique short name given a long
    /// name.
    ///
    /// `new_entry` either has new_entry.long_name set or
    /// new_entry.e.name. However, this would require `new_entry` to
    /// be mutable though.
    ///
    /// This function does not check if the long_name is unique
    /// though. This is the caller's responsibility.
    fn add_dir_entry(&mut self, cluster: u32, entry: &HybridEntry) -> Errno {

        // Caller must only provide a short or long name (but not
        // both).
        if entry.long_name.len() > 0 && !entry.e.is_free() {
            return Errno::EINVAL;
        }

        // trace!("{} fn add_dir_entry()", line!());

        let mut new_entry = entry.clone();
        // Instead of faithfully generating a short name based on the
        // long name and the other short names in this directory,
        // generate a random name.
        //
        // This can be done without needing to know all the other
        // existing short names in the directory. It should only be a
        // problem if you want to find a long file on a FAT
        // implementation only supporting short names. If the FAT
        // implementation supports long names, it should always show
        // you the long name anyway (and you do not care what the
        // short name is)..
        if entry.long_name.len() > 0 {
            let mut rng = rand::thread_rng();
            let s: String = rng.sample_iter(&Alphanumeric).take(11).collect::<String>().to_ascii_uppercase();
            new_entry.e.name.copy_from_slice(s.as_bytes());
        }

        let bytes = new_entry.to_bytes();
        assert!(bytes.len() % DIR_ENTRY_SIZE == 0);

        if bytes.len() > 512 {
            // TODO Currently, the implementation only allocates a
            // single new cluster if there is insufficient space. The
            // new cluster offers a minimum of 512 bytes. Be
            // conservative and fail if more space is required.
            return Errno::EINVAL;
        }

        let num_entries = bytes.len() / DIR_ENTRY_SIZE;
        let mut free_idx: Option<usize> = None;
        let mut max_idx: usize = 0;
        let mut consecutive_free_entries = 0usize;
        for (range, e) in self.dir_entry_iter(cluster) {
            if e.e.is_free() {
                consecutive_free_entries += 1;
                if consecutive_free_entries == num_entries && free_idx == None {
                    free_idx = Some(range.start - consecutive_free_entries + 1);
                }
            } else {
                consecutive_free_entries = 0;
                if (e.e.is_file() || e.e.is_directory()) &&
                    e.e.short_name_as_str() == new_entry.e.short_name_as_str() ||
                    (e.long_name.len() > 0 && e.long_name == new_entry.long_name) {
                    return Errno::EEXIST;
                }
            }

            max_idx = range.end;
        }

        // Allocate a new cluster if not enough consecutive free
        // entries were found so far.
        if free_idx == None {
            let free_fat_entries = match self.find_free_fat32_entries(1) {
                None => return Errno::ENOSPC,
                Some(x) => x
            };

            self.append_to_chain(cluster, &free_fat_entries);
            for x in &free_fat_entries {
                self.clear_cluster(*x);
            }

            // max_idx references the first entry in the newly
            // allocated cluster. Use any remaining free entries in
            // the already existing cluster By subtracting
            // `consecutive_free_entries` from `max_idx`. As a result,
            // the new entry will span a cluster boundary.
            free_idx = Some(max_idx - consecutive_free_entries);
        }

        self.write_dir_entry(cluster, free_idx.unwrap(), &new_entry.to_bytes());
        return Errno::SUCCESS;
    }

    /// @param cluster First(!) cluster of a directory.
    pub fn write_dir_entry(&mut self, cluster: u32, idx: usize, bytes: &Vec<u8>) {
        trace!("fn write_dir_entry() {} cluster= {}, idx= {}",
                 line!(), cluster, idx);

        let mut data = [0u8; 512];
        let entries_per_sector = data.len() / core::mem::size_of::<DirEntry>();
        let idx_within_sector: usize = idx % entries_per_sector;
        let mut sector: u8 = (idx / entries_per_sector).try_into().unwrap();
        let entries_to_write = bytes.len() / DIR_ENTRY_SIZE;

        // If the entry spans a sector/cluster boundary, two sectors
        // must be updated.
        let entries_first_sector = std::cmp::min(entries_to_write, entries_per_sector - idx_within_sector);
        let entries_second_sector = entries_to_write - entries_first_sector;

        self.read_sector_of_chain(sector, cluster, &mut data);
        // let num_entries = bytes.len() / DIR_ENTRY_SIZE;
        // trace!("{} num_entries= {}", line!(), num_entries);
        // trace!("{} bytes= {:#04X?}", line!(), bytes);
        data[idx_within_sector * DIR_ENTRY_SIZE..(idx_within_sector + entries_first_sector) * DIR_ENTRY_SIZE].copy_from_slice(
            &bytes[0..entries_first_sector*DIR_ENTRY_SIZE]);

        self.write_sector_of_chain(sector, cluster, &data);

        if entries_second_sector == 0 {
            return;
        }

        self.read_sector_of_chain(sector+1, cluster, &mut data);
        data[0..entries_second_sector * DIR_ENTRY_SIZE].copy_from_slice(
            &bytes[entries_first_sector * DIR_ENTRY_SIZE..]);
        self.write_sector_of_chain(sector+1, cluster, &mut data);
    }
}

// Iterate over all sectors of a cluster chain. Used, for example, for
// directories.
impl Iterator for ClusterItr<'_> {
    type Item = [u8; 512];
    fn next(&mut self) -> Option<Self::Item> {
        // trace!("fn ClusterItr::next(), {}, self.sector= {}, self.entry= {}",
        //          line!(), self.sector, self.entry.read());

        if self.entry.is_end_of_chain() {
            return None
        }
        let mut data = [0; 512];
        let sector = self.fat.first_sector_of_cluster(self.entry.read()) + self.sector as u32;
        let file_offset = 512 * self.fat.bpb.hidden_sectors as u64 + sector as u64 * 512;
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

        let fsinfo: FsInfo = {
            let mut bytes = [0; 512];
            f.seek(SeekFrom::Start(((512 * (mbr.partitions[0].offset_lba + (fat32.fs_info as u32)))) as u64)).is_ok();
            f.read_exact(&mut bytes).unwrap();
            unsafe { mem::transmute(bytes) }
        };

        assert!(bpb.bytes_per_sec == 512);

        Fat32Media { f: f, bpb: bpb, fat32: fat32, fsinfo: fsinfo }
    }

    fn parse_directory(&'a mut self, cluster_id: u32, handler: &mut dyn FileAction) {

        let mut long_name_buf: [u16;LONG_NAME_MAX_CHARS] = [0;LONG_NAME_MAX_CHARS];
        let mut long_name = "".to_string();
        let mut checksum = 0u8;
        let mut visit_dir: Vec<HybridEntry> = vec![];
        let mut visit_files: Vec<HybridEntry> = vec![];

        // TODO Use DirEntryItr to loop over directory entries.
        let itr = self.cluster_iter(FatEntry::new(cluster_id));
        'outer: for sector_data in itr {
            let entries_per_sector = sector_data.len() / core::mem::size_of::<DirEntry>();
            for i in 0..entries_per_sector {
                let mut dir_entry = HybridEntry::from_short(&DirEntry::from_bytes_short(&sector_data[DIR_ENTRY_SIZE*i..DIR_ENTRY_SIZE*(i+1)]).unwrap());
                let long_entry = LongEntry::from_bytes(&sector_data[DIR_ENTRY_SIZE*i..DIR_ENTRY_SIZE*(i+1)]).unwrap();

                // trace!("{} {:?}", line!(), dir_entry);

                // Special case where all subsequent entries are free and need
                // not be examined.
                if dir_entry.e.is_free_and_following() {
                    // If long_name is set, this entry was preceeded
                    // by one or more long entries. Long entries mut
                    // be followed by a matching short entry, but we
                    // found an empty entry. Something is up.
                    assert!(long_name.is_empty());
                    trace!("{} dir_entry.name[0] == 0x00", line!());
                    break 'outer;
                }

                if !dir_entry.e.is_free() {
                    // dir_entry.print();

                    if dir_entry.e.is_long_name() {
                        // Long entry must be followed by short
                        // entry. This is another long entry.
                        assert!(long_name.is_empty());

                        // assemble long name
                        if (long_entry.ord & LAST_LONG_ENTRY) != 0 {
                            long_name_buf = [0; LONG_NAME_MAX_CHARS];
                            checksum = long_entry.checksum;
                        }

                        assert_eq!(long_entry.checksum, checksum);

                        let ord = long_entry.ord & LONG_ENTRY_ORD_MASK;
                        let start: usize = (CHARS_PER_LONG_ENTRY*(ord-1) as u32).try_into().unwrap();
                        let end  : usize = (CHARS_PER_LONG_ENTRY*(ord) as u32).try_into().unwrap();
                        // print!("start={} end={} ", start, end);
                        let slc = &mut long_name_buf[start..end];
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
                            for (i, elem) in long_name_buf.iter().enumerate() {
                                if *elem == 0x0 {
                                    long_name_len = i;
                                    break;
                                }
                            }
                            long_name = String::from_utf16(&long_name_buf[0..long_name_len]).unwrap();
                            // trace!("{} {}", line!(), long_name);
                        }
                    }

                    if dir_entry.e.is_file() {
                        if !long_name.is_empty() {
                            trace!("{} long_name={}, dir_entry.name={} {:X?}, gen_short_name={:X?}",
                                     line!(), long_name, String::from_utf8(dir_entry.e.name.to_vec()).unwrap(),
                                     dir_entry.e.name, gen_short_name(&long_name, &vec![]));
                            assert_eq!(dir_entry.e.checksum(), checksum);
                            // assert_eq!(gen_short_name(&long_name, &vec![]).unwrap(),
                            //            dir_entry.name);
                        }
                        dir_entry.long_name = long_name.clone();

                        // trace!("short entry checksum {}", dir_entry.checksum());
                        match handler.handle_file(&dir_entry) {
                            FatEntryState::NEXT => (),
                            FatEntryState::VISIT => visit_files.push(dir_entry)
                        }

                        // Clear long name after handling
                        // corresponding short entry.
                        long_name.clear();

                    } else if dir_entry.e.is_directory() {
                        // Skip . and ..

                        if dir_entry.e.is_dot_entry() || dir_entry.e.is_dot_dot_entry() {
                            continue;
                        }

                        if !long_name.is_empty() {
                            assert_eq!(dir_entry.e.checksum(), checksum);
                            trace!("{} long_name={}, dir_entry.name={} {:X?}, gen_short_name={:X?}",
                                     line!(), long_name, String::from_utf8(dir_entry.e.name.to_vec()).unwrap(),
                                     dir_entry.e.name, gen_short_name(&long_name, &vec![]));

                        }

                        dir_entry.long_name = long_name.clone();
                        match handler.handle_dir(&dir_entry) {
                            FatEntryState::VISIT => visit_dir.push(dir_entry),
                            FatEntryState::NEXT => (),
                        }

                        // Clear long name after handling
                        // corresponding short entry.
                        long_name.clear();
                    }
                }
            }
            // println!("");
        }

        for dir in visit_dir {
            handler.enter(&dir);
            self.parse_directory(dir.e.cluster_number(), handler);
            handler.exit();
        }

        for f in visit_files {
            handler.enter(&f);
            // trace!("visit_file {:?}", f);
            let mut remaining: usize = f.e.file_size.try_into().unwrap();
            for sector_data in self.file_iter(FatEntry::new(f.e.cluster_number()), f.e.file_size) {
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
    fn root(&self) -> HybridEntry {
        let mut e = DirEntry::default();
        let special_short_chars = "$%'-_@~`!(){}^#& ";
        e.name.copy_from_slice(&special_short_chars.as_bytes()[0..11]);
        e.attr = ATTR_DIRECTORY;
        e.first_cluster_low = self.fat32.root_cluster.try_into().unwrap();
        HybridEntry { e: e, long_name: String::new() }
    }

    /// Returns DirEntry for a given file or directory or None if no
    /// such entry exists.
    fn get_entry(&'a mut self, path: &str) -> Option<HybridEntry> {
        let p = std::path::Path::new(path);
        let mut entry: Option<HybridEntry> = Some(self.root());

        for component in p.components() {
            if component == std::path::Component::RootDir {
                continue;
            }

            // trace!("fn get_entry(), line= {}, {} {:?}",
            //          line!(), entry.unwrap().cluster_number(), component.as_os_str().to_str());
            entry = self.get_entry_in_dir(entry.unwrap().e.cluster_number(),
                                          component.as_os_str().to_str().unwrap().to_string());
            // trace!("fn get_entry(), line= {}, {:?}", line!(), entry);

            if !entry.is_some() {
                return None
            }
        }
        return entry;
    }

    /// Returns DirEntry for a file or directory within a specific directory (cluster_id).
    fn get_entry_in_dir(&'a mut self, cluster_id: u32, name: String) -> Option<HybridEntry> {
        assert!(name.contains("/") == false);

        let mut action = FindCommand {
            path: name, prefix: "".to_string(), entry: None
        };
        self.parse_directory(cluster_id, &mut action);
        return action.entry;
    }

    /// Updates a specific sector of a cluster.
    fn write_sector_of_cluster(&mut self, sector: u8, cluster: u32, data: &[u8; 512]) {
        assert!(sector < self.bpb.sectors_per_cluster);
        assert!(cluster < count_of_clusters(&self.bpb, &self.fat32));

        // trace!("fn write_sector_of_cluster() {} sector= {}, cluster= {}",
        //         line!(), sector, cluster);

        let file_offset = (self.first_sector_of_cluster(cluster) +
                           sector as u32 + self.bpb.hidden_sectors) * 512;
        assert!(self.f.seek(SeekFrom::Start(file_offset.into())).is_ok());

        let r = self.f.write_all(data);
        assert!(r.is_ok());
        // r = self.f.sync_all();
        // assert!(r.is_ok());
    }

    /// @param sector Sector number within the chain pointed to by `cluster`.
    /// @param cluster First cluster of a directory.
    fn write_sector_of_chain(&mut self, mut sector: u8, cluster: u32, data: &[u8; 512]) {
        let mut fat_entry = FatEntry::new(cluster);
        while sector >= self.bpb.sectors_per_cluster {
            fat_entry = self.cluster_number_to_fat32_entry(fat_entry.read());
            sector -= self.bpb.sectors_per_cluster;
        }

        self.write_sector_of_cluster(sector, fat_entry.read(), data);

    }

    fn read_sector_of_cluster(&mut self, sector: u8, cluster: u32, data: &mut [u8; 512]) {
        assert!(sector < self.bpb.sectors_per_cluster);

        let file_offset = (self.first_sector_of_cluster(cluster) +
                           sector as u32 + self.bpb.hidden_sectors) * 512;
        assert!(self.f.seek(SeekFrom::Start(file_offset.into())).is_ok());

        let r = self.f.read_exact(data);
        assert!(r.is_ok());
    }

    /// If `sector` is larger than the number of sectors in a single
    /// cluster, use the FAT to move along the chain until reaching
    /// the target cluster.
    fn read_sector_of_chain(&mut self, mut sector: u8, mut cluster: u32, data: &mut [u8; 512]) {
        while sector >= self.bpb.sectors_per_cluster {
            let fat_entry = self.cluster_number_to_fat32_entry(cluster);
            assert!(!fat_entry.is_end_of_chain());
            cluster = fat_entry.read();
            sector -= self.bpb.sectors_per_cluster;
        }
        self.read_sector_of_cluster(sector, cluster, data);
    }
}

type ICommand = fn(tokens: Vec<&str>, fat: &mut Fat32Media);

fn ls_command(tokens: Vec<&str>, fat: &mut Fat32Media) {

    if tokens.len() != 2 {
        println!("Usage: ls path");
        return;
    }

    let entries = match ls(fat, &tokens[1].to_string()) {
        Err(x) => { println!("{:?}", x); return },
        Ok(x) => x
    };

    println!(".");

    for e in entries {
        print!("{}", e.print());
    }
}

fn touch_command(tokens: Vec<&str>, fat: &mut Fat32Media) {

    if tokens.len() != 2 {
        println!("Usage: touch path1 path2");
        return;
    }

    match fat.touch(&tokens[1].to_string()) {
        Ok(_) => (),
        Err(e) => println!("error {:?}", e),
    };
}

fn rm_command(tokens: Vec<&str>, fat: &mut Fat32Media) {

    if tokens.len() != 2 {
        println!("Usage: rm path1");
        return;
    }

    match fat.rm(tokens[1].to_string()) {
        Errno::SUCCESS => (),
        e => println!("error {:?}", e),
    };
}

fn cp_command(tokens: Vec<&str>, fat: &mut Fat32Media) {

    if tokens.len() != 3 {
        println!("Usage: cp source-path destination-path");
        return;
    }

    match fat.cp(&tokens[1].to_string(), &tokens[2].to_string()) {
        Errno::SUCCESS => (),
        e => println!("error {:?}", e),
    }
}

fn mkdir_command(tokens: Vec<&str>, fat: &mut Fat32Media) {

    if tokens.len() != 2 {
        println!("Usage: mkdir path");
        return;
    }

    match fat.mkdir(tokens[1].to_string()) {
        Err(e) => println!("error {:?}", e),
        _ => ()
    }
}

fn repl(fat: &mut Fat32Media) {

    use std::collections::HashMap;
    let mut cmds: HashMap<String, ICommand> = HashMap::new();
    cmds.insert("ls".to_string(), ls_command);
    cmds.insert("touch".to_string(), touch_command);
    cmds.insert("rm".to_string(), rm_command);
    cmds.insert("cp".to_string(), cp_command);
    cmds.insert("mkdir".to_string(), mkdir_command);

    loop {
        print!("> ");
        std::io::stdout().flush().expect("");
        let mut buf = String::new();
        match std::io::stdin().read_line(&mut buf) {
            Ok(x) => if x == 0 {
                return;
            },
            Err(x) => panic!(x),
        }

        let tokens: Vec<&str> = buf.split_ascii_whitespace().collect();

        if tokens.len() == 0 {
            continue;
        }

        if tokens[0] == "exit" {
            return;
        }

        match cmds.get(tokens[0]) {
            Some(f) => f(tokens, fat),
            None => {
                let s = cmds.keys().map(|x| x).collect::<Vec<&String>>();
                println!("Unknown command. Try one of: {:?}", s);
            }
        }
    }
}

extern crate env_logger;
use env_logger::*;

// http://stackoverflow.com/questions/31192956/whats-the-de-facto-way-of-reading-and-writing-files-in-rust-1-x
fn main() {
    let opts: Opts = Opts::parse();
    let mut fat = Fat32Media::new(opts.diskimage);

    env_logger::init();


    // FAT12/16 size. Must be zero for FAT32.
    assert!(fat.bpb.total_secs_16 == 0);
    assert!(fat.bpb.secs_per_fat_16 == 0);
    assert!(fat.bpb.total_secs_32 != 0);

    // debug!("{:?}", fat.fat32);
    // Can only handle FAT32 major:minor equal to 0:0.
    assert!(fat.fat32.fs_ver == 0);
    // debug!("struct MasterBootRecord has {:?} bytes", core::mem::size_of::< MasterBootRecord >());
    // debug!("struct BIOSParameterBlock has {:?} bytes", core::mem::size_of::< BIOSParameterBlock >());

    assert!(core::mem::size_of::<DirEntry>() == 32);

    // debug!("Cluster count is {:?}", count_of_clusters(&fat.bpb, &fat.fat32));
    // debug!("First data sector is {:?}", first_data_sector(&fat));
    // debug!("First sector of root directory cluster {:?}",
    //         first_sector_of_cluster(fat.fat32.root_cluster, &fat));

    let root_cluster = fat.fat32.root_cluster;
    match opts.subcmd {
        SubCommand::Cat(t) => {
            match fat.cat(t.path) {
                Errno::SUCCESS => (),
                x => println!("Failed with {:?}", x),
            }
        },
        SubCommand::Info(_t) => {
            println!("{:?}", fat.bpb);
            println!("{:?}", fat.fat32);
            println!("Volume label: {}", str::from_utf8(&fat.fat32.vol_label).unwrap());
            let free_space_in_bytes: u64 = fat.free_clusters() as u64 *
                fat.bpb.sectors_per_cluster as u64 * fat.bpb.bytes_per_sec as u64;
            println!("Free space: {} bytes", free_space_in_bytes);
        },
        SubCommand::Interactive(_t) => {
            repl(&mut fat);
        }
        SubCommand::Ls(t) => {
            match ls(&mut fat, &t.path) {
                Err(x) => println!("{:?}", x),
                Ok(x) => {
                    println!(".");
                    for e in x {
                        print!("{}", e.print());
                    }
                }
            };
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
    use super::*;
    use super::Fat32Media;
    use Errno;
    use ls;
    use Errno::ENOENT;

    // Call this at beginning of each test to capture log output
    // during the test. By default no log output is captured during
    // tests.
    fn capture_logging_for_tests() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_ls_01() {
        let mut fat = Fat32Media::new("/Volumes/RAMDisk/testcase_01.img".to_string());
        let entries = ls(&mut fat, &"/".to_string()).unwrap();
        let mut x = entries.iter().map(|x| x.e.short_name_as_str()).collect::<Vec<String>>();

        assert_eq!(x, (0..10).map(|x| x.to_string()).collect::<Vec<String>>());
        for e in entries {
            assert!(e.e.is_directory());
        }

        let entries = ls(&mut fat, &"/1/".to_string()).unwrap();
        let x = entries.iter().map(|x| x.e.short_name_as_str()).collect::<Vec<String>>();
        let expected_entries = [".", "..", "66EC94BA", "83186062", "590D2E74", "EE45872D", "897965E7", "E4CB5817"].iter().map(|x| x.to_string()).collect::<Vec<String>>();
        for expected in &expected_entries {
            assert!(x.contains(expected));
        }

        assert_eq!(ls(&mut fat, &"/nonexist/".to_string()).unwrap_err(), Errno::ENOENT);

        let entries = ls(&mut fat, &"/4/E9068190".to_string()).unwrap();
        let x = entries.iter().map(|x| x.e.short_name_as_str()).collect::<Vec<String>>();
        assert!(x.contains(&"E9068190".to_string()));
        assert!(entries[0].e.is_file());
    }

    #[test]
    fn test_find_free_fat32_entry() {
        let mut fat = Fat32Media::new("/Volumes/RAMDisk/testcase_01.img".to_string());
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
        let mut fat = Fat32Media::new("/Volumes/RAMDisk/testcase_02.img".to_string());
        assert_eq!(fat.touch(&"/0/1".to_string()).unwrap_err(), Errno::ENOENT);
        // On OSX, the newly formatted volume can hold 13 additional
        // entries in its root directory before we need to allocate a
        // new cluster. Each 512 byte sector can hold 16 `DirEntry`
        // entries. One entry is occopied by the VOLUME_ID. Two more
        // entries (one long!) are occupied by the FSEVEN~1 directory
        // which gets automatically created by OSX. Hence, we can
        // create 13 more entries, we need to allocate a new cluster
        // to hold additional entries.
        for i in 0..13 {
            assert!(fat.touch(&("/".to_string()+&i.to_string())).is_ok());
        }
    }

    #[test]
    /// Test writing files into FAT by copying files from the host to the image.
    fn test_cp() {
        // TODO Create new empty image before each run (instead of relying on existing files).
        let mut fat = Fat32Media::new("/Volumes/RAMDisk/testcase_03.img".to_string());
        for i in 0..16 {
            fat.cp("host:///Users/thomas/rust/fat32/src/main.rs", &format!("/{}", i));
        }
    }

    use HybridEntry;

    #[test]
    fn test_long_entry() {
        let mut e = match HybridEntry::from_name("The quick brown.fox") {
            None => panic!(),
            Some(x) => x,
        };

        e.e.name.copy_from_slice(&"THEQUI~1FOX".to_string().as_bytes()[..]);
        // println!("{:#04X?}", e.to_bytes());
        // This byte array encodes two long entries and the corresponding short entry.
        let bytes = [
            0x42, 0x77, 0x00, 0x6E, 0x00, 0x2E, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x0F, 0x00, 0x07, 0x78, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0x01, 0x54, 0x00, 0x68, 0x00, 0x65, 0x00, 0x20, 0x00, 0x71, 0x00, 0x0F, 0x00, 0x07, 0x75, 0x00,
            0x69, 0x00, 0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x62, 0x00, 0x00, 0x00, 0x72, 0x00, 0x6F, 0x00,
            0x54, 0x48, 0x45, 0x51, 0x55, 0x49, 0x7E, 0x31, 0x46, 0x4F, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x21, 0x00, 0x21, 0x00, 0x00, 0x00, 0x01, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        assert_eq!(e.to_bytes(), bytes.to_vec());
  }

    use gen_short_name;
    #[test]
    fn test_gen_short_name() {
        assert_eq!("MUSTCAP    ".to_string().as_bytes(), gen_short_name("MustCap", &vec![]).unwrap());
        assert_eq!(gen_short_name("extChaR=", &vec![]).unwrap(),
                   "EXTCHAR=   ".to_string().as_bytes());
        assert_eq!("LEGAL31    ".to_string().as_bytes(), gen_short_name("Legal31", &vec![]).unwrap());
        assert_eq!("THEQUI~1FOX".to_string().as_bytes(),
                   gen_short_name("The quick brown.fox", &vec![]).unwrap());
        assert_eq!("LETTER01DOC".to_string().as_bytes(),
                   gen_short_name("Letter01.doc", &vec![]).unwrap());
    }

    #[test]
    fn test_from_to_bytes() {
        let mut fat = Fat32Media::new("/Volumes/RAMDisk/testcase_01.img".to_string());
        let entry = fat.get_entry("/1/66EC94BA").unwrap();
        let bytes = entry.e.to_bytes();
        assert_eq!(DirEntry::from_bytes_short(&bytes).unwrap(), entry.e);
    }

    #[test]
    fn test_mkdir() {
        let mut fat = Fat32Media::new("/Volumes/RAMDisk/testcase_01.img".to_string());
    }

    use is_valid_short_name;
    use is_valid_long_name;
    #[test]
    fn test_name() {
        assert!(is_valid_short_name("1"));
        assert!(is_valid_long_name("[BOOT]"));
        assert!(is_valid_long_name("x86_64-efi"));
    }

    use std::process::Command;
    #[test]
    /// Test initialization of a new disk. Write the master boot
    /// record containing a single partition covering all the
    /// available disk space.
    fn test_format_disk() -> std::io::Result<()> {
        const FN: &str = "/Volumes/RAMDisk/d";
        let size_byte: usize = 128 * 1024 * 1024;
        let mut f = OpenOptions::new().write(true).create(true).open(FN)?;
        let mbr = MasterBootRecord::new_disk(&mut f, size_byte);
        f.sync_all()?;

        let args = ["attach", "-imagekey", "diskimage-class=CRawDiskImage", "-nomount", FN];
        let out = Command::new("hdiutil").args(args).output().unwrap();

        let s = std::str::from_utf8(&out.stdout).unwrap();
        let words: Vec<&str> = s.split(char::is_whitespace).collect();
        // First word of `hdiutil` output should be path of the newly
        // created device.
        let device = words[0];

        let status = Command::new("hdiutil").args(["eject", device]).status().unwrap();
        assert!(status.success());
        std::fs::remove_file(FN)?;
        Ok(())
    }
}
