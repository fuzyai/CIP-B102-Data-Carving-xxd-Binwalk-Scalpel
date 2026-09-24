# CIP-B102 Lab 6 – Data Carving & File System Forensics

**Course:** CIP-B102
**Name:** Fuseini Imoru Kantuogaa
**Lab:** Lab 6 – Data Carving
**Environment:** Kali Linux

## Overview

This lab covers manual and automated **file carving** and **file system
forensics** techniques on both a single file (JPEG) and full disk/USB
images. It demonstrates identifying file signatures, extracting embedded
metadata, analyzing FAT file systems with The Sleuth Kit, recovering
deleted files, and carving unknown data with `binwalk` and `scalpel`.

## Environment Setup

Working directory and evidence files were downloaded with `wget`:

```bash
mkdir -p ~/CIP-B102_Lab6_Data_Carving
cd ~/CIP-B102_Lab6_Data_Carving
wget -q <Ch01InChap01.dd>      # FAT12 disk image
wget -q <J_ub_law.jpg>         # JPEG evidence file
wget -q <120M.7z>               # 7-Zip archive (unknown structure)
```

| File | Type | Size |
|---|---|---|
| `Ch01InChap01.dd` | DOS/MBR FAT12 disk image | 1.5 MB |
| `J_ub_law.jpg` | JPEG (Nikon D4, EXIF data) | 1.7 MB |
| `120M.7z` | 7-Zip archive | 36 MB |
| `usb_fat_carving.001` | FAT16 USB image (extracted from `120M.7z`) | 119 MB |

## 1. File Identification & Hashing

- Identified file types with `file` (magic-byte detection) on all three
  evidence files
- Generated **MD5** and **SHA-256** hashes of each file for integrity
  verification (baseline before any manipulation)

```bash
file Ch01InChap01.dd J_ub_law.jpg 120M.7z
md5sum Ch01InChap01.dd J_ub_law.jpg 120M.7z
sha256sum Ch01InChap01.dd J_ub_law.jpg 120M.7z
```

## 2. Manual Hex Analysis (JPEG structure)

- Viewed the JPEG's header and footer bytes with `xxd ... | head` / `tail`
  to confirm the standard JPEG signatures: `FFD8` (Start of Image) and
  `FFD9` (End of Image)
- Dumped a plain hex representation with `xxd -p` and searched for every
  occurrence of `ffd8`/`ffd9` using `grep`, first on a multi-line dump and
  then on a single-line version (`tr -d "\n"`) to correctly match hex
  markers that could span dump lines
- **Reversed the process**: rebuilt a JPEG from the plain hex dump using
  `xxd -r -p`, then verified the reconstructed file was byte-identical to
  the original via `file`, `md5sum`, and `sha256sum` — confirming a
  lossless round-trip

```bash
xxd J_ub_law.jpg | head
xxd J_ub_law.jpg | tail
xxd -p J_ub_law.jpg > J_ub_law_hexdump.txt
grep -o "ffd8" J_ub_law_hexdump.txt
xxd -p J_ub_law.jpg | tr -d "\n" > J_ub_law_hexdump_singleline.txt
xxd -r -p J_ub_law_hexdump.txt J_ub_law_reverse_dump.jpg
```

## 3. Embedded Metadata Extraction

- Inspected a specific byte offset (`xxd -s 0x100 -l 0x9f`) to view the
  Adobe Photoshop metadata block embedded in the file
- Extracted printable strings with `strings`, then filtered for
  forensically relevant metadata (camera make/model, editing software,
  dates, author, copyright) using `grep -Ei`
- Findings recovered from EXIF/XMP metadata:
  - Camera: **Nikon D4**, lens 17.0–35.0mm f/2.8
  - Edited in **Adobe Photoshop 21.1 (Macintosh)**
  - Author: **Howard Korn**
  - Timestamps: 2013-10-08 and 2020-08-20
  - Copyright: "Copyright 1999 Adobe Systems Incorporated"

```bash
xxd -s 0x100 -l 0x9f J_ub_law.jpg
strings J_ub_law.jpg | head -50
strings J_ub_law.jpg | grep -Ei "nikon|photoshop|adobe|date|copyright|author|name"
```

## 4. File System Analysis (The Sleuth Kit)

Analyzed the FAT12 disk image `Ch01InChap01.dd`:

| Command | Purpose |
|---|---|
| `img_stat` | Confirmed image type (raw), size, and sector size |
| `mmls` | Checked for a partition table (none — image is a raw volume) |
| `fsstat` | Retrieved FAT12 file system layout: boot sector, FAT tables, root directory, cluster area/size, FAT chain contents |
| `fls` | Listed all files/directories, including deleted (`*`) entries and system metadata (`$MBR`, `$FAT1`, `$FAT2`, `$OrphanFiles`) |
| `fls -d` | Listed **deleted files only** |
| `icat <inode>` | Recovered file content by inode number and exported it |
| `istat <inode>` | Displayed inode metadata: allocation status, size, MAC timestamps, and the exact sectors occupied |

### Files recovered from the image

| Inode | Recovered Name | Status | Notes |
|---|---|---|---|
| 8 | `Billing_Letter.doc` | Deleted | MS Word doc, author Amelia Phillips |
| 11 | `confirmation.txt` | Deleted | FTP credentials for "laura.roper" |
| 12 | (unnamed) | — | Recovered as `recovered_from_inode.bin` |
| 15 | `letter1.txt` | Deleted | Business letter re: "18th of August" |
| 17 | `Regrets.doc` | Deleted | — |

```bash
img_stat Ch01InChap01.dd
mmls Ch01InChap01.dd
fsstat Ch01InChap01.dd | head -40
fls Ch01InChap01.dd
fls -d Ch01InChap01.dd
icat Ch01InChap01.dd 11 > confirmation.txt
istat Ch01InChap01.dd 8
```

## 5. Signature-Based Carving with `binwalk`

- Ran `binwalk` against the JPEG to confirm embedded structures (EXIF/TIFF
  offset, embedded copyright string) matched what `strings` had found
- Ran `binwalk` against `120M.7z` and discovered it actually contains a
  **7-Zip archive with an embedded PowerPoint file** (`ppt/fonts/...`,
  `ppt/media/image14.png`) plus additional embedded structures
- Extracted the archive with `binwalk -e` and, since the JAR-based
  extractor was unavailable, used **7-Zip directly** (`7z l`, `7z e`) to
  list and extract contents, revealing the true payload:
  `usb_fat_carving.001` (119 MB) — a second, larger disk image

```bash
binwalk J_ub_law.jpg
binwalk 120M.7z
binwalk -e 120M.7z
7z l 120M.7z
7z e 120M.7z
```

## 6. Second Image Analysis — `usb_fat_carving.001`

Repeated the file system workflow on the newly extracted 119 MB image:

- `img_stat` confirmed a raw image, 512-byte sectors
- `mmls` showed a **DOS partition table** with a FAT16 partition starting
  at sector 128
- `fls -o 128` (offset to the partition start) listed the full file
  listing — dozens of files: images (`.bmp`, `.gif`, `.png`, `.tiff`),
  documents (`.doc`, `.pdf`, `.pptx`, `.rtf`), code (`.java`), audio
  (`.wav`), an Outlook PST file, a zip archive, and a file with a
  non-ASCII (Chinese) filename
- `fls -o 128 -d` isolated deleted entries only

```bash
IMAGE="usb_fat_carving.001"
img_stat "$IMAGE"
mmls "$IMAGE"
fls -o 128 "$IMAGE"
fls -o 128 -d "$IMAGE"
```

## 7. Automated Carving with `scalpel`

- Backed up the default config (`/etc/scalpel/scalpel.conf`) before editing
- Enabled the `jpg` file-type signatures in the config (commented out by
  default)
- Ran `scalpel` against `usb_fat_carving.001` to carve JPEGs directly from
  raw disk sectors, independent of file system metadata — recovered
  **17 files**
- Reviewed the audit trail (`audit.txt`) showing each carved file's start
  offset and length
- Verified carved files with `find ... -exec file {}` (confirmed valid
  JPEG/EXIF structures) and generated MD5 hashes of every carved file for
  the evidence log

```bash
sudo cp /etc/scalpel/scalpel.conf /etc/scalpel/scalpel.conf.bak
sudo nano /etc/scalpel/scalpel.conf   # enabled jpg signatures
scalpel "$IMAGE" -o output_lab6_scalpel
find output_lab6_scalpel -type f -exec file {} \;
find output_lab6_scalpel -type f -exec md5sum {} \; > carved_files_md5.txt
```

## Key Tools Used

| Tool | Purpose |
|---|---|
| `xxd` | Hex dump / reverse hex-to-binary |
| `file` | Magic-byte file type identification |
| `strings` | Extract printable text/metadata from binary files |
| `md5sum` / `sha256sum` | Hash-based integrity verification |
| `img_stat`, `mmls`, `fsstat` (Sleuth Kit) | Disk image & file system metadata |
| `fls`, `icat`, `istat` (Sleuth Kit) | File listing, content recovery, inode inspection |
| `binwalk` | Signature-based embedded file/structure detection |
| `7z` | Archive listing/extraction |
| `scalpel` | Signature-based automated file carving |

## Forensic Notes

- Original evidence files were hashed **before** any analysis or
  manipulation to preserve chain of custody.
- The JPEG reconstruction test (hex dump → rebuild → hash match) validates
  that hex-level carving does not corrupt file content.
- `binwalk` revealed that a file's stated extension/type is not always its
  true structure (`120M.7z` contained an unexpected embedded disk image).
- `scalpel`'s carved output was independently verified against the deleted
  file signatures found via file-system-aware tools (`fls`/`icat`),
  demonstrating two complementary recovery approaches: metadata-based vs.
  signature-based carving.
