/** @file
  Publish the payload volume handed over by the bootloader as a read-only
  block device.  Two transports are supported:

    - the FDT /chosen linux,initrd-start/end range (bootloader handoff)
    - a UNIXNUPK container found anywhere in RAM (vendor_boot / boot ramdisk)

  A UNIXNUPK container is a 24-byte header followed by an LZMA-alone stream:

      "UNIXNUPK" | u32 uncompressed | u32 compressed | u32 crc32 | u32 rsvd

  LZMA decompression is provided by MdeModulePkg/LzmaCustomDecompressLib,
  which the platform DSC links into this module as a NULL library.

  SPDX-License-Identifier: BSD-2-Clause
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>

//
// LzmaCustomDecompressLib exports these two symbols but has no public header
// in this EDK2 tree; declare them locally.  Both return RETURN_STATUS.
//
RETURN_STATUS
EFIAPI
LzmaUefiDecompressGetInfo (
  IN  CONST VOID  *Source,
  IN  UINT32      SourceSize,
  OUT UINT32      *DestinationSize,
  OUT UINT32      *ScratchSize
  );

RETURN_STATUS
EFIAPI
LzmaUefiDecompress (
  IN CONST VOID  *Source,
  IN UINTN       SourceSize,
  IN OUT VOID    *Destination,
  IN OUT VOID    *Scratch
  );

// Mu-Silicium SEC stores the incoming x0 value in this HOB as a UINT64.
STATIC CONST EFI_GUID mEntryArgHobGuid = {
  0xDAEE82E6, 0x8090, 0x4E72, { 0xBF, 0xB9, 0x78, 0xC1, 0x3C, 0xD4, 0xE3, 0x59 }
};

// Volume label of the payload FAT image (`[payload] volume` in board.toml).
STATIC CONST CHAR8  mPayloadLabel[] = { 'S', 'H', 'E', 'N', 'G', 'E', 'S', 'P' };

// "UNIXNUPK" as a little-endian UINT64.
#define UNIXNUPK_MAGIC  0x4B50554E58494E55ULL

#pragma pack(1)
typedef struct {
  CHAR8     Magic[8];
  UINT32    UncompressedSize;
  UINT32    CompressedSize;
  UINT32    Crc32;
  UINT32    Reserved;
} UNIXNUPK_HEADER;
#pragma pack()

STATIC
UINT64
ReadCells (
  IN CONST VOID  *Data,
  IN UINT32      Cells
  )
{
  if (Cells == 2) {
    return Fdt64ToCpu (ReadUnaligned64 (Data));
  }

  return Fdt32ToCpu (ReadUnaligned32 (Data));
}

#define RAM_BLOCK_SIZE  512

#pragma pack(1)
typedef struct {
  VENDOR_DEVICE_PATH          Vendor;
  EFI_DEVICE_PATH_PROTOCOL    End;
} RAM_BLOCK_DEVICE_PATH;
#pragma pack()

STATIC RAM_BLOCK_DEVICE_PATH  mDevicePath = {
  {
    { HARDWARE_DEVICE_PATH, HW_VENDOR_DP, { (UINT8)sizeof (VENDOR_DEVICE_PATH), (UINT8)(sizeof (VENDOR_DEVICE_PATH) >> 8) } },
    { 0xA9C6827C, 0x1BD8, 0x410C, { 0x88, 0x5A, 0xC4, 0x65, 0x00, 0xF7, 0xD8, 0x36 } }
  },
  { END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 } }
};

STATIC UINT8                    *mRamBase;
STATIC EFI_BLOCK_IO_MEDIA       mMedia;

STATIC
EFI_STATUS
EFIAPI
RamBlockReset (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN BOOLEAN                ExtendedVerification
  )
{
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockRead (
  IN  EFI_BLOCK_IO_PROTOCOL  *This,
  IN  UINT32                 MediaId,
  IN  EFI_LBA                Lba,
  IN  UINTN                  BufferSize,
  OUT VOID                   *Buffer
  )
{
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (MediaId != mMedia.MediaId) {
    return EFI_MEDIA_CHANGED;
  }

  if ((BufferSize % RAM_BLOCK_SIZE) != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }

  if ((Lba > mMedia.LastBlock) || ((BufferSize / RAM_BLOCK_SIZE) > (mMedia.LastBlock + 1 - Lba))) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Buffer, mRamBase + Lba * RAM_BLOCK_SIZE, BufferSize);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockWrite (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  IN VOID                   *Buffer
  )
{
  return EFI_WRITE_PROTECTED;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockFlush (
  IN EFI_BLOCK_IO_PROTOCOL  *This
  )
{
  return EFI_SUCCESS;
}

STATIC EFI_BLOCK_IO_PROTOCOL  mBlockIo = {
  EFI_BLOCK_IO_PROTOCOL_REVISION,
  &mMedia,
  RamBlockReset,
  RamBlockRead,
  RamBlockWrite,
  RamBlockFlush
};

STATIC
BOOLEAN
PublishRange (
  IN UINT64  Start,
  IN UINT64  End
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;

  mRamBase                = (UINT8 *)(UINTN)Start;
  mMedia.MediaId          = 1;
  mMedia.RemovableMedia   = FALSE;
  mMedia.MediaPresent     = TRUE;
  mMedia.LogicalPartition = FALSE;
  mMedia.ReadOnly         = TRUE;
  mMedia.WriteCaching     = FALSE;
  mMedia.BlockSize        = RAM_BLOCK_SIZE;
  mMedia.IoAlign          = 1;
  mMedia.LastBlock        = (End - Start) / RAM_BLOCK_SIZE - 1;

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiDevicePathProtocolGuid,
                  &mDevicePath,
                  &gEfiBlockIoProtocolGuid,
                  &mBlockIo,
                  NULL
                  );
  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: block device 0x%lx size 0x%lx %r\n", Start, End - Start, Status));
  return !EFI_ERROR (Status);
}

//
// Decompress a UNIXNUPK container and publish the result as the payload FAT.
//
STATIC
BOOLEAN
PublishPack (
  IN CONST UINT8  *Base,
  IN UINT64        Available
  )
{
  CONST UNIXNUPK_HEADER  *Header;
  RETURN_STATUS          Status;
  UINT32                 DestinationSize;
  UINT32                 ScratchSize;
  EFI_PHYSICAL_ADDRESS   Destination;
  VOID                   *Scratch;
  UINTN                  Pages;
  UINTN                  PaddedSize;

  if (Available < sizeof (UNIXNUPK_HEADER)) {
    return FALSE;
  }

  Header = (CONST UNIXNUPK_HEADER *)(UINTN)Base;
  if (ReadUnaligned64 ((CONST UINT64 *)(UINTN)Header->Magic) != UNIXNUPK_MAGIC) {
    return FALSE;
  }

  if ((Header->CompressedSize < 13) || (Header->CompressedSize > 0x20000000) ||
      (Header->UncompressedSize == 0) || (Header->UncompressedSize > 0x40000000))
  {
    return FALSE;
  }

  if ((UINT64)sizeof (UNIXNUPK_HEADER) + Header->CompressedSize > Available) {
    return FALSE;
  }

  DestinationSize = 0;
  ScratchSize     = 0;
  Status = LzmaUefiDecompressGetInfo (
             (CONST VOID *)(Base + sizeof (UNIXNUPK_HEADER)),
             Header->CompressedSize,
             &DestinationSize,
             &ScratchSize
             );
  if (EFI_ERROR (Status) || (DestinationSize == 0) || (DestinationSize > 0x40000000)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: pack info failed %r\n", Status));
    return FALSE;
  }

  PaddedSize = ALIGN_VALUE ((UINTN)DestinationSize, RAM_BLOCK_SIZE);
  Pages      = EFI_SIZE_TO_PAGES (PaddedSize);
  Destination = 0;
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData, Pages, &Destination);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no memory for 0x%x bytes: %r\n", PaddedSize, Status));
    return FALSE;
  }

  Scratch = NULL;
  if (ScratchSize != 0) {
    Status = gBS->AllocatePool (EfiBootServicesData, ScratchSize, &Scratch);
    if (EFI_ERROR (Status)) {
      gBS->FreePages (Destination, Pages);
      return FALSE;
    }
  }

  Status = LzmaUefiDecompress (
             (CONST VOID *)(Base + sizeof (UNIXNUPK_HEADER)),
             Header->CompressedSize,
             (VOID *)(UINTN)Destination,
             Scratch
             );
  if (Scratch != NULL) {
    gBS->FreePool (Scratch);
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: lzma failed %r\n", Status));
    gBS->FreePages (Destination, Pages);
    return FALSE;
  }

  if (!PublishRange ((UINT64)Destination, (UINT64)Destination + PaddedSize)) {
    gBS->FreePages (Destination, Pages);
    return FALSE;
  }

  return TRUE;
}

STATIC
BOOLEAN
LooksLikePayload (
  IN CONST UINT8  *Boot
  );

STATIC
BOOLEAN
PublishInitrd (
  IN CONST VOID  *Fdt
  )
{
  INT32       Chosen;
  CONST VOID  *StartProp;
  CONST VOID  *EndProp;
  INT32       StartLength;
  INT32       EndLength;
  UINT64      Start;
  UINT64      End;

  Chosen = FdtPathOffset (Fdt, "/chosen");
  if (Chosen < 0) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no /chosen\n"));
    return FALSE;
  }

  StartProp = FdtGetProp (Fdt, Chosen, "linux,initrd-start", &StartLength);
  EndProp   = FdtGetProp (Fdt, Chosen, "linux,initrd-end", &EndLength);
  if ((StartProp == NULL) || (EndProp == NULL) ||
      ((StartLength != 4) && (StartLength != 8)) || ((EndLength != 4) && (EndLength != 8)))
  {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no initrd in /chosen\n"));
    return FALSE;
  }

  Start = ReadCells (StartProp, StartLength / 4);
  End   = ReadCells (EndProp, EndLength / 4);
  if (End <= Start) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: empty initrd 0x%lx-0x%lx\n", Start, End));
    return FALSE;
  }

  if (PublishPack ((CONST UINT8 *)(UINTN)Start, End - Start)) {
    return TRUE;
  }

  if (!LooksLikePayload ((CONST UINT8 *)(UINTN)Start)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd 0x%lx-0x%lx is neither pack nor FAT\n", Start, End));
    return FALSE;
  }

  if (((End - Start) % RAM_BLOCK_SIZE) != 0) {
    UINT64  Rounded = ((End - Start) + RAM_BLOCK_SIZE - 1) / RAM_BLOCK_SIZE * RAM_BLOCK_SIZE;
    DEBUG ((DEBUG_WARN, "UNIXNURAMDISK: initrd 0x%lx-0x%lx rounded to 0x%lx bytes\n", Start, End, Rounded));
    End = Start + Rounded;
  }

  return PublishRange (Start, End);
}

STATIC
BOOLEAN
LooksLikePayload (
  IN CONST UINT8  *Boot
  )
{
  UINT16  BytesPerSector;
  UINT32  TotalSectors;

  if ((CompareMem (Boot + 0x2B, mPayloadLabel, sizeof (mPayloadLabel)) != 0) &&
      (CompareMem (Boot + 0x47, mPayloadLabel, sizeof (mPayloadLabel)) != 0))
  {
    return FALSE;
  }

  BytesPerSector = ReadUnaligned16 ((CONST UINT16 *)(Boot + 0x0B));
  if ((BytesPerSector != 512) && (BytesPerSector != 1024) &&
      (BytesPerSector != 2048) && (BytesPerSector != 4096))
  {
    return FALSE;
  }

  TotalSectors = ReadUnaligned16 ((CONST UINT16 *)(Boot + 0x13));
  if (TotalSectors == 0) {
    TotalSectors = ReadUnaligned32 ((CONST UINT32 *)(Boot + 0x20));
  }

  return TotalSectors != 0;
}

STATIC
BOOLEAN
MemoryTypeScannable (
  IN EFI_MEMORY_TYPE  Type
  )
{
  switch (Type) {
    case EfiReservedMemoryType:
    case EfiLoaderCode:
    case EfiLoaderData:
    case EfiBootServicesCode:
    case EfiBootServicesData:
    case EfiRuntimeServicesCode:
    case EfiRuntimeServicesData:
    case EfiConventionalMemory:
    case EfiACPIReclaimMemory:
    case EfiACPIMemoryNVS:
    case EfiPersistentMemory:
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC
EFI_MEMORY_DESCRIPTOR *
GetScannableMemoryMap (
  OUT UINTN  *MapSizeOut,
  OUT UINTN  *DescriptorSizeOut
  )
{
  EFI_STATUS             Status;
  EFI_MEMORY_DESCRIPTOR  *Map;
  UINTN                  MapSize;
  UINTN                  MapKey;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;
  UINTN                  BufferSize;

  MapSize = 0;
  Status  = gBS->GetMemoryMap (&MapSize, NULL, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return NULL;
  }

  BufferSize = MapSize + DescriptorSize * 8;
  Map        = AllocatePool (BufferSize);
  if (Map == NULL) {
    return NULL;
  }

  Status = gBS->GetMemoryMap (&BufferSize, Map, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (EFI_ERROR (Status)) {
    FreePool (Map);
    return NULL;
  }

  *MapSizeOut        = BufferSize;
  *DescriptorSizeOut = DescriptorSize;
  return Map;
}

STATIC
BOOLEAN
ScanMemoryForPack (
  VOID
  )
{
  EFI_MEMORY_DESCRIPTOR  *Map;
  EFI_MEMORY_DESCRIPTOR  *Entry;
  UINTN                  MapSize;
  UINTN                  DescriptorSize;
  UINT64                 RegionStart;
  UINT64                 RegionEnd;
  UINT64                 Address;

  Map = GetScannableMemoryMap (&MapSize, &DescriptorSize);
  if (Map == NULL) {
    return FALSE;
  }

  for (Entry = Map;
       (UINT8 *)Entry < (UINT8 *)Map + MapSize;
       Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + DescriptorSize))
  {
    if (!MemoryTypeScannable (Entry->Type)) {
      continue;
    }

    RegionStart = Entry->PhysicalStart;
    RegionEnd   = RegionStart + MultU64x64 (Entry->NumberOfPages, EFI_PAGE_SIZE);

    for (Address = RegionStart; Address + sizeof (UNIXNUPK_HEADER) <= RegionEnd; Address += RAM_BLOCK_SIZE) {
      if (ReadUnaligned64 ((CONST UINT64 *)(UINTN)Address) != UNIXNUPK_MAGIC) {
        continue;
      }

      DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: pack at 0x%lx (region 0x%lx-0x%lx)\n", Address, RegionStart, RegionEnd));
      if (PublishPack ((CONST UINT8 *)(UINTN)Address, RegionEnd - Address)) {
        FreePool (Map);
        return TRUE;
      }
    }
  }

  FreePool (Map);
  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: pack not found in RAM\n"));
  return FALSE;
}

STATIC
BOOLEAN
ScanMemoryForPayload (
  VOID
  )
{
  EFI_MEMORY_DESCRIPTOR  *Map;
  EFI_MEMORY_DESCRIPTOR  *Entry;
  UINTN                  MapSize;
  UINTN                  DescriptorSize;
  UINT64                 RegionStart;
  UINT64                 RegionEnd;
  UINT64                 Address;
  UINT16                 BytesPerSector;
  UINT32                 TotalSectors;

  Map = GetScannableMemoryMap (&MapSize, &DescriptorSize);
  if (Map == NULL) {
    return FALSE;
  }

  for (Entry = Map;
       (UINT8 *)Entry < (UINT8 *)Map + MapSize;
       Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + DescriptorSize))
  {
    if (!MemoryTypeScannable (Entry->Type)) {
      continue;
    }

    RegionStart = Entry->PhysicalStart;
    RegionEnd   = RegionStart + MultU64x64 (Entry->NumberOfPages, EFI_PAGE_SIZE);

    for (Address = RegionStart; Address + RAM_BLOCK_SIZE <= RegionEnd; Address += RAM_BLOCK_SIZE) {
      if (!LooksLikePayload ((CONST UINT8 *)(UINTN)Address)) {
        continue;
      }

      BytesPerSector = ReadUnaligned16 ((CONST UINT16 *)(UINTN)(Address + 0x0B));
      TotalSectors   = ReadUnaligned16 ((CONST UINT16 *)(UINTN)(Address + 0x13));
      if (TotalSectors == 0) {
        TotalSectors = ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + 0x20));
      }

      DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: payload at 0x%lx (%u x %u)\n", Address, TotalSectors, BytesPerSector));
      if (PublishRange (Address, Address + MultU64x32 (TotalSectors, BytesPerSector))) {
        FreePool (Map);
        return TRUE;
      }
    }
  }

  FreePool (Map);
  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: payload not found in RAM\n"));
  return FALSE;
}

EFI_STATUS
EFIAPI
UniXNURamDiskDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HOB_GUID_TYPE  *Hob;
  UINT64             Dtb;

  Hob = GetFirstGuidHob (&mEntryArgHobGuid);
  if (Hob == NULL) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no entry argument HOB\n"));
    if (!ScanMemoryForPack ()) {
      ScanMemoryForPayload ();
    }

    return EFI_SUCCESS;
  }

  if (GET_GUID_HOB_DATA_SIZE (Hob) < sizeof (UINT64)) {
    return EFI_COMPROMISED_DATA;
  }

  Dtb = ReadUnaligned64 ((CONST UINT64 *)GET_GUID_HOB_DATA (Hob));
  if ((Dtb == 0) || ((Dtb & 3) != 0) || (FdtCheckHeader ((VOID *)(UINTN)Dtb) != 0)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: x0 0x%lx is not a device tree\n", Dtb));
    if (!ScanMemoryForPack ()) {
      ScanMemoryForPayload ();
    }

    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: device tree at 0x%lx, %u bytes\n", Dtb, (UINT32)FdtTotalSize ((VOID *)(UINTN)Dtb)));

  if (PublishInitrd ((VOID *)(UINTN)Dtb)) {
    return EFI_SUCCESS;
  }

  if (!ScanMemoryForPack ()) {
    ScanMemoryForPayload ();
  }

  return EFI_SUCCESS;
}
