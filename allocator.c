#include "./allocator.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define ALIGN 40  // Relative byte alignment
// Expected canaries for corruption detection in metadata
#define CANARY_HEADER 0xDEADBEEF
#define CANARY_FOOTER 0xBEEFDEAD

// Ordering properties largest to smallest avoids compiler adding extra padding
typedef struct block_header {
  size_t size;  // Total size of block (header, footer, and payload)
  size_t user_size;  // Size specified by user when block was allocated
  uint32_t canary;  // Canary to quickly catch significant corruption
  uint32_t checksum;  // Checksum for wider corruption detection area
  uint32_t version_start;  // Versioning for metadata brownout detection
  uint32_t version_end;
  uint8_t allocated;  // Has the block been user allcoated
  uint8_t quarantined;  // Is the block known to be corrupted
  uint8_t alignment_padding[6];  // Enforce 40 byte allignment
} block_header_t;

typedef struct block_footer {
  size_t size;  // Mirrored properties to detect corruption
  uint32_t canary;
  uint32_t payloadChecksum;  // Checksum to detect corruption in the user data
  uint32_t version_start;
  uint32_t version_end;
  uint8_t alignment_padding[16];  // Enforce 40 byte alignment
} block_footer_t;

// Global heap properties
static uint8_t *heap_start = NULL;  // Inital heap pointer
static size_t heap_total_size = 0;  // Requested heap size
static uint8_t free_pattern[5];  // 5-byte repeating pattern signaling free data

// Global coarse-grained locking mutex
static pthread_mutex_t allocator_lock = PTHREAD_MUTEX_INITIALIZER;

// ### Helper functions ###

// Adjust size to 40-byte alignment
static size_t align_block(size_t payloadSize) {
  size_t totalSize = payloadSize + sizeof(block_header_t)
    + sizeof(block_footer_t);  // Size needed for payload and metadata

  // Round to multiple of 40
  size_t alignedSize = ((totalSize + ALIGN-1) / ALIGN) * ALIGN;

  return alignedSize;
}

// Grab footer metadata
static block_footer_t *get_footer(block_header_t *block) {
  // Verify size is reasonable to avoid grabbing corrupted footer
  if (block->size == 0 || block->size > heap_total_size) {
    return NULL;
  }

  uint8_t *header = (uint8_t *) block;
  uint8_t *footerAddr = header + block->size - sizeof(block_footer_t);

  // Verify footer address is reasonable to avoid grabbing corruped footer
  if (footerAddr < heap_start || footerAddr >= heap_start + heap_total_size) {
    return NULL;
  }

  block_footer_t *footer = (block_footer_t *) footerAddr;

  // Check canary has not been modified (corrupted)
  if (footer->canary != CANARY_FOOTER) {
    return NULL;
  }

  return footer;
}

// Traverse to next block in heap
static void *get_next_block(block_header_t *block) {
  // Check block bounds are reasonable
  if (block == NULL || (uint8_t *) block < heap_start ||
    (uint8_t *) block >= heap_start + heap_total_size) {
    return NULL;
  }

  // Check block size is reasonable
  if (block->size == 0 || block->size > heap_total_size) {
    return NULL;
  }

  uint8_t *blockStart = (uint8_t *) block;
  uint8_t *nextBlock = blockStart + block->size;  // Jump to next block

  // Check we haven't left the heap
  if (nextBlock >= heap_start + heap_total_size) {
    return NULL;
  }

  return (void *) nextBlock;
}

// Traverse backwards in heap
static void *get_prev_block(block_header_t *block) {
  // Check block bounds are reasonable
  if (block == NULL || (uint8_t *) block < heap_start ||
    (uint8_t *) block >= heap_start + heap_total_size) {
    return NULL;
  }

  if (block->size == 0 ||
    block->size > heap_total_size) {  // Check block size is reasonable
    return NULL;
  }

  uint8_t *currBlock = (uint8_t *) block;

  // No previous block, at start of heap
  if (currBlock == heap_start) return NULL;

  // Jump to footer metadata
  uint8_t *prevFooterAddr = currBlock - sizeof(block_footer_t);
  block_footer_t *prevFooter = (block_footer_t *) prevFooterAddr;

  // Check canary has not been corrupted
  if (prevFooter->canary != CANARY_FOOTER) return NULL;

  if (prevFooter->size == 0 ||
    prevFooter->size > heap_total_size) {  // Check size is reasonable
    return NULL;
  }

  // Jump to start of previous block data
  uint8_t *prevBlock = prevFooterAddr -
    (prevFooter->size - sizeof(block_footer_t));

  if (prevBlock < heap_start) {  // Check we are within the heap
    return NULL;
  }

  return (void *) prevBlock;
}

// Metadata into a CRC-32 checksum
static uint32_t generateChecksum(block_header_t *block) {
  uint32_t crc = 0xFFFFFFFF;  // All 1s

  // Size Field
  for (size_t i = 0; i < sizeof(size_t); i++) {
    uint8_t byte = (block->size >> (i * 8)) & 0xFF;
    crc ^= byte;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
    }
  }

  // User Size Field
  for (size_t i = 0; i < sizeof(size_t); i++) {
    uint8_t byte = (block->user_size >> (i * 8)) & 0xFF;
    crc ^= byte;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
    }
  }

  // Canary
  for (size_t i = 0; i < sizeof(uint32_t); i++) {
    uint8_t byte = (block->canary >> (i * 8)) & 0xFF;
    crc ^= byte;
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
    }
  }

  // Allocated Field
  crc ^= block->allocated;
  for (int bit = 0; bit < 8; bit++) {
    crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
  }

  // Quarantined Field
  crc ^= block->quarantined;
  for (int bit = 0; bit < 8; bit++) {
    crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
  }
  return ~crc;
}

// CRC alg turns payload into a checksum
static uint32_t generatePayloadChecksum(uint8_t *data, size_t length) {
  uint32_t crc = 0xFFFFFFFF;  // All 1s

  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];  // XOR byte into CRC

    // Process each bit using CRC-32 polynomial
    for (int bit = 0; bit < 8; bit++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xEDB88320;  // CRC-32 polynomial
      } else {
        crc = crc >> 1;
      }
    }
  }
  return ~crc;
}

// Check for possible corruption in block
static int isValid(block_header_t *block) {
  // Check basic bounds
  if ((uint8_t *) block < heap_start || (uint8_t *) block >=
    heap_start + heap_total_size - sizeof(block_header_t)) {
      return 0;
  }

  // Check size is reasonable
  if (block->size == 0 || block->size > heap_total_size) {
      return 0;
  }

  // Check version consistency header
  if (block->version_start != block->version_end) {
    return 0;
  }

  // Check header canary
  if (block->canary != CANARY_HEADER) {
    return 0;
  }

  block_footer_t *footer = get_footer(block);

  // Don't access NULL footers
  if (footer == NULL) {
    return 0;
  }

  // Check footer canary
  if (footer->canary != CANARY_FOOTER) {
    return 0;
  }

  // Check version consistency footer
  if (footer->version_start != footer->version_end) {
    return 0;
  }

  // Check header and footer versions match
  if (block->version_start != footer->version_start) {
    return 0;
  }

  // Check mirrored size
  if (block->size != footer->size) {
    return 0;
  }

  // Check metadata checksum
  if (block->checksum != generateChecksum(block)) {
    return 0;
  }

  uint8_t *data = (uint8_t *) block + sizeof(block_header_t);
  size_t usableSpace = block->user_size;

  // Check payload checksum only if block is allocated
  if (block->allocated == 1) {
    if (footer->payloadChecksum != generatePayloadChecksum(data, usableSpace)) {
      return 0;
    }
  }

  return 1;
}
// Initialise or reinitialise block
static int createBlock(block_header_t *block, size_t size,
                       size_t userSize, uint8_t allocated) {
  uint8_t *header = (uint8_t *) block;
  uint8_t *footerAddr = header + size - sizeof(block_footer_t);

  // check the footer location is reasonable
  if (footerAddr < heap_start || footerAddr >= heap_start + heap_total_size) {
    return -1;
  }

  block_footer_t *footer = (block_footer_t *) footerAddr;
  uint8_t *data = (uint8_t *) block + sizeof(block_header_t);

  // Newly created blocks need versions initiated
  if (!block->version_start) {
    block->version_start = 0;
  }
  if (!block->version_end) {
    block->version_end = 0;
  }

  // Increment version
  uint32_t new_version = block->version_start + 1;
  block->version_start = new_version;
  if (block->version_start != new_version) return -1;
  block->version_end = 0;  // Invalidate end version
  if (block->version_end != 0) {
    return -1;  // Brownout during version write
  }

  // invalidate canaries for brownout detection
  block->canary = 0;
  if (block->canary != 0) return -1;  // Brownout during invalidation

  footer->canary = 0;
  if (footer->canary != 0) return -1;  // Brownout during invalidation

  // Invalidate footer version
  footer->version_start = new_version;
  if (footer->version_start != new_version) {
    return -1;
  }
  footer->version_end = 0;
  if (footer->version_end != 0) return -1;

  // header fields
  block->size = size;
  if (block->size != size) return -1;  // Brownout during size write

  block->user_size = userSize;
  if (block->user_size != userSize) return -1;  // Brownout during usersize

  block->allocated = allocated;
  if (block->allocated != allocated) return -1;  // Brownout during allocate

  block->quarantined = 0;
  if (block->quarantined != 0) return -1;  // Brownout during quarantine write

  // footer fields
  footer->size = size;
  if (footer->size != size) return -1;  // Brownout during footer size write

  if (allocated == 1) {
    uint32_t expectedChecksum = generatePayloadChecksum(data, userSize);
    footer->payloadChecksum = expectedChecksum;
    if (footer->payloadChecksum != expectedChecksum) return -1;
  } else {
    footer->payloadChecksum = 0;
  }

  // Canary repair to commit changes
  footer->canary = CANARY_FOOTER;
  if (footer->canary != CANARY_FOOTER) {
    block->canary = 0;  // Re-invalidate header
    footer->canary = 0;  // Re-invalidate footer
    return -1;
  }

  // Commit footer version
  footer->version_end = new_version;
  if (footer->version_end != new_version) {
    block->canary = 0;
    footer->canary = 0;
    return -1;
  }

  block->canary = CANARY_HEADER;
  if (block->canary != CANARY_HEADER) {
    block->canary = 0;  // Re-invalidate
    footer->canary = 0;  // Re-invalidate
    return -1;
  }

  // Final header checksum generation
  block->checksum = generateChecksum(block);
  if (block->checksum != generateChecksum(block)) {
    block->canary = 0;  // Re-invalidate
    footer->canary = 0;  // Re-invalidate
    return -1;
  }

  // Commit header version
  block->version_end = new_version;
  if (block->version_end != new_version) {
    block->canary = 0;
    footer->canary = 0;
    return -1;
  }

  return 0;
}

static int writeFreePattern(block_header_t *block) {
  size_t dataSize = block->size
    - sizeof(block_header_t) - sizeof(block_footer_t);
  uint8_t *dataPointer = (uint8_t *) block + sizeof(block_header_t);
  for (size_t i = 0; i < dataSize; i++) {
    dataPointer[i] = free_pattern[i % 5];
  }

  // Check for brownout during free pattern write
  for (size_t i = 0; i < dataSize; i++) {
    if (dataPointer[i] != free_pattern[i % 5]) {
      return -1;
    }
  }

  return 0;
}

// Combine adjascent free blocks into one
static void coalesce(block_header_t *block) {
  // Don't touch if block is corrupted
  if (isValid(block) == 0 || block->quarantined) {
    return;
  }

  block_header_t *nextBlock = (block_header_t *) get_next_block(block);

  size_t userSize = 0;
  int allocated = 0;

  if (nextBlock != NULL && isValid(nextBlock) && nextBlock->allocated == 0
    && nextBlock->quarantined == 0) {  // If not corrupted coalesce
    size_t newSize = block->size + nextBlock->size;

    // Write free pattern TODO: Check ordering of this
    if (writeFreePattern(block) != 0) return;

    // Reinitialise block with new size and free
    if (createBlock(block, newSize, userSize, allocated) == 0) {
      if (isValid(block) == 0) {  // Validate for brownout
        return;
      }
    } else {
      return;
    }
  }

  if (block->quarantined) {
    return;
  }

  block_header_t *prevBlock = (block_header_t *) get_prev_block(block);

  if (prevBlock != NULL && isValid(prevBlock) && prevBlock->allocated == 0 &&
    prevBlock->quarantined == 0) {  // If not corrupted then coalesce
    size_t newSize = prevBlock->size + block->size;

    // Write free pattern  TODO: and again here!
    if (writeFreePattern(prevBlock) != 0) {
      prevBlock->quarantined = 1;
      return;
    }
    // Reinitialise block with new size
    if (createBlock(prevBlock, newSize, userSize, allocated) == 0) {
      if (isValid(prevBlock) == 0) {
        prevBlock->quarantined = 1;
      }
    } else {
      prevBlock->quarantined = 1;
    }
  }
}

// ### Shared library functions ###

// Initialize the allocator over a provided memory block.
// Returns 0 on success, non-zero on failure.
int mm_init(uint8_t *heap, size_t heap_size) {
  // Heap must be a valid pointer and at least big enough for the metadata
  if (heap == NULL ||
    heap_size < sizeof(block_header_t) + sizeof(block_footer_t)) {
    return -1;
  }

  // Define global heap properties
  heap_start = heap;
  heap_total_size = heap_size;

  // Check pattern for storm corruption

  // Compare bytes 0-4 with 5-9
  if (heap_size >= 10) {
    for (int i = 0; i < 5; i++) {
      if (heap[i] != heap[5 + i]) {
        return -1;  // Free-pattern corrupted
      }
    }
  }

  // Compare bytes 0-4 with 10-14
  if (heap_size >= 15) {
    for (int i = 0; i < 5; i++) {
      if (heap[i] != heap[10 + i]) {
        return -1;  // Free-pattern corrupted
      }
    }
  }

  // Grab validated 5 byte repeating pattern
  for (int i = 0; i < 5; i++) {
    free_pattern[i] = heap[i];
  }

  block_header_t *initialBlock = (block_header_t *) heap_start;

  size_t userSize = 0;
  int allocated = 0;
  // Initialise block
  if (createBlock(initialBlock, heap_total_size, userSize, allocated) != 0) {
    return -1;  // Failed to create initial block
  }

  return 0;
}

// Allocate a block with ALIGN-byte aligned payload. Returns NULL on failure.
void *mm_malloc(size_t size) {
  pthread_mutex_lock(&allocator_lock);

  if (size == 0) {  // No memory to allocate
    pthread_mutex_unlock(&allocator_lock);
    return NULL;
  }

  size_t spaceRequired = align_block(size);  // Adjust size to 40-byte alignment

  uint8_t *heapPointer = heap_start;  // Traverse from beginning of heap

  // Traverse heap untill suitable block is found
  while (heapPointer < heap_total_size + heap_start) {
    block_header_t *block = (block_header_t *) heapPointer;

    if (isValid(block) == 0) {  // Size can't be trusted
      // Search for non-corrupt block using alignment
      heapPointer += ALIGN;

      uint8_t *lastAddress = heap_start + heap_total_size
        - sizeof(block_header_t);
      while (heapPointer < lastAddress) {
        block_header_t *possibleBlock = (block_header_t *) heapPointer;
        if (isValid(possibleBlock)) {
          break;  // Valid block found, continue as normal
        }
        heapPointer += ALIGN;
      }
      continue;
    }

    if (block->quarantined == 0 && block->allocated == 0
      && block->size >= spaceRequired) {  // Suitable block
      // What space is left over after allocation
      size_t surplus = block->size - spaceRequired;

      // Minimum size to contain metadata and a payload
      size_t minimum = align_block(1);

      size_t blockSize = block->size;  // Default to allocating entire block
      size_t userSize = size;  // User-specified usable space in block
      int blockAllocated = 1;

      // Extra space in block large enough for new block
      if (surplus >= minimum) {
        blockSize = spaceRequired;  // Only allocate what is needed

        uint8_t *splitPos = (uint8_t *) (heapPointer + spaceRequired);
        block_header_t *newBlock = (block_header_t *) splitPos;

        size_t userSizeSurplus = 0;  // Free block
        int newBlockAllocated = 0;
        // On allocation failure fallback to allocting full block
        if (createBlock(newBlock, surplus,
                        userSizeSurplus, newBlockAllocated) == 0) {
          // Must reset free pattern sequence for new unallocated block
          if (writeFreePattern(newBlock) != 0) {
            blockSize = block->size;
          }
        } else {
          blockSize = block->size;
        }
      }

      if (createBlock(block, blockSize, userSize, blockAllocated) != 0) {
        // createBlock failed so block is likely corrupted
        // search for next valid block using alignment
        heapPointer += ALIGN;

        uint8_t *lastAddress = heap_start + heap_total_size
          - sizeof(block_header_t);

        while (heapPointer < lastAddress) {
          block_header_t *nextPossible = (block_header_t *) heapPointer;
          if (isValid(nextPossible)) {
            break;
          }
          heapPointer += ALIGN;
        }
        continue;
      }

      // Return pointer to data
      void *dataPointer = (void *) (heapPointer + sizeof(block_header_t));

      pthread_mutex_unlock(&allocator_lock);
      return dataPointer;
    }

    heapPointer += block->size;  // Move on to next block
  }

  pthread_mutex_unlock(&allocator_lock);
  return NULL;  // No suitable memory block was found.
}

// Safely read data from an allocated block at offset bytes into buf.
// Returns the number of bytes read,
// or -1 if corruption or invalid pointer detected.
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
  pthread_mutex_lock(&allocator_lock);
  if (ptr == NULL || buf == NULL) {  // Pointer or buffer invalid
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  uint8_t *data = (uint8_t *) ptr;
  block_header_t *block = (block_header_t *)(data - sizeof(block_header_t));

  if (isValid(block) == 0 || block->quarantined == 1) {  // Block corrupt
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  size_t usableSpace = block->user_size;

  // Verify userSize is reasonable
  size_t total_payload = block->size
    - sizeof(block_header_t) - sizeof(block_footer_t);
  if (usableSpace > total_payload) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Don't read if offset is beyond the user's allocated size
  if (offset >= usableSpace) {
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  uint8_t *readFrom = data + offset;
  uint8_t *buffer = (uint8_t *) buf;
  size_t bytesFromOffset = usableSpace - offset;

  size_t toRead;
  // Read the minimum of length and bytes after provided offset
  if (len < bytesFromOffset) {
    toRead = len;
  } else {
    toRead = bytesFromOffset;
  }

  // Read into buffer
  for (size_t i = 0; i < toRead; i++) {
    buffer[i] = readFrom[i];
  }

  pthread_mutex_unlock(&allocator_lock);
  return (int) toRead;
}

// Safely write data into an allocated block at offset bytes from src.
// Returns the number of bytes written,
// or -1 if corruption or invalid pointer detected.
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
  pthread_mutex_lock(&allocator_lock);

  if (ptr == NULL || src == NULL) {  // Pointer or source invalid
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  uint8_t *data = (uint8_t *) ptr;
  uint8_t *header = data - sizeof(block_header_t);
  block_header_t *block = (block_header_t *) header;

  // Don't write to corrupted blocks
  if (isValid(block) == 0 || block->quarantined == 1) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  size_t usableSpace = block->user_size;

  // Verify userSize is reasonable
  size_t total_payload = block->size
    - sizeof(block_header_t) - sizeof(block_footer_t);
  if (usableSpace > total_payload) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Verify offset is not beyond user space
  if (offset >= usableSpace) {
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Can't write beyond allocated space so truncate
  if (offset + len > usableSpace) {
    len = usableSpace - offset;
  }

  // Only allow writes that fill allocated space
  if (offset + len != usableSpace) {
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Try grab footer
  block_footer_t *footer = get_footer(block);
  if (footer == NULL) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Increment header version to signal metadata write in progress
  uint32_t new_version = block->version_start + 1;
  block->version_start = new_version;
  if (block->version_start != new_version) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  block->version_end = 0;  // Invalidate header
  if (block->version_end != 0) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Invalidate footer version
  footer->version_start = new_version;
  if (footer->version_start != new_version) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  footer->version_end = 0;  // Invalidate footer
  if (footer->version_end != 0) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  uint8_t *writeFrom = data + offset;
  uint8_t *source = (uint8_t *) src;
  int bytesWritten = 0;

  // Write
  for (size_t i = 0; i < len; i++) {
    writeFrom[i] = source[i];
    bytesWritten += 1;
  }

  // Validate the write (brownout detection)
  if (bytesWritten != (int) len) {  // Length comparison
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }
  for (size_t i = 0; i < len; i++) {  // Data comparison
    if (writeFrom[i] != source[i]) {
      block->quarantined = 1;
      pthread_mutex_unlock(&allocator_lock);
      return -1;
    }
  }

  // Update payload checksum
  footer->payloadChecksum = generatePayloadChecksum(data, usableSpace);

  // Commit footer version
  footer->version_end = new_version;
  if (footer->version_end != new_version) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Commit header version
  block->version_end = new_version;
  if (block->version_end != new_version) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  // Verify the block is still valid after metadata write
  if (isValid(block) == 0) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return -1;
  }

  pthread_mutex_unlock(&allocator_lock);
  return bytesWritten;
}

// Free a previously-allocated pointer (ignore NULL).
// Must detect double-free.
void mm_free(void *ptr) {
  pthread_mutex_lock(&allocator_lock);

  if (ptr == NULL) {  // Pointer not valid
    pthread_mutex_unlock(&allocator_lock);
    return;
  }

  uint8_t *data = (uint8_t *) ptr;

  uint8_t *header = data - sizeof(block_header_t);
  block_header_t *block = (block_header_t *) header;

  if (isValid(block) == 0) {  // Don't free corrupt blocks
    pthread_mutex_unlock(&allocator_lock);
    return;
  }

  if (block->allocated == 0) {  // Don't double-free
    pthread_mutex_unlock(&allocator_lock);
    return;
  }

  // Reset 5-byte pattern for free memory
  if (writeFreePattern(block) != 0) {
    pthread_mutex_unlock(&allocator_lock);
    return;
  }

  // Reinitialise block as free (also updates checksum)
  if (createBlock(block, block->size, 0, 0) != 0) {
    pthread_mutex_unlock(&allocator_lock);
    return;
  }

  // Check validity after reinitialisation
  if (isValid(block) == 0) {
    pthread_mutex_unlock(&allocator_lock);
    return;
  }

  coalesce(block);  // Coalesce adjacent unallocated blocks
  pthread_mutex_unlock(&allocator_lock);
}

// Resize a previously allocated block to new_size bytes, preserving data.
void *mm_realloc(void *ptr, size_t new_size) {
  if (ptr == NULL) {  // Pointer invalid
    return mm_malloc(new_size);
  }

  if (new_size == 0) {  // Realocating to size 0 is freeing
    mm_free(ptr);
    return NULL;
  }

  pthread_mutex_lock(&allocator_lock);

  uint8_t *data = (uint8_t *) ptr;
  block_header_t *block = (block_header_t *) (data - sizeof(block_header_t));

  // Don't reallocate corrupt blocks
  if (isValid(block) == 0 || block->quarantined) {
    block->quarantined = 1;
    pthread_mutex_unlock(&allocator_lock);
    return NULL;
  }

  // Use userSize
  size_t oldUserSize = block->user_size;
  // May be enough space in padded payload for reallocation
  size_t available_payload = block->size
    - sizeof(block_header_t) - sizeof(block_footer_t);

  // Minimum size for metadata and a payload
  size_t blockMinSize = align_block(1);

  // Shrink usable space
  if (new_size < oldUserSize) {  // May need to split off freed space
    size_t reallocSize = align_block(new_size);
    size_t leftover = block->size - reallocSize;

    // If leftover is at least minumum block size, split
    if (leftover >= blockMinSize) {
      int blockAllocated = 1;
      if (createBlock(block, reallocSize,
                      new_size, blockAllocated) == 0) {  // Create succeded
        uint8_t *splitPos = (uint8_t *) block + reallocSize;
        block_header_t *newBlock = (block_header_t *) splitPos;

        size_t newBlockUserSize = 0;
        int newBlockAllocated = 0;
        if (createBlock(newBlock, leftover,
                        newBlockUserSize, newBlockAllocated) == 0) {
          // Reset free pattern
          if (writeFreePattern(newBlock) == 0) {
            coalesce(newBlock);
          } else {
            newBlock->quarantined = 1;
          }
        }

        pthread_mutex_unlock(&allocator_lock);
        return ptr;
      }  // If createBlock failed defaults to malloc
    } else {  // No split needed just shrink
        uint8_t *newPaddingStart = data + new_size;
        size_t newPaddingLength = oldUserSize - new_size;

        for (size_t i = 0; i < newPaddingLength; i++) {
          newPaddingStart[i] = 0;  // Overwrite shrunk data
        }

        int blockAllocated = 1;
        if (createBlock(block, block->size, new_size, blockAllocated) == 0) {
          pthread_mutex_unlock(&allocator_lock);
          return ptr;
        }  // Otherwise defailts to malloc
      }
    // new_size fits in current block, but not usable space
  } else if (new_size <= available_payload) {
    // Update userSize and return same pointer
    if (createBlock(block, block->size, new_size, 1) == 0) {
      pthread_mutex_unlock(&allocator_lock);
      return ptr;
    }  // Failure defaults to malloc
  } else {
    block_header_t *nextBlock = (block_header_t *) get_next_block(block);

    // Next block exists and is not corrupted
    if (nextBlock && nextBlock->allocated == 0 && isValid(nextBlock) == 1) {
      size_t availableSize = (block->size + nextBlock->size);
      size_t spaceRequired = align_block(new_size);

      // Check there is enough space to reach requested size
      if (availableSize >= spaceRequired) {
        size_t surplus = availableSize - spaceRequired;

        size_t blockSize = availableSize;  // Default to whole space

        if (surplus >= blockMinSize) {
          blockSize = spaceRequired;  // Only use space required

          uint8_t *splitPos = (uint8_t *) block + spaceRequired;
          block_header_t *newBlock = (block_header_t *) splitPos;

          // Split off free block
          if (createBlock(newBlock, surplus, 0, 0) == 0) {
            // Reset free pattern
            if (writeFreePattern(newBlock) == 0) {
              // Only coalece if free pattern was written
              coalesce(newBlock);
            } else {
              newBlock->quarantined = 1;
            }
          } else {
            // On failure to split just use whole space
            blockSize = availableSize;
          }
        }

        // Create expanded block with specified userSize
        if (createBlock(block, blockSize, new_size, 1) == 0) {
          pthread_mutex_unlock(&allocator_lock);
          return ptr;
        }  // On failure defaults to malloc
      }  // Next block not large enough, default to malloc
    }  // Next block invalid/allocated, default to malloc
  }

  // Unlock to call mm_malloc
  pthread_mutex_unlock(&allocator_lock);
  void *newPtr = mm_malloc(new_size);
  if (newPtr == NULL) {
    return NULL;
  }

  // Re-lock heap
  pthread_mutex_lock(&allocator_lock);
  // Copy old data to new address
  uint8_t *oldData = (uint8_t *) ptr;
  uint8_t *newData = (uint8_t *) newPtr;
  size_t copySize = (oldUserSize < new_size) ? oldUserSize : new_size;

  for (size_t i = 0; i < copySize; i++) {
    newData[i] = oldData[i];
  }

  block_header_t *newHeader = (block_header_t *)
    (newData - sizeof(block_header_t));

  if (isValid(newHeader) == 0) {
    pthread_mutex_unlock(&allocator_lock);
    mm_free(newPtr);
    return NULL;  // New block allocation failed
  }

  pthread_mutex_unlock(&allocator_lock);
  mm_free(data);
  return newPtr;
}

// Output current heap usage and integrity statistics
// for debugging (No Credit, helper function).
void mm_heap_stats(void) {
  int allocatedBlocks = 0;
  int freeBlocks = 0;
  int allocatedBytes = 0;
  int unallocatedBytes = 0;
  uint8_t *address = heap_start;
  uint8_t *end = heap_start + heap_total_size;
  while (address < end) {
    block_header_t *block = (block_header_t *) address;

    // Handle corrupted blocks
    if (block->size == 0 || block->size > heap_total_size
      || address + block->size > end) {
      printf("## Corrupted block found, heap stats may be inacurate ##\n");
      break;
    }

    if (block->allocated == 0) {
      freeBlocks += 1;
      unallocatedBytes += block->size;
    } else if (block->allocated == 1) {
      allocatedBlocks += 1;
      allocatedBytes += block->size;
    }
    address += block->size;
  }

  int heapUsage = (allocatedBytes * 100 / heap_total_size);

  printf("Total Heap Size: %zuB\n", heap_total_size);
  printf("Allocated Blocks: %d\n", allocatedBlocks);
  printf("Unallocated Blocks: %d\n", freeBlocks);
  printf("Total Allocated Bytes: %dB\n", allocatedBytes);
  printf("Total Unallocated Bytes: %dB\n", unallocatedBytes);
  printf("Heap Usage: %d%%\n", heapUsage);
}
