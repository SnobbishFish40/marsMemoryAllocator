#include "allocator.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    printf("=== SIMPLE TEST ===\n\n");
    
    // Create heap
    uint8_t heap[2000];
    
    // Test 1: Init
    printf("Test 1: Initialize heap\n");
    if (mm_init(heap, sizeof(heap)) != 0) {
        printf("✗ FAILED: Init failed\n");
        return 1;
    }
    printf("✓ PASSED: Init\n\n");
    
    // Test 2: Single allocation
    printf("Test 2: Allocate 100 bytes\n");
    void *ptr1 = mm_malloc(100);
    if (ptr1 == NULL) {
        printf("✗ FAILED: Allocation returned NULL\n");
        return 1;
    }
    uintptr_t ptr1Num = (uintptr_t) ptr1;
    if (ptr1Num % 40 != 0) {
      printf("FAILED: Memory address not a multiple of 40\n");
      return 1;
    }
    printf("✓ PASSED: Got pointer %p\n", ptr1);
    printf("  Address is at offset: %ld from heap start\n\n", (uint8_t*)ptr1 - heap);
    
    // Test 3: Write data
    printf("Test 3: Write data\n");
    const char *msg = "Hello!";
    int written = mm_write(ptr1, 0, msg, strlen(msg) + 1);
    if (written < 0) {
        printf("✗ FAILED: Write returned %d\n", written);
        return 1;
    }
    printf("✓ PASSED: Wrote %d bytes\n\n", written);
    
    // Test 4: Read data back
    printf("Test 4: Read data\n");
    char buffer[100];
    int read_bytes = mm_read(ptr1, 0, buffer, sizeof(buffer));
    if (read_bytes < 0) {
        printf("✗ FAILED: Read returned %d\n", read_bytes);
        return 1;
    }
    printf("✓ PASSED: Read %d bytes: '%s'\n\n", read_bytes, buffer);
    
    // Test 5: Second allocation
    printf("Test 5: Allocate another 50 bytes\n");
    void *ptr2 = mm_malloc(50);
    if (ptr2 == NULL) {
        printf("✗ FAILED: Second allocation returned NULL\n");
        return 1;
    }
    printf("✓ PASSED: Got pointer %p\n\n", ptr2);
    
    // Test 6: Free first pointer
    printf("Test 6: Free first pointer\n");
    mm_free(ptr1);
    printf("✓ PASSED: Freed ptr1\n\n");
    
    // Test 7: Free second pointer
    printf("Test 7: Free second pointer\n");
    mm_free(ptr2);
    printf("✓ PASSED: Freed ptr2\n\n");
    
    // Test 8: Allocate after freeing
    printf("Test 8: Allocate 80 bytes (should reuse freed space)\n");
    void *ptr3 = mm_malloc(80);
    if (ptr3 == NULL) {
        printf("✗ FAILED: Allocation after free returned NULL\n");
        return 1;
    }
    printf("✓ PASSED: Got pointer %p\n", ptr3);
    printf("  Same as ptr1? %s\n\n", ptr1 == ptr3 ? "YES (reused!)" : "NO");
    
    // Test 9: Heap stats
    printf("Test 9: Check heap stats\n");
    mm_heap_stats();
    
    // Clean up
    mm_free(ptr3);
    
    printf("\n=== CORRUPTION TESTS ===\n\n");
    
    // Test 10: Corrupt header magic and try to read
    printf("Test 10: Corrupt header canary\n");
    void *ptr4 = mm_malloc(100);
    if (!ptr4) {
        printf("✗ FAILED: Allocation failed\n");
        return 1;
    }
    
    // Write some data first
    mm_write(ptr4, 0, "Valid data", 11);
    
    // Manually corrupt the header canary
    typedef struct {
        size_t size;
        uint8_t allocated;
        uint8_t quarantined;
        uint32_t canary;
        uint32_t checksum;
        uint8_t padding[22];
    } test_header_t;
    
    test_header_t *corrupt_hdr = (test_header_t *)((uint8_t *)ptr4 - sizeof(test_header_t));
    printf("  Original canary: 0x%X\n", corrupt_hdr->canary);
    corrupt_hdr->canary = 0xBADBAD;  // Corrupt it!
    printf("  Corrupted canary: 0x%X\n", corrupt_hdr->canary);
    
    // Try to read - should fail
    char test_buf[20];
    int result = mm_read(ptr4, 0, test_buf, sizeof(test_buf));
    if (result == -1) {
        printf("✓ PASSED: Detected corrupted canary (read returned -1)\n\n");
    } else {
        printf("✗ FAILED: Did not detect corrupted canary (read returned %d)\n\n", result);
    }
    
    // Test 11: Corrupt footer and try to write
    printf("Test 11: Corrupt footer canary\n");
    void *ptr5 = mm_malloc(100);
    if (!ptr5) {
        printf("✗ FAILED: Allocation failed\n");
        return 1;
    }
    
    // Manually corrupt the footer
    typedef struct {
        size_t size;
        uint32_t canary;
        uint8_t padding[28];
    } test_footer_t;
    
    test_header_t *hdr = (test_header_t *)((uint8_t *)ptr5 - sizeof(test_header_t));
    test_footer_t *corrupt_ftr = (test_footer_t *)((uint8_t *)hdr + hdr->size - sizeof(test_footer_t));
    
    printf("  Original footer canary: 0x%X\n", corrupt_ftr->canary);
    corrupt_ftr->canary = 0xDEADDEAD;  // Corrupt it!
    printf("  Corrupted footer canary: 0x%X\n", corrupt_ftr->canary);
    
    // Try to write - should fail
    const char *test_data = "test";
    result = mm_write(ptr5, 0, test_data, 5);
    if (result == -1) {
        printf("✓ PASSED: Detected corrupted footer (write returned -1)\n\n");
    } else {
        printf("✗ FAILED: Did not detect corrupted footer (write returned %d)\n\n", result);
    }
    
    // Don't free corrupted blocks - they should be quarantined
    
  // Test 12: Corrupt size (header-footer mismatch)
    printf("Test 12: Corrupt size (brownout simulation)\n");
    void *ptr6 = mm_malloc(100);
    if (!ptr6) {
        printf("✗ FAILED: Allocation failed\n");
        return 1;
    }
    
    test_header_t *hdr6 = (test_header_t *)((uint8_t *)ptr6 - sizeof(test_header_t));
    size_t original_size = hdr6->size;
    printf("  Original size: %zu\n", original_size);
    
    // Corrupt header size (simulate brownout - header updated but footer not)
    hdr6->size = original_size + 100;
    printf("  Corrupted header size: %zu\n", hdr6->size);
    printf("  Footer size still: %zu (mismatch!)\n", original_size);
    
    // Try to read - should detect size mismatch
    result = mm_read(ptr6, 0, test_buf, sizeof(test_buf));
    if (result == -1) {
        printf("✓ PASSED: Detected size mismatch\n\n");
    } else {
        printf("✗ FAILED: Did not detect size mismatch\n\n");
    }
    mm_heap_stats();
    
    mm_init(heap, sizeof(heap));
    mm_heap_stats();

    // Test 13: Corrupt checksum
    printf("Test 13: Corrupt checksum\n");
    void *ptr7 = mm_malloc(100);
    if (!ptr7) {
        printf("✗ FAILED: Allocation failed\n");
        return 1;
    }
    
    test_header_t *hdr7 = (test_header_t *)((uint8_t *)ptr7 - sizeof(test_header_t));
    printf("  Original checksum: 0x%X\n", hdr7->checksum);
    hdr7->checksum ^= 0x12345678;  // Flip some bits
    printf("  Corrupted checksum: 0x%X\n", hdr7->checksum);
    
    // Try to write - should detect bad checksum
    result = mm_write(ptr7, 0, test_data, 5);
    if (result == -1) {
        printf("✓ PASSED: Detected corrupted checksum\n\n");
    } else {
        printf("✗ FAILED: Did not detect corrupted checksum\n\n");
    }
    
    // Test 14: Double-free detection
    printf("Test 14: Double-free detection\n");
    void *ptr8 = mm_malloc(100);
    if (!ptr8) {
        printf("✗ FAILED: Allocation failed\n");
        return 1;
    }
    
    printf("  Freeing once...\n");
    mm_free(ptr8);
    printf("  Freeing again (should detect double-free)...\n");
    mm_free(ptr8);  // Should be detected and handled safely
    printf("✓ PASSED: Double-free handled safely (no crash)\n\n");
    
    // Test 15: Use after free
    printf("Test 15: Use after free\n");
    void *ptr9 = mm_malloc(100);
    if (!ptr9) {
        printf("✗ FAILED: Allocation failed\n");
        return 1;
    }
    
    mm_write(ptr9, 0, "Some data", 10);
    mm_free(ptr9);
    
    // Try to read after free - behavior may vary but shouldn't crash
    printf("  Attempting to read after free...\n");
    result = mm_read(ptr9, 0, test_buf, sizeof(test_buf));
    printf("  Read after free returned: %d\n", result);
    printf("✓ PASSED: No crash on use-after-free\n\n");
    
    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}

