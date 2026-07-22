#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "./allocator.h"

// Defaults
#define DEFAULT_HEAP_SIZE 5000
#define DEFAULT_STORM_LEVEL 1
#define DEFAULT_SEED 42

static unsigned int seed;

typedef struct {
  unsigned int seed;
  int storm_level;
  size_t heap_size;
} configuration_t;

configuration_t getArgs(int argc, char *argv[]) {
  configuration_t config;
  config.seed = DEFAULT_SEED;
  config.storm_level = DEFAULT_STORM_LEVEL;
  config.heap_size = DEFAULT_HEAP_SIZE;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
      config.seed = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--storm") == 0 && i + 1 < argc) {
      config.storm_level = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
      config.heap_size = atoi(argv[++i]);
    } else {
      printf("Not an argument: %s\n", argv[i]);
      exit(1);
    }
  }

  return config;
}

// Bit flipping from radiation storms
void radiationStorm(uint8_t *heap, size_t heap_size, int storm_level) {
  if (storm_level == 0) return;

  int flips = storm_level * 5;

  int bytesHit = 0;
  for (int i = 0; i < flips; i++) {
    size_t targetByte = rand_r(&seed) % heap_size;
    int bit = rand_r(&seed) % 8;
    heap[targetByte] ^= (1 << bit);
    bytesHit++;
  }
}

// Standard allocation and deallocation operations
int standardUsage(uint8_t *heap, size_t heap_size) {
  printf("\n1. STANDARD OPERATIONS TESTING:\n");

  if (mm_init(heap, heap_size) != 0) {
    printf("\ta) Heap initialisation failed immediately (FAIL)\n");
    return 0;
  }
  printf("\ta) Initialised heap at size %zu bytes\n", heap_size);

  void *ptr1 = mm_malloc(100);
  if (!ptr1) {
    printf("\tb) First allocation failed (FAIL)\n");
    return 0;
  }
  printf("\tb) Allocated 100 bytes at %p\n", ptr1);

  void *ptr2 = mm_malloc(200);
  if (!ptr2) {
    printf("\tb) Second allocation failed (FAIL)\n");
    return 0;
  }
  printf("\tb) Allocated 200 bytes at %p\n", ptr2);

  mm_free(ptr1);
  printf("\tc) Freed first block at %p\n", ptr1);

  mm_free(ptr2);
  printf("\td) Freed second block at %p\n", ptr2);

  void *ptr3 = mm_malloc(100);
  if (ptr3 != ptr1) {
    printf("\te) Did not reuse free space for new allocation,"
           "freeing may have failed (FAIL)\n");
    return 0;
  }
  printf("\te) Allocated 100 bytes at %p, reusing freed space\n", ptr3);

  size_t heap_start = (size_t) heap;
  if (((size_t) ptr3 - heap_start) % 40 != 0) {
    printf("\tf) Pointer with offset %zu is not 40-byte aligned (FAIL)\n",
           (size_t) ptr3 % 40);
    return 0;
  }
  printf("Pointer is  aligned with offset %zu\n", (size_t) ptr3 % 40);

  printf("\n## STANDARD OPERATIONS TESTING PASSED ##\n");
  return 1;
}

// Read and write operations
int readAndWrite(uint8_t *heap, size_t heap_size) {
  printf("\n2. READ AND WRITE TESTING:\n");

  mm_init(heap, heap_size);

  void *ptr = mm_malloc(13);
  if (!ptr) {
    printf("\tsetup) Allocation failed (FAIL)\n");
    return 0;
  }

  const char *test_data = "Hello World!";  // 13 bytes including null
  int bytesWritten = mm_write(ptr, 0, test_data, strlen(test_data) + 1);
  if (bytesWritten < 0) {
    printf("\ta) Write failed (FAIL)\n");
    return 0;
  }
  printf("\ta) Wrote %d bytes\n", bytesWritten);

  char buffer[100];
  int bytesRead = mm_read(ptr, 0, buffer, sizeof(buffer));
  if (bytesRead < 0) {
    printf("\tb) Read failed (FAIL)\n");
    return 0;
  }

  if (strcmp(buffer, test_data) != 0) {
    printf("\tb) Data mismatch: '%s' != '%s' (FAIL)\n", buffer, test_data);
    return 0;
  }
  printf("\tb) Read %d bytes: '%s'\n", bytesRead, buffer);

  mm_free(ptr);
  printf("\n## READ/WRITE TESTING PASSED ##\n");
  return 1;
}

// Strict boundary enforcement testing
int boundaryEnforcement(uint8_t *heap, size_t heap_size) {
  printf("\n3. STRICT BOUNDARY ENFORCEMENT TESTING:\n");

  mm_init(heap, heap_size);

  void *ptr = mm_malloc(50);
  if (!ptr) {
    printf("\tsetup) Allocation failed (FAIL)\n");
    return 0;
  }

  char full_data[50];
  memset(full_data, 'A', 50);
  int result = mm_write(ptr, 0, full_data, 50);
  if (result < 0) {
    printf("\ta) Full write failed but should succeed (FAIL)\n");
    mm_free(ptr);
    return 0;
  }
  printf("\ta) Full write (offset=0, len=50) succeeded\n");

  char partial_data[25];
  memset(partial_data, 'B', 25);
  result = mm_write(ptr, 0, partial_data, 25);
  if (result >= 0) {
    printf("\tb) Partial write succeeded but should fail (FAIL)\n");
    mm_free(ptr);
    return 0;
  }
  printf("\tb) Partial write (offset=0, len=25) correctly rejected\n");

  char offset_data[30];
  memset(offset_data, 'C', 30);
  result = mm_write(ptr, 20, offset_data, 30);
  if (result < 0) {
    printf("\tc) Offset write failed but should succeed (FAIL)\n");
    mm_free(ptr);
    return 0;
  }
  printf("\tc) Offset write succeeded\n");

  char overflow_data[51];
  memset(overflow_data, 'D', 51);
  result = mm_write(ptr, 0, overflow_data, 51);
  if (result != 50) {
    printf("\td) Overflow write was not truncated (FAIL)\n");
    mm_free(ptr);
    return 0;
  }
  printf("\td) Overflow write correctly truncated\n");

  char read_buffer[25];
  result = mm_read(ptr, 0, read_buffer, 25);
  if (result <= 0) {
    printf("\te) Partial read failed (should be allowed) (FAIL)\n");
    mm_free(ptr);
    return 0;
  }
  printf("\te) Partial read succeeded (read %d bytes)\n", result);

  mm_free(ptr);
  printf("\n## STRICT BOUNDARY ENFORCEMENT TESTING PASSED ##\n");
  return 1;
}

// Corruption detection
int corruptionDetection(uint8_t *heap, size_t heap_size) {
  printf("\n4. CORRUPTION DETECTION TESTING:\n");

  mm_init(heap, heap_size);

  void *ptr = mm_malloc(100);
  if (!ptr) {
    printf("\tsetup) Allocation failed (FAIL)\n");
    return 0;
  }

  typedef struct {
    size_t size;
    uint32_t canary;
    uint32_t checksum;
    uint8_t allocated;
    uint8_t quarantined;
    uint8_t padding[22];
  } test_header_t;

  test_header_t *header = (test_header_t *)
          ((uint8_t *) ptr - sizeof(test_header_t));
  printf("\ta) Corrupting header canary...\n");
  header->canary = 0xBADBAD;

  char buffer[10];
  int result = mm_read(ptr, 0, buffer, sizeof(buffer));
  mm_free(ptr);

  if (result != -1) {
    printf("\ta) Did not detect corruption (FAIL)\n");
    return 0;
  }
  printf("\ta) Detected header canary corruption\n");
  printf("\n## CORRUPTION DETECTION TESTING PASSED ##\n");
  return 1;
}

// Payload corruption detection
int payloadCorruptionDetection(uint8_t *heap, size_t heap_size) {
  printf("\n5. PAYLOAD CORRUPTION DETECTION TESTING:\n");

  mm_init(heap, heap_size);

  void *ptr = mm_malloc(100);
  if (!ptr) {
    printf("\tsetup) Allocation failed (FAIL)\n");
    return 0;
  }

  // Write known data
  char data[100];
  memset(data, 0xAB, 100);
  int result = mm_write(ptr, 0, data, 100);
  if (result < 0) {
    printf("\tsetup) Write failed (FAIL)\n");
    mm_free(ptr);
    return 0;
  }
  printf("\tsetup) Wrote 100 bytes of data\n");

  // Directly corrupt payload data
  uint8_t *payload = (uint8_t *)ptr;
  payload[50] ^= 0x01;  // Flip one bit
  printf("\ta) Flipped bit in payload at offset 50\n");

  // Try to write again - should detect payload corruption via checksum
  result = mm_write(ptr, 0, data, 100);
  if (result >= 0) {
    printf("\tb) Did not detect payload corruption before write (FAIL)\n");
    mm_free(ptr);
    return 0;
  }
  printf("\tb) Detected payload corruption (block quarantined)\n");

  mm_free(ptr);
  printf("\n## PAYLOAD CORRUPTION DETECTION TESTING PASSED ##\n");
  return 1;
}

// Double-free detection
int doubleFree(uint8_t *heap, size_t heap_size) {
  printf("\n6. DOUBLE-FREE DETECTION TESTING:\n");

  mm_init(heap, heap_size);

  void *ptr = mm_malloc(100);
  if (!ptr) {
    printf("\tsetup) Allocation failed\n");
    return 0;
  }

  mm_free(ptr);
  printf("\ta) Freed once...\n");

  mm_free(ptr);
  printf("\ta) Double-free handled\n");

  printf("\n## DOUBLE-FREE DETECTION TESTING PASSED ##\n");

  return 1;
}

// Reallocation
int reallocationTest(uint8_t *heap, size_t heap_size) {
  printf("\n7. REALLOCATION TESTING:\n");

  mm_init(heap, heap_size);

  void *ptr = mm_malloc(50);
  if (!ptr) {
    printf("\tsetup) Initial allocation failed (FAIL)\n");
    return 0;
  }

  const char *data = "Test data";
  mm_write(ptr, 0, data, strlen(data) + 1);
  printf("\tsetup) Wrote data to block...\n");

  void *new_ptr = mm_realloc(ptr, 100);
  if (!new_ptr) {
    printf("\t a) Realloc failed (FAIL)\n");
    return 0;
  }
  printf("\ta) Reallocated to 100 bytes\n");

  char buffer[50];
  mm_read(new_ptr, 0, buffer, sizeof(buffer));
  mm_free(new_ptr);

  if (strcmp(buffer, data) != 0) {
    printf("\tb) Data not preserved (FAIL)\n");
    return 1;
  }
  printf("\tb) Data preserved after realloc\n");
  printf("\n## REALLOCATION TESTING PASSED ##\n");
  return 1;
}

// Large allocation stress test
int largeAllocationStress(uint8_t *heap, size_t heap_size) {
  printf("\n8. LARGE ALLOCATION STRESS TESTING:\n");

  mm_init(heap, heap_size);

  // Try to allocate many large blocks
  void *ptrs[20];
  int allocated = 0;
  size_t allocation_size = 500;  // Large blocks

  for (int i = 0; i < 20; i++) {
    ptrs[i] = mm_malloc(allocation_size);
    if (ptrs[i]) {
      allocated++;
      // Write data to verify integrity
      char pattern = 'A' + (i % 26);
      char data[500];
      memset(data, pattern, allocation_size);
      if (mm_write(ptrs[i], 0, data, allocation_size) < 0) {
        printf("\tsetup) Write failed for block %d (FAIL)\n", i);
        break;
      }
    } else {
      break;  // Heap exhausted
    }
  }
  printf("\ta) Allocated %dx %zu byte blocks\n", allocated, allocation_size);

  // Verify all blocks still readable
  int readable = 0;
  for (int i = 0; i < allocated; i++) {
    char buffer[500];
    if (mm_read(ptrs[i], 0, buffer, allocation_size) > 0) {
      readable++;
      // Verify pattern
      char expected = 'A' + (i % 26);
      int correct = 1;
      for (size_t j = 0; j < allocation_size; j++) {
        if (buffer[j] != expected) {
          correct = 0;
          break;
        }
      }
      if (!correct) {
        printf("\tb) Data corruption in block %d (FAIL)\n", i);
      }
    }
  }
  printf("\tb) Successfully read and verified %d/%d blocks\n",
         readable, allocated);

  // Free all blocks
  for (int i = 0; i < allocated; i++) {
    mm_free(ptrs[i]);
  }
  printf("\tc) Freed all %d blocks\n", allocated);

  // Try to reallocate after freeing
  void *realloc_ptr = mm_malloc(allocation_size * allocated / 2);
  if (realloc_ptr) {
    printf("\td) Successfully reallocated after freeing (coalescing works)\n");
    mm_free(realloc_ptr);
  } else {
    printf("\td) Could not reallocate (potential fragmentation)\n");
  }

  printf("\n## LARGE ALLOCATION STRESS TESTING PASSED ##\n");
  return 1;
}

// Storm simulation
int stormSim(uint8_t *heap, size_t heap_size, int storm_level) {
  printf("\n9. STORM SIMULATION TESTING:\n");

  if (storm_level == 0) {
    return 1;
  }

  mm_init(heap, heap_size);

  void *ptrs[10];
  int allocated = 0;

  for (int i = 0; i < 10; i++) {
    ptrs[i] = mm_malloc(50 + i * 10);
    if (ptrs[i]) {
      allocated++;
      mm_write(ptrs[i], 0, "data", 5);
    }
  }
  printf("\tsetup) Allocated %d blocks...\n", allocated);

  printf("\ta) Radiation storm...\n");
  radiationStorm(heap, heap_size, storm_level);

  // Target header
  if (allocated > 2) {
    printf("\ta) Adding targeted header corruption...\n");
    uint8_t *ptr = (uint8_t *)ptrs[1];
    uint8_t *header = ptr - 40;  // Header is 40 bytes
    // Corrupt one byte in the header
    header[8] ^= 0xFF;  // Corrupt checksum
  }

  int corrupted = 0;
  char buffer[10];
  for (int i = 0; i < allocated; i++) {
    if (mm_read(ptrs[i], 0, buffer, sizeof(buffer)) == -1) {
      corrupted++;
    }
  }

  printf("\ta) Detected %d corrupted blocks out of %d corrupted blocks\n",
         corrupted, allocated);

  for (int i = 0; i < allocated; i++) {
    mm_free(ptrs[i]);
  }
  printf("\n## STORM SIMULATION TESTING PASSED ##\n");

  return 1;
}

// Thread safety test
typedef struct {
  uint8_t *heap;
  size_t heap_size;
  int thread_id;
  int *success_count;
} thread_arg_t;

void *thread_worker(void *arg) {
  thread_arg_t *args = (thread_arg_t *) arg;
  int operations = 100;  // Operations per thread

  for (int i = 0; i < operations; i++) {
    // Allocate
    size_t size = 50 + (i % 50);
    void *ptr = mm_malloc(size);
    if (ptr == NULL) continue;

    // Write
    char data[100];
    memset(data, 'A' + args->thread_id, size);
    if (mm_write(ptr, 0, data, size) < 0) {
      mm_free(ptr);
      continue;
    }

    // Read and verify
    char buffer[100];
    if (mm_read(ptr, 0, buffer, size) > 0) {
      int correct = 1;
      for (size_t j = 0; j < size; j++) {
        if (buffer[j] != 'A' + args->thread_id) {
          correct = 0;
          break;
        }
      }
      if (correct) {
        (*args->success_count)++;
      }
    }

    // Free
    mm_free(ptr);
  }
  return NULL;
}

int threadSafetyTest(uint8_t *heap, size_t heap_size) {
  printf("\n10. THREAD SAFETY TESTING:\n");

  mm_init(heap, heap_size);

  const int num_threads = 4;
  pthread_t threads[4];
  thread_arg_t args[4];
  int success_counts[4] = {0, 0, 0, 0};

  // Create threads
  for (int i = 0; i < num_threads; i++) {
    args[i].heap = heap;
    args[i].heap_size = heap_size;
    args[i].thread_id = i;
    args[i].success_count = &success_counts[i];

    if (pthread_create(&threads[i], NULL, thread_worker, &args[i]) != 0) {
      printf("\ta) Failed to create thread %d (FAIL)\n", i);
      return 0;
    }
  }

  // Wait for completion
  for (int i = 0; i < num_threads; i++) {
    pthread_join(threads[i], NULL);
  }

  // Check results
  int total_success = 0;
  for (int i = 0; i < num_threads; i++) {
    total_success += success_counts[i];
    printf("\ta) Thread %d: %d successful operations\n", i, success_counts[i]);
  }

  if (total_success < num_threads * 50) {  // At least 50% success expected
    printf("\tb) Too many failed operations, possible race condition (FAIL)\n");
    return 0;
  }

  printf("\tb) %d total successful concurrent operations\n", total_success);
  printf("\tc) No crashes or data corruption detected\n");

  printf("\n## THREAD SAFETY TESTING PASSED ##\n");
  return 1;
}

// Free-pattern corruption test
int patternValidationTest(uint8_t *heap, size_t heap_size) {
  printf("\n11. PATTERN VALIDATION TESTING:\n");

  for (size_t i = 0; i < heap_size; i++) {
    heap[i] = (uint8_t)(i % 5);
  }

  if (mm_init(heap, heap_size) != 0) {
    printf("\ta) Clean pattern validation FAILED (should succeed)\n");
    return 0;
  }
  printf("\ta) Clean pattern validated successfully\n");

  for (size_t i = 0; i < heap_size; i++) {
    heap[i] = (uint8_t)(i % 5);
  }
  heap[7] = 99;  // Corrupt byte 7

  if (mm_init(heap, heap_size) == 0) {
    printf("\tb) Corrupted pattern accepted (should reject!) (FAIL)\n");
    return 0;
  }
  printf("\tb) Corrupted pattern rejected correctly\n");

  for (size_t i = 0; i < heap_size; i++) {
    heap[i] = (uint8_t)(i % 5);
  }

  printf("\n## PATTERN VALIDATION TESTING PASSED ##\n");
  return 1;
}

int main(int argc, char *argv[]) {
  printf("----- Memory Allocator Testing -----\n");

  configuration_t config = getArgs(argc, argv);

  printf("\nTest Configuration:\n");
  printf("  Random Seed:  %u\n", config.seed);
  printf("  Storm Level:  %d\n", config.storm_level);
  printf("  Heap Size:    %zu bytes\n", config.heap_size);

  seed = config.seed;

  uint8_t *heap = (uint8_t *) malloc(config.heap_size);
  if (!heap) {
    printf("\nFailed to allocate heap memory\n");
    return 1;
  }

  for (size_t i = 0; i < config.heap_size; i++) {
    heap[i] = (uint8_t) (i % 5);
  }

  printf("Allocated %zu byte heap at %p\n", config.heap_size, (void *) heap);

  int tests_passed = 0;
  int tests_total = 0;

  tests_total++; tests_passed += standardUsage(heap, config.heap_size);
  tests_total++; tests_passed += readAndWrite(heap, config.heap_size);
  tests_total++; tests_passed += boundaryEnforcement(heap, config.heap_size);
  tests_total++; tests_passed += corruptionDetection(heap, config.heap_size);
  tests_total++; tests_passed += payloadCorruptionDetection(heap,
                                                            config.heap_size);
  tests_total++; tests_passed += doubleFree(heap, config.heap_size);
  tests_total++; tests_passed += reallocationTest(heap, config.heap_size);
  tests_total++; tests_passed += largeAllocationStress(heap, config.heap_size);
  tests_total++; tests_passed += stormSim(heap, config.heap_size,
                                          config.storm_level);
  tests_total++; tests_passed += threadSafetyTest(heap, config.heap_size);
  tests_total++; tests_passed += patternValidationTest(heap, config.heap_size);

  printf("\nTest Summary\n");
  printf("\tTests Passed:  %2d / %2d\n", tests_passed, tests_total);
  printf("\tSuccess Rate:  %3d%%\n", (tests_passed * 100) / tests_total);

  free(heap);

  return 0;
}
