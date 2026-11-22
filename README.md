# CWE-401: Missing Release of Memory after Effective Lifetime

## What is the weakness?

[CWE-401](https://cwe.mitre.org/data/definitions/401.html) describes a memory leak: a program allocates memory, loses every reference to it, and never releases it. The memory stays reserved for the life of the process even though nothing can use it.

The phrase "after effective lifetime" means the memory is no longer needed by the program, but it is still allocated because the code never called `free()` (or the equivalent) on it. Leaks in short-lived programs may be harmless, but in long-running programs (servers, daemons, services) they grow over time and eventually exhaust memory.

## The vulnerable code

`programa.c`:

```c
#include <stdlib.h>
#include <stdio.h>

#define LOOPS 100
#define MAXSIZE 256

int main(int argc, char **argv) {
  int count = 0;
  char *pointer = NULL;

  for (count = 0; count < LOOPS; count++) {
    pointer = (char *)malloc(sizeof(char) * MAXSIZE);
  }

  free(pointer);
  return count;
}
```

### Why it leaks

Each loop iteration allocates 256 bytes and stores the address in `pointer`. This overwrites the previous address, so the earlier blocks become unreachable. Only the last allocation is freed after the loop.

| Iteration | Action                          | Status                              |
|-----------|---------------------------------|-------------------------------------|
| 1         | `pointer = malloc(256)` (block A) | A is referenced                   |
| 2         | `pointer = malloc(256)` (block B) | A is **lost** (leaked)            |
| ...       | ...                             | ...                                 |
| 100       | `pointer = malloc(256)` (block Z) | Y is **lost** (leaked)            |
| after     | `free(pointer)`                 | Only Z is released                  |

Result: **99 blocks leaked, 99 × 256 = 25,344 bytes** lost.

The program exits quickly, so the operating system reclaims the memory and the leak has no visible effect here. The same pattern inside a loop in a long-running program would be a real problem.

## The fix

Release each block before the pointer is overwritten by moving `free()` inside the loop:

```c
#include <stdlib.h>
#include <stdio.h>

#define LOOPS 100
#define MAXSIZE 256

int main(int argc, char **argv) {
  int count = 0;
  char *pointer = NULL;

  for (count = 0; count < LOOPS; count++) {
    pointer = (char *)malloc(sizeof(char) * MAXSIZE);
    free(pointer);
  }

  return count;
}
```

Each block is freed in the same iteration it was allocated, so no references are lost. The trailing `free(pointer)` is removed because `pointer` is already freed and must not be freed again (that would be a double free).

If the block is only needed within a single iteration, this is the correct lifetime. If you need the block to outlive the iteration, store the pointers (for example in an array) and free each one later.

## Verifying the leak and the fix

On Linux or macOS, [Valgrind](https://valgrind.org/) reports leaks:

```sh
gcc -g -o programa programa.c
valgrind --leak-check=full ./programa
```

The vulnerable version reports `25,344 bytes in 99 blocks` as definitely lost. The fixed version reports `All heap blocks were freed -- no leaks are possible`.

With GCC or Clang, AddressSanitizer's leak checker gives similar results:

```sh
gcc -g -fsanitize=address -o programa programa.c
./programa
```

## Related weaknesses

- [CWE-401](https://cwe.mitre.org/data/definitions/401.html): Missing Release of Memory after Effective Lifetime (this document)
- [CWE-415](https://cwe.mitre.org/data/definitions/415.html): Double Free (what can happen if `free()` is added after the loop in the fixed version)
- [CWE-416](https://cwe.mitre.org/data/definitions/416.html): Use After Free
