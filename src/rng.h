#pragma once
#include <cstddef>

// The only source of randomness in the program: the kernel CSPRNG via getrandom().
// Aborts on failure; there is deliberately no fallback.
void os_random(void* buf, size_t len);

// Overwrite memory holding secrets in a way the compiler will not elide.
void secure_zero(void* buf, size_t len);
