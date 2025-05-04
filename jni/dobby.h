#ifndef DOBBY_H_
#define DOBBY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define DOBBY_API __attribute__((visibility("default")))

#if defined(__arm64__) || defined(__aarch64__)
#define DobbyBuildPlatform DOBBY_BUILD_PLATFORM_aarch64

#elif defined(__arm__)
#define DobbyBuildPlatform DOBBY_BUILD_PLATFORM_armv7

#elif defined(__x86_64__)
#define DobbyBuildPlatform DOBBY_BUILD_PLATFORM_x64

#elif defined(__i386__)
#define DobbyBuildPlatform DOBBY_BUILD_PLATFORM_x86

#else
#error "Unsupported Architecture"

#endif

typedef enum { DYLT_ARM, DYLT_ARM64, DYLT_X64, DYLT_X86 } DobbyRegisterType;

/**
 * Intercept a function by replacing entry entry.
 *
 * @param address the address(absolute) or symbol of function you want to intercept
 * @param replace_func the hook function, will be called when thiz_func is invoking
 * @param origin_func a var to get the origin function address for backup
 * @return bool success or not
 */
DOBBY_API bool DobbyHook(void *address, void *replace_func, void **origin_func);

/**
 * Restore hook function back to original implement.
 *
 * @param address the address(absolute) where you want to restore
 * @return bool success or not
 */
DOBBY_API bool DobbyDestroy(void *address);

#ifdef __cplusplus
}
#endif

#endif
