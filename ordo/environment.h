#ifndef environment_h
#define environment_h

/* Decides whether the build target is a 32-bit or 64-bit platform. */
#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifndef ENVIRONMENT64
#ifndef ENVIRONMENT32
#error "Unknown platform."
#endif
#endif

#endif