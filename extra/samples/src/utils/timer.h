/*===-- timer.h ----------------------------------------*- SAMPLE -*- H -*-===*/
/**
*** @file
*** @brief Sample Utility
***
*** Provides an interface to a timer implementation (e.g. for benchmarking).
***
*** Note: requires librt if that library is available on the target system.
**/
/*===----------------------------------------------------------------------===*/

#ifndef SAMPLE_UTILS_TIMER_H
#define SAMPLE_UTILS_TIMER_H

/** Initializes the timer to be signaled after some period of time.
***
*** @param [in]     seconds        The time, in seconds, before elapsing.
***
*** @remarks There can be at most one timer active at any given time - calling
***          this function twice before \c timer_free() is not defined.
**/
void timer_init(double seconds);

/** Returns whether the timer has elapsed or not.
***
*** @returns Zero if it has not elapsed, 1 otherwise.
***
*** @remarks On systems with an interrupt/callback-based timer implementation,
***          this function call will have near zero overhead. If not, it might
***          have high overhead as it will have to rely on \c timer_now().
**/
int timer_has_elapsed(void);

/** Returns the current time relative to a fixed point in seconds.
***
*** @returns The current time (at least millisecond accuracy).
**/
double timer_now(void);

/** Frees the timer initialized with \c timer_init().
***
*** @remarks If the timer is not initialized, this is undefined.
**/
void timer_free(void);

/* The two macros below can be used to easily time a block of code - they work
 * as follows: pass an unsigned integral variable in the TIMER_START macro for
 * the counter parameter, a double variable in the elapsed parameter, and some
 * time duration (in seconds, as a double) in the duration parameters. For the
 * TIMER_STOP macro, simply pass the same variable you passed in elapsed. Then
 * put whatever block of code you want to benchmark in between TIMER_START and
 * TIMER_STOP (it will be placed in a new scope).
 *
 * After TIMER_STOP has finished, your elapsed variable will contain the exact
 * time in seconds spent in the loop (typically very near duration), while the
 * counter variable will contain the total iteration count of the code block.
 *
 * Note the counter variable should probably be of type uint64_t or similar as
 * a uint32_t can easily overflow, depending on the code block and duration.
*/


#define TIMER_START(elapsed, counter, duration)\
    counter = 0;\
    timer_init((duration));\
    elapsed = timer_now();\
    while (++counter && !timer_has_elapsed())\
    {\

#define TIMER_STOP(elapsed)\
    }\
    elapsed = timer_now() - elapsed;\
    timer_free();

#endif
