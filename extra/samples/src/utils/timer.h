/*===-- timer.h ----------------------------------------*- SAMPLE -*- H -*-===*/
/**
*** @file
*** @brief Sample Utility
***
*** Provides an interface to a timer implementation (e.g. for benchmarking).
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

#endif
