#ifndef __TIMESTAMP_H__
#define __TIMESTAMP_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

struct tm;

#ifdef __cplusplus
extern "C" {
#endif

#define Time_Nano 1LL
#define Time_Micro (1000LL * Time_Nano)
#define Time_Milli (1000LL * Time_Micro)
#define Time_Second (1000LL * Time_Milli)
#define Time_Minute (60LL * Time_Second)
#define Time_Hour (60LL * Time_Minute)

#define TIME_STR_SIZE 512

#define rFC339Local "2006-01-02T15:04:05"
#define rFC339NanoLocal "2006-01-02T15:04:05.999999999"
#define dateLocal "2006-01-02"
#define defaultContainerTime "0001-01-01T00:00:00Z"

typedef struct types_timestamp {
    bool has_seconds;
    int64_t seconds;
    bool has_nanos;
    int32_t nanos;
} types_timestamp_t;

struct types_timezone {
    int hour;
    int min;
};

bool valid_time_tz(const char *time);
types_timestamp_t str_to_timestamp(const char *str);
int str_to_nanos(const char *str, int64_t *nanos);
bool get_tm_from_str(const char *str, struct tm *tm, int32_t *nanos);
bool parsing_time(const char *format, const char *time, struct tm *tm, int32_t *nanos);
bool fix_date(struct tm *tm);
int get_valid_days(int mon, int year);
bool get_time_buffer(const types_timestamp_t *timestamp, char *timebuffer, size_t maxsize, bool local_utc);
bool get_now_time_stamp(types_timestamp_t *timestamp);
bool get_now_time_buffer(char *timebuffer, size_t maxsize);
bool get_now_local_utc_time_buffer(char *timebuffer, size_t maxsize);
#ifdef __cplusplus
}
#endif

#endif
