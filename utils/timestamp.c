#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>

#include "timestamp.h"
#include "utils.h"
bool valid_time_tz(const char *time) {
	char *pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$";
	if(time == NULL)  {
		printf("invalid NULL param\n");
		return false;
	}
	return reg_match(pattern, time) == 0;
}

static int parsing_time_to_digit(const char *time, size_t *i)
{
    int sum = 0;

    while (time[*i] != '\0' && isdigit(time[*i])) {
        sum = sum * 10 + time[*i] - '0';
        (*i)++;
    }
    return sum;
}

static void parsing_time_data_year(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_year = parsing_time_to_digit(time, i);
}

static void parsing_time_data_month(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_mon = parsing_time_to_digit(time, i);
}

static void parsing_time_data_day(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_mday = parsing_time_to_digit(time, i);
}

static void parsing_time_data_hour(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_hour = parsing_time_to_digit(time, i);
}

static void parsing_time_data_min(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_min = parsing_time_to_digit(time, i);
}

static void parsing_time_data_sec(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_sec = parsing_time_to_digit(time, i);
}

static void parsing_time_data(const char *time, struct tm *tm)
{
    size_t i = 0;

    parsing_time_data_year(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_month(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_day(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_hour(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_min(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_sec(tm, time, &i);
}

bool parsing_time(const char *format, const char *time, struct tm *tm, int32_t *nanos)
{
    size_t len_format = 0; 
    size_t len_time = 0; 
    size_t index_nanos = 0; 

    if (format == NULL || time == NULL) {
        return false;
    }    

    if (strcmp(format, rFC339NanoLocal) == 0) { 
        index_nanos = strlen(rFC339Local) + 1; 
    }    
    len_format = strlen(format);
    len_time = strlen(time);

    if (index_nanos) {
        if (len_format < len_time || index_nanos >= len_time) {
            return false;
        }
    } else {
        if (len_format != len_time) {
            return false;
        }
    }    

    if (index_nanos) {
        *nanos = 0; 
        while (time[index_nanos] != '\0') {
            *nanos = *nanos * 10 + time[index_nanos] - '0'; 
            index_nanos++;
        }
        while (index_nanos < len_format) {
            *nanos *= 10;
            index_nanos++;
        }
    } else {
        *nanos = 0; 
    }    

    parsing_time_data(time, tm); 

    return true;
}

static bool is_out_of_range(int value, int lower, int upper)
{
    return (value > upper) || (value < lower);
}

static bool is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int get_valid_days(int mon, int year)
{
    int leap_year = 0;
    int valid_days = 31;

    if (is_leap_year(year)) {
        leap_year = 1;
    }

    switch (mon) {
        case 2:
            valid_days = (valid_days - 3) + leap_year;
            break;
        case 4:
        case 6:
        case 9:
        case 11:
            valid_days = 30;
            break;
        default:
            break;
    }

    return valid_days;
}

bool fix_date(struct tm *tm)
{
    if (tm == NULL) {
        return false;
    }

    // Max year 2100 is enough, do not be 9999, it can overflow when translate it to nanos
    bool ret = (is_out_of_range(tm->tm_hour, 0, 23)) || (is_out_of_range(tm->tm_min, 0, 59)) ||
               (is_out_of_range(tm->tm_sec, 0, 59)) || (is_out_of_range(tm->tm_mon, 1, 12)) ||
               (is_out_of_range(tm->tm_year, 1900, 2100));

    if (ret) {
        printf("Normal section out of range\n");
        return false;
    }

    int valid_day = get_valid_days(tm->tm_mon, tm->tm_year);
    ret = ret || is_out_of_range(tm->tm_mday, 1, valid_day);
    if (ret) {
        printf("Day out of range\n");
        return false;
    }
    tm->tm_year -= 1900;
    tm->tm_mon -= 1;
    return true;
}

bool get_tm_from_str(const char *str, struct tm *tm, int32_t *nanos)
{
    char *format = NULL;

    if (str == NULL || tm == NULL || nanos == NULL) {
        return false;
    }

    if (strings_contains_any(str, ".")) {
        format = rFC339NanoLocal;
    } else if (strings_contains_any(str, "T")) {
        int tcolons = strings_count(str, ':');
        switch (tcolons) {
            case 0:
                format = "2016-01-02T15";
                break;
            case 1:
                format = "2016-01-02T15:04";
                break;
            case 2:
                format = rFC339Local;
                break;
            default:
                printf("date format error\n");
                return false;
        }
    } else {
        format = dateLocal;
    }

    if (!parsing_time(format, str, tm, nanos)) {
        printf("Failed to parse time \"%s\" with format \"%s\"\n", str, format);
        return false;
    }

    if (!fix_date(tm)) {
        printf("\"%s\" is invalid\n", str);
        return false;
    }

    return true;
}

static int time_tz_to_seconds_nanos(const char *time_tz, int64_t *seconds, int32_t *nanos)
{
    int nret = 0; 
    struct tm t = { 0 }; 
    int32_t nano = 0; 
    char *time_str = NULL;

    if (seconds != NULL) {
        *seconds = 0; 
    }    
    if (nanos != NULL) {
        *nanos = 0; 
    }    
    if (time_tz == NULL) {
        return 0;
    }    

    /* translate to rfc339NanoLocal */
    time_str = strdup_s(time_tz);
    time_str[strlen(time_str) - 1] = '\0'; /* strip last 'Z' */

    if (!get_tm_from_str(time_str, &t, &nano)) {
        printf("get tm from string %s failed\n", time_str);
        nret = -1;
        goto err_out;
    }    

    if (seconds != NULL) {
        *seconds = timegm(&t);
    }    

    if (nanos != NULL) {
        *nanos = nano;
    }    

err_out:
    free(time_str);
    return nret;
}

static char *tm_get_zp(const char *tmstr)
{
    char *zp = NULL;

    zp = strrchr(tmstr, '+');
    if (zp == NULL) {
        zp = strrchr(tmstr, '-');
    }
    return zp;
}

static inline bool hasnil(const char *str, const struct tm *tm, const int32_t *nanos, const struct types_timezone *tz)
{
    if (str == NULL || tm == NULL || nanos == NULL || tz == NULL) {
        return true;
    }
    return false;
}

static size_t tz_init_hour(struct types_timezone *tz, const char *zonestr, size_t i)
{
    int positive = 1;
    int sum = 0;

    if (zonestr[0] == '-') {
        positive = -1;
    }

    sum = parsing_time_to_digit(zonestr, &i);
    tz->hour = positive * sum;
    return i;
}

static size_t tz_init_min(struct types_timezone *tz, const char *zonestr, size_t i)
{
    int positive = 1;
    int sum = 0;

    if (zonestr[0] == '-') {
        positive = -1;
    }

    sum = parsing_time_to_digit(zonestr, &i);
    tz->min = positive * sum;
    return i;
}

static bool tz_init_ok(struct types_timezone *tz, const char *zonestr)
{
    size_t i = 0;

    i = tz_init_hour(tz, zonestr, 1);
    if (zonestr[i] == '\0') {
        return false;
    }
    tz_init_min(tz, zonestr, i + 1);
    return true;
}

static bool get_tm_zone_from_str(const char *str, struct tm *tm, int32_t *nanos, struct types_timezone *tz)
{
    char *tmstr = NULL;
    char *zp = NULL;
    char *zonestr = NULL;
    bool ret = false;

    if (hasnil(str, tm, nanos, tz)) {
       	printf("Get tm and timezone from str input error\n");
        return false;
    }

    tmstr = strdup_s(str);
    zp = tm_get_zp(tmstr);
    if (zp == NULL) {
        printf("No time zone symbol found in input string\n");
        goto err_out;
    }
    zonestr = strdup_s(zp);
    *zp = '\0';

    if (!get_tm_from_str(tmstr, tm, nanos)) {
        printf("Get tm from str failed\n");
        goto err_out;
    }

    if (!tz_init_ok(tz, zonestr)) {
        printf("init tz failed\n");
        goto err_out;
    }
    ret = true;

err_out:
    free(tmstr);
    free(zonestr);
    return ret;
}

int str_to_nanos(const char *str, int64_t *nanos)
{
    struct tm tm = { 0 };
    struct types_timezone tz;
    int32_t nano = 0;
    types_timestamp_t ts;
    const int s_hour = 3600;
    const int s_minute = 60;

    if (nanos == NULL) {
        return -1;
    }

    *nanos = 0;
    if (str == NULL || !strcmp(str, "") || !strcmp(str, defaultContainerTime)) {
        return 0;
    }

    if (!valid_time_tz(str)) {
        printf("invalid time %s\n", str);
        return -1;
    }

    if (str[strlen(str) - 1] == 'Z') {
        int ret = time_tz_to_seconds_nanos(str, &ts.seconds, &ts.nanos);
        if (ret != 0) {
            printf("Invalid time stamp: %s\n", str);
            return -1;
        }
        *nanos = ts.seconds * Time_Second + ts.nanos;
        return 0;
    }

    if (!get_tm_zone_from_str(str, &tm, &nano, &tz)) {
        printf("Transform str to timestamp failed\n");
        return -1;
    }

    *nanos = (timegm(&tm) - (int64_t)tz.hour * s_hour - (int64_t)tz.min * s_minute) * Time_Second + nano;
    return 0;
}

types_timestamp_t str_to_timestamp(const char *str)
{
    int64_t nanos = 0;
    types_timestamp_t timestamp = { 0 };

    if (str_to_nanos(str, &nanos) != 0) {
        printf("Failed to get created time from image config\n");
        goto out;
    }

    timestamp.has_seconds = true;
    timestamp.seconds = nanos / Time_Second;
    timestamp.has_nanos = true;
    timestamp.nanos = nanos % Time_Second;

out:
    return timestamp;
}

bool get_time_buffer(const types_timestamp_t *timestamp, char *timebuffer, size_t maxsize, bool local_utc)
{
    int nret = 0;
    int tm_zone_hour = 0;
    int tm_zone_min = 0;
    int32_t nanos;
    struct tm tm_local = { 0 };
    size_t tmp_size = 0;
    time_t seconds;
    bool west_timezone = false;
    long int tm_gmtoff = 0;
    const int seconds_per_minutes = 60;
    const int seconds_per_hour = 3600;

    if (timebuffer == NULL || maxsize == 0 || !timestamp->has_seconds) {
        return false;
    }

    seconds = (time_t)timestamp->seconds;
    localtime_r(&seconds, &tm_local);
    strftime(timebuffer, maxsize, "%Y-%m-%dT%H:%M:%S", &tm_local);

    if (timestamp->has_nanos) {
        nanos = timestamp->nanos;
    } else {
        nanos = 0;
    }

    tmp_size = maxsize - strlen(timebuffer);

    if (local_utc) {
        nret = snprintf(timebuffer + strlen(timebuffer), tmp_size, ".%09dZ", nanos);
        goto out;
    }

#ifdef __USE_MISC
    tm_gmtoff = tm_local.tm_gmtoff;
#else
    tm_gmtoff = tm_local.__tm_gmtoff;
#endif

    if (tm_gmtoff < 0) {
        west_timezone = true;
        tm_gmtoff = -tm_gmtoff;
    }

    tm_zone_hour = tm_gmtoff / seconds_per_hour;
	tm_zone_min = (tm_gmtoff - tm_zone_hour * seconds_per_hour) / seconds_per_minutes;

    if (!west_timezone) {
        nret = snprintf(timebuffer + strlen(timebuffer), tmp_size, ".%09d+%02d:%02d", nanos, tm_zone_hour, tm_zone_min);
    } else {
        nret = snprintf(timebuffer + strlen(timebuffer), tmp_size, ".%09d-%02d:%02d", nanos, tm_zone_hour, tm_zone_min);
    }

out:
    if (nret < 0 || (size_t)nret >= tmp_size) {
        printf("sprintf timebuffer failed\n");
        return false;
    }

    return true;
}

bool get_now_time_stamp(types_timestamp_t *timestamp)
{
    int err = 0; 
    struct timespec ts;

    if (timestamp == NULL) {
        printf("Invalid arguments\n");
        return false;
    }    

    err = clock_gettime(CLOCK_REALTIME, &ts);
    if (err != 0) { 
        printf("failed to get time\n");
        return false;
    }    
    timestamp->has_seconds = true;
    timestamp->seconds = (int64_t)ts.tv_sec;
    timestamp->has_nanos = true;
    timestamp->nanos = (int32_t)ts.tv_nsec;
    return true;
}

bool get_now_time_buffer(char *timebuffer, size_t maxsize) {
	types_timestamp_t timestamp;
	
	if(get_now_time_stamp(&timestamp) == false) {
		return false;
	}

	return get_time_buffer(&timestamp, timebuffer, maxsize, false);
}

bool get_now_local_utc_time_buffer(char *timebuffer, size_t maxsize) {
	types_timestamp_t timestamp;
	
	if(get_now_time_stamp(&timestamp) == false) {
		return false;
	}

	return get_time_buffer(&timestamp, timebuffer, maxsize, true);
}

