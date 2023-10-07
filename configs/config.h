#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "configs_constants.h"
#define CONSTANTS_JSON_CONF_FILE "/etc/docker-mini/configs/constants.json"

int init_constants();

configs_constants *get_constants();
