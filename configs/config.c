#include "config.h"
#include "log.h"

configs_constants *g_configs_constants = NULL;

int init_constants() {
	parser_error err = NULL;
	int ret = 0;

	g_configs_constants = configs_constants_parse_file(CONSTANTS_JSON_CONF_FILE, NULL, &err);
	if(g_configs_constants == NULL) {
		LOG_ERROR("Load constants json config failed: %s\n", err);
		ret = -1;
		goto out;
	}

out:
	free(err);
	if(ret != 0) {
		free_configs_constants(g_configs_constants);
	}
	return ret;
}

configs_constants *get_constants() {
	if(g_configs_constants == NULL) {
		init_constants();
	}
	return g_configs_constants;
}


