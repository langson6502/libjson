/*
 * A minimalism implement of JSON parser written in portable ANSI C.
 *
 * Repository - https://github.com/langson6502/libjson
 * References - https://www.json.org/
 *
 * Copyright © 2020 Langson Leung <langson.leung@gmail.com>
 *
 */

#ifndef __JSON_H__
#define __JSON_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum json_value_type {
    JSON_NULL,
    JSON_BOOL,
    JSON_STRING,
    JSON_INTEGER,
    JSON_DECIMAL,
    JSON_OBJECT,
    JSON_ARRAY,
} json_value_type_t;

extern const char *json_type_name[];

typedef struct json_node {
    struct json_node *parent;
    struct json_node *next;
    struct json_node *prev;
    json_value_type_t type;
    char *name;
    union {
        bool    boolean;
        char    *string;
        int64_t integer;
        double  decimal;
        struct json_node *child;
        struct json_node *array;
    } value;
} json_node_t;

typedef struct json_config_context {
    void* (*malloc)(size_t size);
    void  (*free)(void *ptr);
    void* (*realloc)(void *ptr, size_t size);
    int   (*sprintf)(char *buf, const char *fmt, ...);
    int   (*printf)(const char *fmt, ...);
    char* (*strndup)(const char* str, size_t size);
} json_config_context_t;
extern json_config_context_t *json_config_ctx;

json_node_t* json_parse(const char *text);
void json_free(json_node_t **root);

json_node_t* json_child(json_node_t *node, const char *name);
json_node_t* json_array_at(json_node_t *node, uint32_t i);
json_node_t* json_find_by_name(json_node_t *node, const char *name);

char* json_stringify(const json_node_t *root, bool b_pretty);
char* json_minify(const char *text);

#ifdef __cplusplus
}
#endif

#endif /* __JSON_H__ */
