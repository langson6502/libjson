/*
 * A minimalism implement of JSON parser written in portable ANSI C.
 *
 * Repository - https://github.com/langson6502/libjson/
 * References - https://www.json.org/
 *
 * Copyright © 2020 Langson Leung <langson.leung@gmail.com>
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

static json_config_context_t __json_config_ctx = {
        .malloc  = malloc,
        .free    = free,
        .realloc = realloc,
        .sprintf = sprintf,
        .printf  = printf,
        .strndup = strndup,
};
json_config_context_t *json_config_ctx = &__json_config_ctx;

const char *json_type_name[] = {
        "JSON_NULL",
        "JSON_BOOL",
        "JSON_STRING",
        "JSON_INTEGER",
        "JSON_DECIMAL",
        "JSON_OBJECT",
        "JSON_ARRAY",
};

static inline void __json_error(char ch, char *ptr) {
    char snippet[9];
    int i = 0;
    while ((ptr[i] != '\0') && (i < 8)) {
        snippet[i] = ptr[i];
        ++i;
    }
    snippet[i] = '\0';

    json_config_ctx->printf("found unexpected char '%c'(0x%02x) at `%s`.\n",
            ch, ch, snippet);
}

#define JSON_ERROR(ch, ptr)      \
    do {                         \
        __json_error(ch, ptr);   \
        return NULL;             \
    } while (0)
/* End of JSON_ERROR */

#define JSON_CHECK_ERR_v1(expr)  \
    do {                         \
        int __e = (expr);        \
        if (__e) {               \
            return __e;          \
        }                        \
    } while (0)
/* End of JSON_CHECK_ERR_v1 */

#define JSON_CHECK_ERR_v2(expr)  \
    do {                         \
        int __e = (expr);        \
        if (__e) {               \
            return NULL;         \
        }                        \
    } while (0)
/* End of JSON_CHECK_ERR_v2 */

#define JSON_CHECK_PTR(ptr)      \
    do {                         \
        if ((ptr) == NULL) {     \
            return NULL;         \
        }                        \
    } while (0)
/* End of JSON_CHECK_ERR */

#define JSON_NEXT_EXPECT(_ch)    \
    do {                         \
        char ch = (++ptr)[0];    \
        if (ch != _ch) {         \
            JSON_ERROR(ch, ptr); \
        }                        \
    } while (0)
/* End of JSON_NEXT_EXPECT */

static json_node_t* __json_node_new(json_value_type_t type, char *name) {
    json_node_t *json = json_config_ctx->malloc(sizeof(json_node_t));
    JSON_CHECK_PTR(json);
    memset(json, 0, sizeof(json_node_t));

    json->type = type;
    json->name = name;

    return json;
}

static inline bool __is_whitespace(char ch) {
    switch (ch) {
    case 0x20:
    case '\n':
    case '\r':
    case '\t':
        return true;
    default:
        return false;
    }
}

static inline char* __skip_whitespace(char *ptr) {
    while (*ptr != '\0') {
        if (__is_whitespace(*ptr))
            ++ptr;
        else break;
    }
    return ptr;
}

/*
 * Only support C++-style (a.k.a. single-line) comments which start with
 * double slash "//" and continue until the end of the line.
 */
static inline bool __is_ln_comment(char *ptr) {
    return ((ptr[0] == '/') && (ptr[1] == '/'));
}
static inline char* __skip_ln_comment(char *ptr) {
    if (__is_ln_comment(ptr)) {
        ptr += 2; // skip //.
        while ((*ptr != '\n') && (*ptr != '\0')) {
            ++ptr;
        }
        if (*ptr == '\n') ++ptr;
    }
    return ptr;
}

static inline char* __skip_invalid_char(char *ptr) {
    do {
        ptr = __skip_whitespace(ptr);
        ptr = __skip_ln_comment(ptr);
    } while (__is_whitespace(*ptr) || __is_ln_comment(ptr));
    return ptr;
}

static inline bool __is_digit(char ch) {
    switch (ch) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return true;
    default:
        return false;
    }
}

static inline bool __is_number(char ch) {
    return ((ch == '-') || __is_digit(ch));
}

static char* __parse_number(char *ptr, json_node_t *json) {
    enum num_type_t {
        NT_integer = 0,
        NT_fraction,
        NT_exponent,
    } num_type = NT_integer;
    enum num_state_t {
        NS_number_begin = 0,
        NS_number_minus,
        NS_digit_0,
        NS_digit_1_9,
        NS_fraction_begin,
        NS_fraction,
        NS_exponent_begin,
        NS_exponent_sign,
        NS_exponent,
        NS_number_finish,
    } state = NS_number_begin;

    char *num_str = ptr;
    do {
        char ch = *ptr;

        switch (state) {
        case NS_number_begin:
            if (ch == '-') {
                state = NS_number_minus;
            } else \
            if (ch == '0') {
                state = NS_digit_0;
            } else \
            if (ch >= '1' && ch <= '9') {
                state = NS_digit_1_9;
            } else {
                /* Won't reach here. */
                JSON_ERROR(ch, ptr);
            }
            break;
        case NS_number_minus:
            if (ch == '0') {
                state = NS_digit_0;
            } else \
            if (ch >= '1' && ch <= '9') {
                state = NS_digit_1_9;
            } else {
                /* Such as: "--", "-,". */
                JSON_ERROR(ch, ptr);
            }
            break;
        case NS_digit_0:
            if (ch == '.') {
                num_type = NT_fraction;
                state = NS_fraction_begin;
            } else \
            if (ch == 'e' || ch == 'E') {
                num_type = NT_exponent;
                state = NS_exponent_begin;
            } else {
                /*
                 * The 2nd char will be treated as next section.
                 * Such as: "0,", "00", "0x1234".
                 * FIXME: how about strtoll(0x1234)?
                 */
                state = NS_number_finish;
            }
            break;
        case NS_digit_1_9:
            if (__is_digit(ch)) {
                ;
            } else \
            if (ch == '.') {
                num_type = NT_fraction;
                state = NS_fraction_begin;
            } else \
            if (ch == 'e' || ch == 'E') {
                num_type = NT_exponent;
                state = NS_exponent_begin;
            } else {
                /* Such as: "11,", "10x". */
                state = NS_number_finish;
            }
            break;
        case NS_fraction_begin:
            if (__is_digit(ch)) {
                state = NS_fraction;
            } else {
                /* Such as: "0.,", "1.a". */
                JSON_ERROR(ch, ptr);
            }
            break;
        case NS_fraction:
            if (__is_digit(ch)) {
                ;
            } else \
            if (ch == 'e' || ch == 'E') {
                num_type = NT_exponent;
                state = NS_exponent_begin;
            } else {
                /* Such as: "0.1a", "-2.5,". */
                state = NS_number_finish;
            }
            break;
        case NS_exponent_begin:
            if (ch == '-' || ch == '+') {
                state = NS_exponent_sign;
            } else \
            if (__is_digit(ch)) {
                state = NS_exponent;
            } else {
                /* Such as: "0.1e,", "-2.5Ex". */
                JSON_ERROR(ch, ptr);
            }
            break;
        case NS_exponent_sign:
            if (__is_digit(ch)) {
                state = NS_exponent;
            } else {
                /* Such as: "0.1e+a", "-2.0E-x,", "1e--". */
                JSON_ERROR(ch, ptr);
            }
            break;
        case NS_exponent:
            if (__is_digit(ch)) {
                ;
            } else {
                /* Such as: "0.1e+2a", "-2.0E-10x,". */
                state = NS_number_finish;
            }
            break;
        case NS_number_finish:
        default:
            break;
        }
    } while ((state != NS_number_finish) && (*(++ptr) != '\0'));

    if (state == NS_number_finish) {
        if (num_type == NT_integer) {
            json->type = JSON_INTEGER;
            json->value.integer = (int64_t)strtoll(num_str, NULL, 10);
        } else {
            json->type = JSON_DECIMAL;
            json->value.decimal = strtod(num_str, NULL);
        }
    }

    return ptr;
}

static inline bool __is_hex(char ch) {
    return (__is_digit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'));
}

static inline bool __is_escapes(char ch) {
    switch (ch) {
    case '"':
    case '\\':
    case '/':
    case 'b':
    case 'f':
    case 'n':
    case 'r':
    case 't':
    case 'u':
        return true;
    default:
        return false;
    }
}

static inline bool __is_string(char ch) {
    return (ch == '"');
}

static char* __parse_string(char *ptr, char **string) {
    bool b_escaping = false;
    bool b_4hex = false;
    uint32_t n_4hex = 0;
    bool b_end_quote = false;

    char *str = ++ptr; // skip opening '"'.
    do {
        char ch = *ptr;
        if (ch != ' ' && __is_whitespace(ch)) {
            JSON_ERROR(ch, ptr);
        }

        if (b_4hex) {
            if (!__is_hex(ch)) {
                JSON_ERROR(ch, ptr);
            }
            if ((++n_4hex) == 4) {
                n_4hex = 0;
                b_4hex = false;
            }
        } else \
        if (b_escaping) {
            if (!__is_escapes(ch)) {
                JSON_ERROR(ch, ptr);
            }
            if (ch == 'u') {
                b_4hex = true;
            }
            b_escaping = false;
        } else \
        if (ch == '\\') {
            b_escaping = true;
        } else \
        if (ch == '"') {
            b_end_quote = true;
            break;
        }
    } while (*(++ptr) != '\0');

    if (b_end_quote) {
        size_t n = (ptr - str);
        *string = json_config_ctx->strndup(str, n);
        JSON_CHECK_PTR(*string);
        ++ptr; // skip closing '"'.
    } else {
        char *_str = (str - 1);
        char snippet[9];
        int i = 0;
        while ((_str[i] != '\0') && (i < 8)) {
            snippet[i] = ptr[i];
            ++i;
        }
        snippet[i] = '\0';

        json_config_ctx->printf("no closing string quote for `%s`.\n", snippet);

        ptr = NULL;
    }

    return ptr;
}

static inline bool __is_value(char ch);
static char* __parse_value(char *ptr, json_node_t *json);

static inline bool __is_object(char ch) {
    return (ch == '{');
}

static char* __parse_object(char *ptr, json_node_t *json) {
    json_node_t *parent = json;

    ++ptr; // skip '{'.
    ptr = __skip_invalid_char(ptr);
    if (*ptr == '}') {
        return ++ptr;
    }

    do {
        ptr = __skip_invalid_char(ptr);
        if (__is_string(*ptr)) {
            char *name = NULL;
            ptr = __parse_string(ptr, &name);
            JSON_CHECK_PTR(ptr);

            json_node_t *_json = __json_node_new(JSON_NULL, name);
            if (!_json) {
                json_config_ctx->free(name);
                JSON_CHECK_PTR(_json);
            } else {
                _json->parent = parent;
                if (json == parent) {
                    json->value.child = _json;
                } else {
                    json->next = _json;
                    _json->prev = json;
                }
                json = _json;
            }
        } else {
            JSON_ERROR(*ptr, ptr);
        }

        ptr = __skip_invalid_char(ptr);
        if (__is_value(*ptr)) {
            ++ptr; // skip ':'.
            ptr = __parse_value(ptr, json);
            JSON_CHECK_PTR(ptr);
        } else {
            JSON_ERROR(*ptr, ptr);
        }
    } while ((*ptr == ',') && (++ptr));

    if (*ptr != '}') {
        JSON_ERROR(*ptr, ptr);
    } else {
        ++ptr;
    }

    return ptr;
}

static inline bool __is_array(char ch) {
    return (ch == '[');
}

static char* __parse_array(char *ptr, json_node_t *json) {
    json_node_t *parent = json;

    ++ptr; // skip '['.
    ptr = __skip_invalid_char(ptr);
    if (*ptr == ']') {
        return ++ptr;
    }

    do {
        json_node_t *_json = __json_node_new(JSON_NULL, NULL);
        JSON_CHECK_PTR(_json);

        _json->parent = parent;
        if (json == parent) {
            json->value.array = _json;
        } else {
            json->next = _json;
            _json->prev = json;
        }
        json = _json;

        ptr = __parse_value(ptr, json);
        JSON_CHECK_PTR(ptr);
    } while ((*ptr == ',') && (++ptr));

    if (*ptr != ']') {
        JSON_ERROR(*ptr, ptr);
    } else {
        ++ptr;
    }

    return ptr;
}

static inline bool __is_value(char ch) {
    return (ch == ':');
}

static char* __parse_value(char *ptr, json_node_t *json) {
    ptr = __skip_invalid_char(ptr);

    char ch = *ptr;
    if (__is_string(ch)) {
        json->type = JSON_STRING;
        ptr = __parse_string(ptr, &(json->value.string));
        JSON_CHECK_PTR(ptr);
    } else \
    if (__is_number(ch)) {
        ptr = __parse_number(ptr, json);
        JSON_CHECK_PTR(ptr);
    } else \
    if (__is_object(ch)) {
        json->type = JSON_OBJECT;
        ptr = __parse_object(ptr, json);
        JSON_CHECK_PTR(ptr);
    } else \
    if (__is_array(ch)) {
        json->type = JSON_ARRAY;
        ptr = __parse_array(ptr, json);
        JSON_CHECK_PTR(ptr);
    } else \
    if (ch == 't') { // true
        JSON_NEXT_EXPECT('r');
        JSON_NEXT_EXPECT('u');
        JSON_NEXT_EXPECT('e');
        ++ptr;
        json->type = JSON_BOOL;
        json->value.boolean = true;
    } else \
    if (ch == 'f') { // false
        JSON_NEXT_EXPECT('a');
        JSON_NEXT_EXPECT('l');
        JSON_NEXT_EXPECT('s');
        JSON_NEXT_EXPECT('e');
        ++ptr;
        json->type = JSON_BOOL;
        json->value.boolean = false;
    } else \
    if (ch == 'n') { // null
        JSON_NEXT_EXPECT('u');
        JSON_NEXT_EXPECT('l');
        JSON_NEXT_EXPECT('l');
        ++ptr;
        json->type = JSON_NULL;
        json->value.string = NULL;
    } else {
        JSON_ERROR(ch, ptr);
    }

    ptr = __skip_invalid_char(ptr);
    return ptr;
}

json_node_t* json_parse(const char *text) {
    json_node_t *root = NULL;
    JSON_CHECK_PTR(text);

    char *ptr = (char *)text;
    ptr = __skip_invalid_char(ptr);

    if (__is_object(*ptr)) {
        root = __json_node_new(JSON_OBJECT, NULL);
        JSON_CHECK_PTR(root);

        if (!__parse_object(ptr, root)) {
            json_free(&root);
        }
    } else {
        JSON_ERROR(*ptr, ptr);
    }

    return root;
}

void json_free(json_node_t **_root) {
    if (!_root || !(*_root)) {
        return;
    }

    json_node_t *json = *_root;
    if (json->name) {
        json_config_ctx->free(json->name);
        json->name = NULL;
    }

    if ((json->type == JSON_STRING) && json->value.string) {
        json_config_ctx->free(json->value.string);
        json->value.string = NULL;
    } else \
    if ((json->type == JSON_OBJECT) && json->value.child) {
        json_free(&json->value.child);
    } else \
    if ((json->type == JSON_ARRAY) && json->value.array) {
        json_free(&json->value.array);
    }

    if (json->next) {
        json_free(&json->next);
    }
    json_config_ctx->free(json);

    (*_root) = NULL;
}

json_node_t* json_child(json_node_t *node, const char *name) {
    JSON_CHECK_PTR(node);
    JSON_CHECK_PTR(name);

    if (node->type != JSON_OBJECT) {
        json_config_ctx->printf("%s: json_node_t named `%s` at %p is"
                " NOT a JSON_OBJECT.\n", __func__, node->name, node);
        return NULL;
    }

    json_node_t *child = node->value.child;
    while (child) {
        if (child->name && (strcmp(child->name, name) == 0)) {
            break;
        }
        child = child->next;
    }

    return child;
}

json_node_t* json_array_at(json_node_t *node, uint32_t i) {
    JSON_CHECK_PTR(node);

    if (node->type != JSON_ARRAY) {
        json_config_ctx->printf("%s: json_node_t named `%s` at %p is"
                " NOT a JSON_ARRAY.\n", __func__, node->name, node);
        return NULL;
    }

    node = node->value.array;
    uint32_t _i = 0;
    while (node && (_i++ < i)) {
        node = node->next;
    }

    return node;
}

json_node_t* json_find_by_name(json_node_t *node, const char *name) {
    JSON_CHECK_PTR(node);
    JSON_CHECK_PTR(name);

    while (node) {
        if (node->name && (strcmp(node->name, name) == 0)) {
            break;
        }

        /* Find in sub nodes. */
        json_node_t *_node = NULL;
        if ((node->type == JSON_OBJECT) && (node->value.child)) {
            _node = json_find_by_name(node->value.child, name);
        } else \
        if ((node->type == JSON_ARRAY) && (node->value.array)) {
            _node = json_find_by_name(node->value.array, name);
        }
        if (_node) { // Found.
            return _node;
        }

        /* Next sibling. */
        node = node->next;
    }

    return node;
}

typedef struct __json_stringify_buf {
    char *buffer, *line;
    char *warning;
    uint32_t buflen;
    uint32_t chunk_size;
} __json_stringify_buf_t;

static int __json_stringify(const json_node_t *json, bool b_pretty, uint32_t depth,
        __json_stringify_buf_t *ctx) {
    do {
        char *pl = ctx->line;

        /* Indentation. */
        if (b_pretty) {
            uint32_t d = depth;
            while (d-- > 0) *pl++ = '\t';
        }

        /* Name. */
        if (json->name) {
            // FIXME: strlen(json->name) may be very big.
            pl += json_config_ctx->sprintf(pl, "\"%s\":", json->name);
            if (b_pretty) {
                *pl++ = ' ', *pl = '\0';
            }
        }

        /* Value. */
        switch (json->type) {
        case JSON_OBJECT:
        case JSON_ARRAY: {
            json_node_t *sub_json_nodes = (json->type == JSON_OBJECT) ?
                    json->value.child : json->value.array;
            *pl++ = (json->type == JSON_OBJECT) ? '{' : '[', *pl = '\0';
            if (b_pretty && sub_json_nodes) {
                *pl++ = '\n', *pl = '\0';
            }
            // json_config_ctx->printf(ctx->line);
            ctx->line = pl;

            if (sub_json_nodes) {
                JSON_CHECK_ERR_v1(__json_stringify(sub_json_nodes, b_pretty,
                        depth + 1, ctx));
                pl = ctx->line;

                if (b_pretty) {
                    uint32_t d = depth;
                    while (d-- > 0) *pl++ = '\t';
                }
            }

            *pl++ = (json->type == JSON_OBJECT) ? '}' : ']', *pl = '\0';
            break;
        }
        case JSON_INTEGER:
            pl += json_config_ctx->sprintf(pl, "%ld", json->value.integer);
            break;
        case JSON_DECIMAL: {
            /* Keep at least one digit after dot. */
            char *_pl = pl;
            pl += sprintf(pl, "%g", json->value.decimal);
            if (!strchr(_pl, '.')) {
                pl += sprintf(pl, ".0");
            }
            break;
        }
        case JSON_STRING:
            // FIXME: strlen(json->string) may be very big.
            pl += json_config_ctx->sprintf(pl, "\"%s\"", json->value.string);
            break;
        case JSON_BOOL:
            pl += json_config_ctx->sprintf(pl, "%s", json->value.boolean ? "true" : "false");
            break;
        case JSON_NULL:
        default:
            pl += json_config_ctx->sprintf(pl, "null");
            break;
        }

        /* Has more? */
        if (json->next) {
            *pl++ = ',', *pl = '\0';
        }

        /* EoL. */
        if (b_pretty) {
            *pl++ = '\n', *pl = '\0';
        }

        /* Update line pointer. */
        // json_config_ctx->printf(ctx->line);
        ctx->line = pl;
        if (ctx->line > ctx->warning) {
            uint32_t consumed = (uint32_t)(ctx->line - ctx->buffer);
            uint32_t _buflen = ctx->buflen + ctx->chunk_size;
            char *_buffer = (char *)json_config_ctx->realloc(ctx->buffer, _buflen);
            if (!_buffer) {
                json_config_ctx->free(ctx->buffer);
                return -1;
            }
            ctx->buffer  = _buffer;
            ctx->buflen  = _buflen;
            ctx->line    = _buffer + consumed;
            ctx->warning = _buffer + _buflen - ctx->chunk_size;
        }
    } while (json->next && (json = json->next));

    return 0;
}

char* json_stringify(const json_node_t *root, bool b_pretty) {
    JSON_CHECK_PTR(root);

    __json_stringify_buf_t _ctx = {0, }, *ctx = &_ctx;
    ctx->chunk_size = 1024; // FIXME: must hold one line.
    ctx->buffer = (char *)json_config_ctx->malloc(ctx->chunk_size * 2);
    JSON_CHECK_PTR(ctx->buffer);
    ctx->buflen  = ctx->chunk_size * 2;
    ctx->line    = ctx->buffer;
    ctx->warning = ctx->line + ctx->chunk_size;

    JSON_CHECK_ERR_v2(__json_stringify(root, b_pretty, 0, ctx));

    return ctx->buffer;
}

char* json_minify(const char *text) {
    JSON_CHECK_PTR(text);

#if 1
    json_node_t *root = json_parse(text);
    JSON_CHECK_PTR(root);

    char *minified = json_stringify(root, false);
    json_free(&root);
#else
    char *minified = (char *)json_config_ctx->
            malloc(strlen(text) + 1);
    JSON_CHECK_PTR(minified);

    // FIXME: comments.

    char *from = (char *)text, *to = minified;
    bool b_string = false;
    while (*from != '\0') {
        if (*from == '"' && *(from - 1) != '\\') {
            b_string = !b_string;
        }
        if (!b_string && __is_whitespace(*from)) {
            ++from;
        } else {
            *to++ = *from++;
        }
    }
    *to = '\0';
#endif

    return minified;
}
