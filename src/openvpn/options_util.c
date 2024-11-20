/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "options_util.h"

#include "push.h"

const char *
parse_auth_failed_temp(struct options *o, const char *reason)
{
    struct gc_arena gc = gc_new();

    const char *message = reason;
    char *m = string_alloc(reason, &gc);

    /* Check if the message uses the TEMP[flags]: message format*/
    char *endofflags = strstr(m, "]");

    /* Temporary failure from the server */
    if (m[0] == '[' && endofflags)
    {
        message = strstr(reason, "]") + 1;
        /* null terminate the substring to only looks for flags between [ and ] */
        *endofflags = '\x00';
        const char *token = strtok(m, "[,");
        while (token)
        {
            if (!strncmp(token, "backoff ", strlen("backoff ")))
            {
                if (sscanf(token, "backoff %d", &o->server_backoff_time) != 1)
                {
                    msg(D_PUSH, "invalid AUTH_FAIL,TEMP flag: %s", token);
                    o->server_backoff_time = 0;
                }
            }
            else if (!strncmp(token, "advance ", strlen("advance ")))
            {
                token += strlen("advance ");
                if (!strcmp(token, "no"))
                {
                    o->no_advance = true;
                }
                else if (!strcmp(token, "remote"))
                {
                    o->advance_next_remote = true;
                    o->no_advance = false;
                }
                else if (!strcmp(token, "addr"))
                {
                    /* Go on to the next remote */
                    o->no_advance = false;
                }
            }
            else
            {
                msg(D_PUSH_ERRORS, "WARNING: unknown AUTH_FAIL,TEMP flag: %s", token);
            }
            token = strtok(NULL, "[,");
        }
    }

    /* Look for the message in the original buffer to safely be
     * able to return it */
    if (!message || message[0] != ':')
    {
        message = "";
    }
    else
    {
        /* Skip the : at the beginning */
        message += 1;
    }
    gc_free(&gc);
    return message;
}

bool
valid_integer(const char *str, bool positive)
{
    char *endptr;
    long long i = strtoll(str, &endptr, 10);

    if (i < INT_MIN || (positive && i < 0) || *endptr != '\0' || i > INT_MAX)
    {
        return false;
    }
    else
    {
        return true;
    }
}

int
positive_atoi(const char *str, int msglevel)
{
    char *endptr;
    long long i = strtoll(str, &endptr, 10);

    if (i < 0 || *endptr != '\0' || i > INT_MAX)
    {
        msg(msglevel, "Cannot parse argument '%s' as non-negative integer",
            str);
        i = 0;
    }

    return (int) i;
}

int
atoi_warn(const char *str, int msglevel)
{
    char *endptr;
    long long i = strtoll(str, &endptr, 10);

    if (i < INT_MIN || *endptr != '\0' || i > INT_MAX)
    {
        msg(msglevel, "Cannot parse argument '%s' as integer", str);
        i = 0;
    }

    return (int) i;
}

static const char *updatable_options[] = {
    "block-ipv6",
    "block-outside-dns",
    "dhcp-option",
    "dns",
    "ifconfig",
    "ifconfig-ipv6",
    "push-continuation",
    "redirect-gateway",
    "redirect-private",
    "route",
    "route-gateway",
    "route-ipv6",
    "route-metric",
    "topology",
    "tun-mtu",
    "keepalive"
};

/**
 * @brief Checks the formatting and validity of options inside push-update messages.
 *
 * This function is used in `apply_pull_filter()` to validate and process options
 * in push-update messages. It performs the following checks:
 * - Determines if the options are updatable.
 * - Checks for the presence of the `-` flag, which indicates that the option
 *   should be removed.
 * - Checks for the `?` flag, which marks the option as optional and suppresses
 *   errors if the client cannot update it.
 * - Modifies the original string (`*line`) by removing the `'-'` and `'?'` flags
 *   after validating them and updating the appropriate flags in the `flags` variable.
 * - `-?option`, `-option`, `?option` are valid formats, `?-option` is not a valid format.
 *
 * @param line A pointer to an option string. This string is the option being validated.
 * @param flags A pointer where flags will be stored:
 *              - `PUSH_OPT_TO_REMOVE`: Set if the `-` flag is present.
 *              - `PUSH_OPT_OPTIONAL`: Set if the `?` flag is present.
 *
 * @return true if the flags and option combination are valid.
 * @return false if:
 *         - The `-` and `?` flags are not formatted correctly.
 *         - The `line` parameter is empty or `NULL`.
 *         - The `?` flag is absent and the option is not updatable.
 */
static bool
check_push_update_option_flags(char **line, unsigned int *flags)
{
    if (!line || !*line || !**line)
    {
        return false;
    }
    *flags = 0;
    bool opt_is_updatable = false;
    char *str = *line;
    char c = **line;

    if (c == '-')
    {
        if (!(str)[1])
        {
            return false;
        }
        *flags |= PUSH_OPT_TO_REMOVE;
        c = *(++(str));
    }
    if (c == '?')
    {
        if (!(str)[1] || (str)[1] == '-')
        {
            return false;
        }
        *flags |= PUSH_OPT_OPTIONAL;
        c = *(++(str));
    }

    /* Skip '?' and '-' if they are present */
    size_t len = strlen(str);
    memmove(*line, str, len);
    (*line)[len] = '\0';
    str = *line;

    int count = sizeof(updatable_options)/sizeof(char *);
    for (int i = 0; i < count; ++i)
    {
        size_t opt_len = strlen(updatable_options[i]);
        if (len < opt_len)
        {
            continue;
        }
        if (!strncmp(str, updatable_options[i], opt_len)
            && (!str[opt_len] || str[opt_len] == ' '))
        {
            opt_is_updatable = true;
            break;
        }
    }

    if (!opt_is_updatable)
    {
        if (*flags & PUSH_OPT_OPTIONAL)
        {
            msg(D_PUSH, "Pushed option is not updatable: '%s'", *line);
            return true;
        }
        else
        {
            msg(M_WARN, "Pushed option is not updatable: '%s'. Restarting.", *line);
            return false;
        }
    }

    return true;
}

bool
apply_pull_filter(const struct options *o, char *line, bool is_update, unsigned int *push_update_option_flags)
{
    struct pull_filter *f;

    if (!o->pull_filter_list && !(is_update))
    {
        return true;
    }

    /* skip leading spaces matching the behaviour of parse_line */
    while (isspace(*line))
    {
        line++;
    }

    if (is_update)
    {
        if (!check_push_update_option_flags(&line, push_update_option_flags))
        {
            return false;
        }
        if (!o->pull_filter_list)
        {
            return true;
        }
    }

    for (f = o->pull_filter_list->head; f; f = f->next)
    {
        if (f->type == PUF_TYPE_ACCEPT && strncmp(line, f->pattern, f->size) == 0)
        {
            msg(D_LOW, "Pushed option accepted by filter: '%s'", line);
            return true;
        }
        else if (f->type == PUF_TYPE_IGNORE && strncmp(line, f->pattern, f->size) == 0)
        {
            msg(D_PUSH, "Pushed option removed by filter: '%s'", line);
            return true;
        }
        else if (f->type == PUF_TYPE_REJECT && strncmp(line, f->pattern, f->size) == 0)
        {
            if (is_update && (*push_update_option_flags & PUSH_OPT_OPTIONAL))
            {
                msg(D_PUSH, "Pushed option removed by filter: '%s'", line);
                return true;
            }
            else
            {
                msg(M_WARN, "Pushed option rejected by filter: '%s'. Restarting.", line);
                return false;
            }
        }
    }
    return true;
}
