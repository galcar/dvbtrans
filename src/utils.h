/*
 * This file is part of the dvbtrans distribution (https://github.com/galcar/dvbtrans).
 * Copyright (c) 2024 G. Alcaraz.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _UTILS_H_
#define _UTILS_H_

static const unsigned char *EMPTY_STRING = "";

char *substring (const char *in, int n, int len);

char *replace (char *in, char c, char r);

char *to_lower (char *in);

long long current_timestamp_ms ();

char *url_decode (const char *src);

#endif
