/* Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
 *
 * This file is part of CREST, which is distributed under the revised
 * BSD license.  A copy of this license can be found in the file LICENSE.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
 * for details.
 */

#include <crest.h>

int main(void) {
  int a, b, c, d;
  char x, y, z;
  short s;

  CREST_int(a);
  CREST_char(x);
  CREST_char(y);

  b = a;
  *((char*)&b) = x;
  *(((char*)&b) + 2) = x;

  *(((char*)&c) + 3) = y;
  c = a;

  *(((char*)&c) + 1) = '0';

  *(((short*)&b) + 1) = 13;

  z = *(((char*)&a));
  z = *(((char*)&a) + 1);
  z = *(((char*)&a) + 2);
  z = *(((char*)&a) + 3);

  a = 1984;
  *(((char*)&a) + 1) = y;
  *(((char*)&a) + 3) = y;

  d = b;

  d = c;

  s = *((short*)&a);

  s = *(((short*)&b)+1);

  d = a;
}

