/* Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
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
#include <stdio.h>

struct bar {
  int x;
  int y;
};

struct foo {
  int x;
  struct bar bar;
  int y;
};

struct foo F[100];

int main(void) {
  struct foo f2;
  struct bar b;

  CREST_int(b.x);
  CREST_int(b.y);

  F[1].x = 7;
  F[1].bar = (const struct bar)b;
  F[1].y = 19;

  CREST_int(f2.x);
  CREST_int(f2.y);

  f2 = F[1];

  if (f2.bar.x > 3) { }
  if (f2.y < 18) { }
  if (f2.bar.y == 7) { }
  if (f2.x > 0) { }

  f2 = (const struct foo)(*(F+19));

  return 0;
}
