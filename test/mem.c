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

int X[5] = {1, 2, 3, 4, 5};
int main(void) {
  int a, b;
  CREST_int(a);
  CREST_int(b);
  if (X[a] == b) {
    printf("Yes\n");
  } else {
    printf("No\n");
  }
  return 0;
}
