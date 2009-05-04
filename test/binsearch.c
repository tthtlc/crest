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

int X[8] = {0, 1, 2, 3, 4, 5, 6, 7};

int main(void) {
  int a, max = 7, min = 0;

  CREST_int(a);
 
 while(max > min) {
  int mid = (min + max) /2;
  if (X[mid] == a) {
    printf("Yes\n");
    break;
  } else if(X[mid] < a) {
    printf("No\n");
    min = mid + 1;
  }
  else {
   printf("No\n");
   max = mid - 1;
  }
 }	
  return 0;
}
