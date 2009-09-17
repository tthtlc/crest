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


#include <stdio.h>
#include <string.h>
#include <klee/klee.h>
#include "pcre.h"

const int OVECCOUNT = 30;

/*
size_t my_strlen(char* s) {
  char* p = s;
  while (*p) p++;
  return (p - s);
}
*/

int main(int argc, char* argv[]) {
  const char* error;
  int erroroffset;
  int ovector[OVECCOUNT];
  int N, i, rc;

  // Symbolic subject string.
  N = atoi(argv[1]);
  char* subject = (char*)malloc(N + 1);
  for (i = 0; i < N; i++) {
	klee_make_symbolic(&subject[i], sizeof(subject[i]), "input"); 
  }
  subject[N] = 0;

  // Pattern string.
  char* pattern = (char*)malloc(2*N + 6);
  for (i = 0; i < N; i++) {
    pattern[2*i] = 'x';
    pattern[2*i + 1] = '*';
  }
  pattern[2*N] = 0;
  strcat(pattern, "(y|z)");

  // Compile the regular expression.
  pcre* re = pcre_compile(pattern, 0, &error, &erroroffset, NULL);
  if (re == NULL) {
    printf("PCRE compilation failed at offset %d: %s\n", erroroffset, error);
    return 1;
  }

  // Execute the regular expression.
  rc = pcre_exec(re, NULL,
                 subject, N, // my_strlen(subject),
                 0, 0, ovector, OVECCOUNT);

  printf("%d: %s\n", rc, subject);

  return 0;
}
