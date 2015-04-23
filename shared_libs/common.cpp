#include <stdlib.h>
#include <string.h>
#include "common.h"

char* create_str(int l) {/*{{{*/
    char *s = (char*)malloc(sizeof(char) * (l + 1));
    memset(s, '\0', l + 1);
    return s;
}/*}}}*/

unsigned char* create_ustr(int l) {/*{{{*/
    unsigned char *s = (unsigned char*)malloc(sizeof(char) * (l + 1));
    memset(s, '\0', l + 1);
    return s;
}/*}}}*/

