#include <stdlib.h>
#include <string.h>
#include "common.h"

template<class T> nullptr_t<T>::inline operator T*() const {return 0;}
template<class C, class T> nullptr_t<C, T>::inline operator T C::*() const {return 0;}

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

