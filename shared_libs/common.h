#ifndef __AITF_COMMON_H
#define __AITF_COMMON_H

// nullptr emulation
class nullptr_t {/*{{{*/
  public:
    template<class T>
    inline operator T*() const; // convertible to any type of null non-member pointer...

    template<class C, class T>
    inline operator T C::*() const;   // or any type of null member pointer...

  private:
    void operator&() const;  // Can't take address of nullptr
} nullptr = {};/*}}}*/

char* create_str(int);
unsigned char* create_ustr(int l);

#endif
