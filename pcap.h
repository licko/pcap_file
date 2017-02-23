#ifndef __included_pcap_h__
#define __included_pcap_h__

#include <sys/time.h>

typedef signed char i8;
typedef signed short i16;
typedef signed int i32;
typedef signed long long i64;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long uword;

struct pcap_pkthdr {
  //struct timeval ts;      /* time stamp */
  u32 tv_sec;        /* Seconds. */  
  u32 tv_usec;  /* Microseconds. */  
  u32 caplen;     /* length of portion present */
  u32 len;        /* length this packet (off wire) */
};

struct pcap_file_header {
  u32 magic;
  u16 version_major;
  u16 version_minor;
  i32 thiszone;     /* gmt to local correction */
  u32 sigfigs;    /* accuracy of timestamps */
  u32 snaplen;    /* max length saved portion of each pkt */
  u32 linktype;   /* data link type (LINKTYPE_*) */
};

u32 pcapfile_open(char *pcap_file_name);
void pcapfile_close(u32 fd);
i32 pcapfile_write_data(u32 fd, u8 *data, u32 data_len);

#endif /* __included_pcap_h__ */