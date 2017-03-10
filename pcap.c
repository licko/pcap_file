#include <stdio.h>
#include<fcntl.h>
#include<errno.h>
#include <arpa/inet.h>
#include "pcap.h"

u32 pcapfile_open(char *pcap_file_name)
{
  u32 fd;
  u32 file_heaser_size;
  struct pcap_file_header head;
  head.magic = 0xa1b2c3d4;
  head.version_major = 2;
  head.version_minor = 4;
  head.thiszone = 0;
  head.sigfigs = 0;
  head.snaplen = 0x0000ffff;
  head.linktype = 1;

  fd = open(pcap_file_name, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR); /* 创建并打开文件 */
  if (fd < 0) 
    {
      printf("pcap_file_name\n");
      return -1;
    }

  file_heaser_size = sizeof(struct pcap_file_header);
  if((write(fd, &head, file_heaser_size) != file_heaser_size))
    {
      printf("Error writing to the file!\n");
      return -1;
    }

  return fd;
}

void pcapfile_close(u32 fd)
{
  close(fd);
}

i32 pcapfile_write_data(u32 fd, u8 *data, u32 data_len)
{
  struct pcap_pkthdr pcap;   
  struct timeval tv;  
   
  gettimeofday(&tv, NULL);  
  pcap.tv_sec = tv.tv_sec; //htonl(tv.tv_sec);
  pcap.tv_usec = tv.tv_usec; //htonl(tv.tv_usec);

  pcap.caplen = pcap.len = data_len;
  

  if(write(fd, &pcap, sizeof(pcap)) != sizeof(pcap))
    {
      printf("Write pcap pkthdr failed!\n");
      return -1;
    }
 
  if(write(fd, data, data_len) != data_len)
    {
      printf("Write data failed!\n");
      return -1;
    }
  
  return 0;
}

