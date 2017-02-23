#include <stdio.h>
#include "pcap.h"

u32 main()
{
  i32 fd;
  char data[102] = {0x00, 0x32 ,0x50 ,0x91 ,0x33 ,0x20 ,0xA2 ,0xE0 ,0x12 ,0xFA ,0xBF ,0x63 ,0x81 ,0x00 ,0x00 ,0x0A ,0x08 ,0x00 ,0x45 ,0x00 ,0x00, 
                    0x54, 0x00 ,0x00 ,0x40 ,0x00 ,0x40 ,0x01 ,0x12 ,0x9E ,0x0A ,0x04 ,0x05 ,0x02 ,0x14 ,0x04 ,0x05 ,0x02 ,0x08 ,0x00 ,0xDC ,0xED,
                    0xBA, 0x6D ,0x03 ,0xB4 ,0xF0 ,0x62 ,0x98 ,0x57 ,0x00 ,0x00 ,0x00 ,0x00 ,0x09 ,0x63 ,0x0C ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x10, 
                    0x11, 0x12 ,0x13 ,0x14 ,0x15 ,0x16 ,0x17 ,0x18 ,0x19 ,0x1A ,0x1B ,0x1C ,0x1D ,0x1E ,0x1F ,0x20 ,0x21 ,0x22 ,0x23 ,0x24 ,0x25,
                    0x26, 0x27 ,0x28 ,0x29 ,0x2A ,0x2B ,0x2C ,0x2D ,0x2E ,0x2F ,0x30 ,0x31 ,0x32 ,0x33 ,0x34 ,0x35 ,0x36 ,0x37};
  
  int i = 5;

  fd = pcapfile_open("pcap_test.pcap");
  if (fd != -1)
    {
      while(i--)
        {
          pcapfile_write_data(fd, data, 102);
        }
      
      pcapfile_close(fd);
    }
  
  return 0;
}
