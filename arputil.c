#include "arputil.h"

u_int8_t is_ip_valid(char *ipAddr)
{
  int num, count = 0;
  char *ptr;
#define DELIM "."

  if(ipAddr == NULL)
  {
    return FALSE;
  }

  ptr = strtok(ipAddr, DELIM);
  if(ptr == NULL)
  {
     return FALSE;
  }

  while(ptr)
  {
    num = atoi(ptr);
    if(num >= 0 && num <=255)
    {
      ptr = strtok(NULL, DELIM);
      if(ptr != NULL)
      {
        ++count;
      }
    }
    else
    {
      return FALSE;
    }
  }

  if(count != 3)
  {
    return FALSE;
  }
  return TRUE;
}