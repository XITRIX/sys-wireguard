#pragma once

#include <stdint.h>

typedef struct ip_addr {
  uint8_t type;
  union {
    uint32_t ip4;
    uint8_t ip6[16];
  } addr;
} ip_addr_t;

typedef ip_addr_t ip4_addr_t;
