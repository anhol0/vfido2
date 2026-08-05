#ifndef MACRO_HPP
#define MACRO_HPP

#define MAKE_U16(high, low) (((uint16_t)high << 8) | ((uint16_t)(low)))
#define MAKE_U32(high, low) (((uint32_t)high << 16) | ((uint32_t)(low)))
#define MAKE_U64(high, low) (((uint64_t)high << 32) | ((uint64_t)(low)))

#endif
