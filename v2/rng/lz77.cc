#include <stdint.h>

// This code was publicly posted by Andy Herbert.
// I think it is the public domain.

// return outsize
uint32_t lz77_compress (uint8_t *uncompressed_text, uint32_t uncompressed_size, uint8_t *compressed_text) {
  uint8_t pointer_length, temp_pointer_length;
  uint16_t pointer_pos, temp_pointer_pos, output_pointer;
  uint32_t compressed_pointer, output_size, coding_pos, output_lookahead_ref, look_behind, look_ahead;
  
  *((uint32_t *) compressed_text) = uncompressed_size;
  compressed_pointer = output_size = 4;
  
  for(coding_pos = 0; coding_pos < uncompressed_size; ++coding_pos) {
    pointer_pos = 0;
    pointer_length = 0;
    for(temp_pointer_pos = 1; (temp_pointer_pos < 4096) && (temp_pointer_pos <= coding_pos);
        ++temp_pointer_pos) {
      look_behind = coding_pos - temp_pointer_pos;
      look_ahead = coding_pos;
      for(temp_pointer_length = 0;
          uncompressed_text[look_ahead++] == uncompressed_text[look_behind++];
           ++temp_pointer_length) {
        if(temp_pointer_length == 15)
          break;
      }
      if(temp_pointer_length > pointer_length) {
        pointer_pos = temp_pointer_pos;
        pointer_length = temp_pointer_length;
        if(pointer_length == 15)
          break;
      }
    }
    coding_pos += pointer_length;
    if(pointer_length && (coding_pos == uncompressed_size)) {
      output_pointer = (pointer_pos << 4) | (pointer_length - 1);
      output_lookahead_ref = coding_pos - 1;
    } else {
      output_pointer = (pointer_pos << 4) | pointer_length;
      output_lookahead_ref = coding_pos;
    }
    *((uint32_t *) (compressed_text + compressed_pointer)) = output_pointer;
    compressed_pointer += 2;
    *(compressed_text + compressed_pointer++) = *(uncompressed_text + output_lookahead_ref);
    output_size += 3;
  }
  
  return output_size;
}

uint32_t lz77_decompress (uint8_t *compressed_text, uint8_t *uncompressed_text) {
  uint8_t pointer_length;
  uint16_t input_pointer, pointer_pos;
  uint32_t compressed_pointer, coding_pos, pointer_offset, uncompressed_size;
  
  uncompressed_size = *((uint32_t *) compressed_text);
  compressed_pointer = 4;
  
  for(coding_pos = 0; coding_pos < uncompressed_size; ++coding_pos) {
    input_pointer = *((uint32_t *) (compressed_text + compressed_pointer));
    compressed_pointer += 2;
    pointer_pos = input_pointer >> 4;
    pointer_length = input_pointer & 15;
    if(pointer_pos)
      for(pointer_offset = coding_pos - pointer_pos; pointer_length > 0; --pointer_length)
        uncompressed_text[coding_pos++] = uncompressed_text[pointer_offset++];
    *(uncompressed_text + coding_pos) = *(compressed_text + compressed_pointer++);
  }
  
  return coding_pos;
}
