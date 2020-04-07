/*
* MGF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifdef SOUP_BUILD
module;
#include <algorithm>
#include <mutex>

#define SOUP_MACRO_ONLY
#include <botan/assert.h>
#include <botan/build.h>
module Botan;
#else

#include <botan/mgf1.h>
#include <botan/hash.h>
#include <algorithm>

#endif

namespace Botan {

void mgf1_mask(HashFunction& hash,
               const uint8_t in[], size_t in_len,
               uint8_t out[], size_t out_len)
   {
   uint32_t counter = 0;

   secure_vector<uint8_t> buffer(hash.output_length());
   while(out_len)
      {
      hash.update(in, in_len);
      hash.update_be(counter);
      hash.final(buffer.data());

      const size_t xored = std::min<size_t>(buffer.size(), out_len);
      xor_buf(out, buffer.data(), xored);
      out += xored;
      out_len -= xored;

      ++counter;
      }
   }

}
