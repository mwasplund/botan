/*
* KDF1 from ISO 18033-2
* (C) 2016 Philipp Weber
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

#include <botan/kdf1_iso18033.h>

#endif

namespace Botan {

size_t KDF1_18033::kdf(uint8_t key[], size_t key_len,
                       const uint8_t secret[], size_t secret_len,
                       const uint8_t salt[], size_t salt_len,
                       const uint8_t label[], size_t label_len) const
   {
   uint32_t counter = 0;
   secure_vector<uint8_t> h;

   size_t offset = 0;
   while(offset != key_len && counter != 0xFFFFFFFF)
      {
      m_hash->update(secret, secret_len);
      m_hash->update_be(counter++);
      m_hash->update(label, label_len);
      m_hash->update(salt, salt_len);
      m_hash->final(h);

      const size_t added = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), added);
      offset += added;
      }

   return offset;
   }

}
