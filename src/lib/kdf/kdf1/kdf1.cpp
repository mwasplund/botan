/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifdef SOUP_BUILD
module;
#include <mutex>

#define SOUP_MACRO_ONLY
#include <botan/assert.h>
#include <botan/build.h>
module Botan;
#else

#include <botan/kdf1.h>

#endif

namespace Botan {

size_t KDF1::kdf(uint8_t key[], size_t key_len,
                 const uint8_t secret[], size_t secret_len,
                 const uint8_t salt[], size_t salt_len,
                 const uint8_t label[], size_t label_len) const
   {
   m_hash->update(secret, secret_len);
   m_hash->update(label, label_len);
   m_hash->update(salt, salt_len);

   if(key_len < m_hash->output_length())
      {
      secure_vector<uint8_t> v = m_hash->final();
      copy_mem(key, v.data(), key_len);
      return key_len;
      }

   m_hash->final(key);
   return m_hash->output_length();
   }

}
