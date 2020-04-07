/*
* KDF defined in NIST SP 800-56c
* (C) 2016 Kai Michaelis
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

#include <botan/sp800_56c.h>

#endif

namespace Botan {

size_t SP800_56C::kdf(uint8_t key[], size_t key_len,
                      const uint8_t secret[], size_t secret_len,
                      const uint8_t salt[], size_t salt_len,
                      const uint8_t label[], size_t label_len) const
   {
   // Randomness Extraction
   secure_vector<uint8_t> k_dk;

   m_prf->set_key(salt, salt_len);
   m_prf->update(secret, secret_len);
   m_prf->final(k_dk);

   // Key Expansion
   m_exp->kdf(key, key_len, k_dk.data(), k_dk.size(), nullptr, 0, label, label_len);

   return key_len;
   }

}
