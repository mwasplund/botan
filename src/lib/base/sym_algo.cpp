/*
* (C) 2018 Jack Lloyd
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

#include <botan/sym_algo.h>
#include <botan/exceptn.h>

#endif

namespace Botan {

void SymmetricAlgorithm::throw_key_not_set_error() const
   {
   throw Key_Not_Set(name());
   }

void SymmetricAlgorithm::set_key(const uint8_t key[], size_t length)
   {
   if(!valid_keylength(length))
      throw Invalid_Key_Length(name(), length);
   key_schedule(key, length);
   }

}
