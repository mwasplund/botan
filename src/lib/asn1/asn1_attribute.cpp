/*
* Attribute
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

#include <botan/asn1_attribute.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>

#endif

namespace Botan {

/*
* Create an Attribute
*/
Attribute::Attribute(const OID& attr_oid, const std::vector<uint8_t>& attr_value) :
   oid(attr_oid),
   parameters(attr_value)
   {}

/*
* Create an Attribute
*/
Attribute::Attribute(const std::string& attr_oid,
                     const std::vector<uint8_t>& attr_value) :
   oid(OID::from_string(attr_oid)),
   parameters(attr_value)
   {}

/*
* DER encode a Attribute
*/
void Attribute::encode_into(DER_Encoder& codec) const
   {
   codec.start_cons(SEQUENCE)
      .encode(oid)
      .start_cons(SET)
         .raw_bytes(parameters)
      .end_cons()
   .end_cons();
   }

/*
* Decode a BER encoded Attribute
*/
void Attribute::decode_from(BER_Decoder& codec)
   {
   codec.start_cons(SEQUENCE)
      .decode(oid)
      .start_cons(SET)
         .raw_bytes(parameters)
      .end_cons()
   .end_cons();
   }

}
