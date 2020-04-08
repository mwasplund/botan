/*
* TLS Handshake Message
* (C) 2012 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_MSG_H_
#define BOTAN_TLS_HANDSHAKE_MSG_H_

#include <botan/tls_magic.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#ifndef SOUP_BUILD
#include <vector>
#include <string>
#endif

namespace Botan {

namespace TLS {

/**
* TLS Handshake Message Base Class
*/
class BOTAN_PUBLIC_API(2,0) Handshake_Message
   {
   public:
      /**
      * @return string representation of this message type
      */
      std::string type_string() const;

      /**
      * @return the message type
      */
      virtual Handshake_Type type() const = 0;

      /**
      * @return DER representation of this message
      */
      virtual std::vector<uint8_t> serialize() const = 0;

      virtual ~Handshake_Message() = default;
   };

}

}

#endif
