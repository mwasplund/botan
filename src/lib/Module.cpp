module;

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <type_traits>

export module Botan;

#include <botan/base64.h>
#include <botan/ber_dec.h>
#include <botan/blinding.h>
#include <botan/calendar.h>
#include <botan/charset.h>
#include <botan/cpuid.h>
#include <botan/datastor.h>
#include <botan/der_enc.h>
#include <botan/dh.h>
#include <botan/divide.h>
#include <botan/ecdh.h>
#include <botan/entropy_src.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/loadstor.h>
#include <botan/monty.h>
#include <botan/numthry.h>
#include <botan/ocsp.h>
#include <botan/oids.h>
#include <botan/parsing.h>
#include <botan/pem.h>
#include <botan/reducer.h>
#include <botan/rdrand_rng.h>
#include <botan/tls_algos.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/workfactor.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <botan/x509_ext.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/codec_base.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mp_monty.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>
#include <botan/internal/primality.h>
#include <botan/internal/rounding.h>
#include <botan/internal/safeint.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
  #include <botan/locking_allocator.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
  #include <botan/internal/rdrand.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
  #include <botan/internal/rdseed.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DARN)
  #include <botan/internal/p9_darn.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
  #include <botan/internal/dev_random.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
  #include <botan/internal/es_win32.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
  #include <botan/internal/proc_walk.h>
  #include <botan/internal/os_utils.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
  #include <botan/internal/getentropy.h>
#endif