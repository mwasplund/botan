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
#include <botan/bcrypt_pbkdf.h>
#include <botan/ber_dec.h>
#include <botan/blinding.h>
#include <botan/block_cipher.h>
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
#include <botan/mgf1.h>
#include <botan/monty.h>
#include <botan/numthry.h>
#include <botan/ocsp.h>
#include <botan/oids.h>
#include <botan/parsing.h>
#include <botan/pem.h>
#include <botan/reducer.h>
#include <botan/rdrand_rng.h>
#include <botan/rotate.h>
#include <botan/scan_name.h>
#include <botan/sha3.h>
#include <botan/stream_cipher.h>
#include <botan/tls_algos.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/workfactor.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <botan/x509_ext.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/cast_sboxes.h>
#include <botan/internal/codec_base.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mp_monty.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>
#include <botan/internal/primality.h>
#include <botan/internal/rounding.h>
#include <botan/internal/safeint.h>
#include <botan/internal/simd_32.h>
#include <botan/internal/simd_avx2.h>
#include <botan/internal/socket.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/timer.h>

#if defined(BOTAN_HAS_EME_OAEP)
#include <botan/oaep.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1)
#include <botan/eme_pkcs.h>
#endif

#if defined(BOTAN_HAS_EME_RAW)
#include <botan/eme_raw.h>
#endif

#if defined(BOTAN_HAS_CHACHA)
  #include <botan/chacha.h>
#endif

#if defined(BOTAN_HAS_SALSA20)
  #include <botan/salsa20.h>
#endif

#if defined(BOTAN_HAS_SHAKE_CIPHER)
  #include <botan/shake_cipher.h>
#endif

#if defined(BOTAN_HAS_CTR_BE)
  #include <botan/ctr.h>
#endif

#if defined(BOTAN_HAS_OFB)
  #include <botan/ofb.h>
#endif

#if defined(BOTAN_HAS_RC4)
  #include <botan/rc4.h>
#endif

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

#if defined(BOTAN_HAS_HTTP_UTIL)
  #include <botan/http_util.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_RTLGENRANDOM)
  #include <botan/dyn_load.h>
#endif


#if defined(BOTAN_HAS_AES)
  #include <botan/aes.h>
#endif

#if defined(BOTAN_HAS_ARIA)
  #include <botan/aria.h>
#endif

#if defined(BOTAN_HAS_BLOWFISH)
  #include <botan/blowfish.h>
#endif

#if defined(BOTAN_HAS_CAMELLIA)
  #include <botan/camellia.h>
#endif

#if defined(BOTAN_HAS_CAST_128)
  #include <botan/cast128.h>
#endif

#if defined(BOTAN_HAS_CAST_256)
  #include <botan/cast256.h>
#endif

#if defined(BOTAN_HAS_CASCADE)
  #include <botan/cascade.h>
#endif

#if defined(BOTAN_HAS_DES)
  #include <botan/des.h>
  #include <botan/desx.h>
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
  #include <botan/gost_28147.h>
#endif

#if defined(BOTAN_HAS_IDEA)
  #include <botan/idea.h>
#endif

#if defined(BOTAN_HAS_KASUMI)
  #include <botan/kasumi.h>
#endif

#if defined(BOTAN_HAS_LION)
  #include <botan/lion.h>
#endif

#if defined(BOTAN_HAS_MISTY1)
  #include <botan/misty1.h>
#endif

#if defined(BOTAN_HAS_NOEKEON)
  #include <botan/noekeon.h>
#endif

#if defined(BOTAN_HAS_SEED)
  #include <botan/seed.h>
#endif

#if defined(BOTAN_HAS_SERPENT)
  #include <botan/serpent.h>
#endif

#if defined(BOTAN_HAS_SHACAL2)
  #include <botan/shacal2.h>
#endif

#if defined(BOTAN_HAS_SM4)
  #include <botan/sm4.h>
#endif

#if defined(BOTAN_HAS_TWOFISH)
  #include <botan/twofish.h>
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
  #include <botan/threefish_512.h>
#endif

#if defined(BOTAN_HAS_XTEA)
  #include <botan/xtea.h>
#endif

#if defined(BOTAN_HAS_OPENSSL)
  #include <botan/internal/openssl.h>
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
  #include <botan/internal/commoncrypto.h>
#endif