module;

#include <cstddef>
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
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

#include <botan/assert.h>
#include <botan/build.h>
#include <botan/types.h>

#include <botan/aead.h>
#include <botan/base64.h>
#include <botan/bcrypt_pbkdf.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/block_cipher.h>
#include <botan/calendar.h>
#include <botan/cbc.h>
#include <botan/certstor_system.h>
#include <botan/certstor_windows.h>
#include <botan/charset.h>
#include <botan/cpuid.h>
#include <botan/credentials_manager.h>
#include <botan/ctr.h>
#include <botan/curve_nistp.h>
#include <botan/der_enc.h>
#include <botan/dh.h>
#include <botan/divide.h>
#include <botan/blinding.h>
#include <botan/blowfish.h>
#include <botan/ecdh.h>
#include <botan/elgamal.h>
#include <botan/emsa_pkcs1.h>
#include <botan/emsa.h>
#include <botan/entropy_src.h>
#include <botan/ghash.h>
#include <botan/hash_id.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/keypair.h>
#include <botan/loadstor.h>
#include <botan/mac.h>
#include <botan/oids.h>
#include <botan/parsing.h>
#include <botan/pem.h>
#include <botan/pk_algs.h>
#include <botan/pk_ops.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/rotate.h>
#include <botan/rsa.h>
#include <botan/scan_name.h>
#include <botan/stream_cipher.h>
#include <botan/system_rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager.h>
#include <botan/x509path.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/codec_base.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mp_monty.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/padding.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/primality.h>
#include <botan/internal/rounding.h>
#include <botan/internal/safeint.h>
#include <botan/internal/socket.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/timer.h>
#include <botan/internal/tls_cbc.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/tls_session_key.h>


#if defined(BOTAN_HAS_CERTSTOR_MACOS)
   #include <botan/certstor_macos.h>
#elif defined(BOTAN_HAS_CERTSTOR_WINDOWS)
   #include <botan/certstor_windows.h>
#elif defined(BOTAN_HAS_CERTSTOR_FLATFILE) && defined(BOTAN_SYSTEM_CERT_BUNDLE)
   #include <botan/certstor_flatfile.h>
#endif

#if defined(BOTAN_HAS_TLS_CBC)
  #include <botan/internal/tls_cbc.h>
#endif

#if defined(BOTAN_HAS_EMSA1)
   #include <botan/emsa1.h>
#endif

#if defined(BOTAN_HAS_EMSA_X931)
   #include <botan/emsa_x931.h>
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
   #include <botan/emsa_pkcs1.h>
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
   #include <botan/pssr.h>
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
   #include <botan/emsa_raw.h>
#endif

#if defined(BOTAN_HAS_ISO_9796)
   #include <botan/iso9796.h>
#endif

#if defined(BOTAN_HAS_SCRYPT)
   #include <botan/scrypt.h>
#endif

#if defined(BOTAN_HAS_PBKDF1)
  #include <botan/pbkdf1.h>
#endif

#if defined(BOTAN_HAS_PBKDF2)
  #include <botan/pbkdf2.h>
#endif

#if defined(BOTAN_HAS_PGP_S2K)
  #include <botan/pgp_s2k.h>
#endif

#if defined(BOTAN_HAS_MODE_XTS)
  #include <botan/xts.h>
#endif

#if defined(BOTAN_HAS_GCM_CLMUL_CPU)
  #include <botan/internal/clmul_cpu.h>
#endif

#if defined(BOTAN_HAS_GCM_CLMUL_SSSE3)
  #include <botan/internal/clmul_ssse3.h>
#endif

#if defined(BOTAN_HAS_BLOCK_CIPHER)
  #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_AEAD_CCM)
  #include <botan/ccm.h>
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
  #include <botan/chacha20poly1305.h>
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
  #include <botan/eax.h>
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
  #include <botan/gcm.h>
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
  #include <botan/ocb.h>
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
  #include <botan/siv.h>
#endif

#if defined(BOTAN_HAS_CBC_MAC)
  #include <botan/cbc_mac.h>
#endif

#if defined(BOTAN_HAS_CMAC)
  #include <botan/cmac.h>
#endif

#if defined(BOTAN_HAS_GMAC)
  #include <botan/gmac.h>
  #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_HMAC)
  #include <botan/hmac.h>
  #include <botan/hash.h>
#endif

#if defined(BOTAN_HAS_POLY1305)
  #include <botan/poly1305.h>
#endif

#if defined(BOTAN_HAS_SIPHASH)
  #include <botan/siphash.h>
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
  #include <botan/x919_mac.h>
#endif

#if defined(BOTAN_HAS_HKDF)
#include <botan/hkdf.h>
#endif

#if defined(BOTAN_HAS_KDF1)
#include <botan/kdf1.h>
#endif

#if defined(BOTAN_HAS_KDF2)
#include <botan/kdf2.h>
#endif

#if defined(BOTAN_HAS_KDF1_18033)
#include <botan/kdf1_iso18033.h>
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF) || defined(BOTAN_HAS_TLS_V12_PRF)
#include <botan/prf_tls.h>
#endif

#if defined(BOTAN_HAS_X942_PRF)
#include <botan/prf_x942.h>
#endif

#if defined(BOTAN_HAS_SP800_108)
#include <botan/sp800_108.h>
#endif

#if defined(BOTAN_HAS_SP800_56A)
#include <botan/sp800_56a.h>
#endif

#if defined(BOTAN_HAS_SP800_56C)
#include <botan/sp800_56c.h>
#endif

#if defined(BOTAN_HAS_ADLER32)
  #include <botan/adler32.h>
#endif

#if defined(BOTAN_HAS_CRC24)
  #include <botan/crc24.h>
#endif

#if defined(BOTAN_HAS_CRC32)
  #include <botan/crc32.h>
#endif

#if defined(BOTAN_HAS_GOST_34_11)
  #include <botan/gost_3411.h>
#endif

#if defined(BOTAN_HAS_KECCAK)
  #include <botan/keccak.h>
#endif

#if defined(BOTAN_HAS_MD4)
  #include <botan/md4.h>
#endif

#if defined(BOTAN_HAS_MD5)
  #include <botan/md5.h>
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
  #include <botan/rmd160.h>
#endif

#if defined(BOTAN_HAS_SHA1)
  #include <botan/sha160.h>
#endif

#if defined(BOTAN_HAS_SHA2_32)
  #include <botan/sha2_32.h>
#endif

#if defined(BOTAN_HAS_SHA2_64)
  #include <botan/sha2_64.h>
#endif

#if defined(BOTAN_HAS_SHA3)
  #include <botan/sha3.h>
#endif

#if defined(BOTAN_HAS_SKEIN_512)
  #include <botan/skein_512.h>
#endif

#if defined(BOTAN_HAS_SHAKE)
  #include <botan/shake.h>
#endif

#if defined(BOTAN_HAS_STREEBOG)
  #include <botan/streebog.h>
#endif

#if defined(BOTAN_HAS_SM3)
  #include <botan/sm3.h>
#endif

#if defined(BOTAN_HAS_TIGER)
  #include <botan/tiger.h>
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
  #include <botan/whrlpool.h>
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
  #include <botan/par_hash.h>
#endif

#if defined(BOTAN_HAS_COMB4P)
  #include <botan/comb4p.h>
#endif

#if defined(BOTAN_HAS_BLAKE2B)
  #include <botan/blake2b.h>
#endif

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