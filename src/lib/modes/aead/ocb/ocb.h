/*
* OCB Mode
* (C) 2013,2014 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_OCB_H_
#define BOTAN_AEAD_OCB_H_

#include <botan/aead.h>

BOTAN_FUTURE_INTERNAL_HEADER(ocb.h)

namespace Botan {

class BlockCipher;

// Has to be in Botan namespace so unique_ptr can reference it
class L_computer final
   {
   public:
      explicit L_computer(const BlockCipher& cipher) :
         m_BS(cipher.block_size()),
         m_max_blocks(cipher.parallel_bytes() / m_BS)
         {
         m_L_star.resize(m_BS);
         cipher.encrypt(m_L_star);
         m_L_dollar = poly_double(star());
         m_L.push_back(poly_double(dollar()));

         while(m_L.size() < 8)
            m_L.push_back(poly_double(m_L.back()));

         m_offset_buf.resize(m_BS * m_max_blocks);
         }

      void init(const secure_vector<uint8_t>& offset)
         {
         m_offset = offset;
         }

      bool initialized() const { return m_offset.empty() == false; }

      const secure_vector<uint8_t>& star() const { return m_L_star; }
      const secure_vector<uint8_t>& dollar() const { return m_L_dollar; }
      const secure_vector<uint8_t>& offset() const { return m_offset; }

      const secure_vector<uint8_t>& get(size_t i) const
         {
         while(m_L.size() <= i)
            m_L.push_back(poly_double(m_L.back()));

         return m_L[i];
         }

      const uint8_t*
      compute_offsets(size_t block_index, size_t blocks)
         {
         BOTAN_ASSERT(blocks <= m_max_blocks, "OCB offsets");

         uint8_t* offsets = m_offset_buf.data();

         if(block_index % 4 == 0)
            {
            const secure_vector<uint8_t>& L0 = get(0);
            const secure_vector<uint8_t>& L1 = get(1);

            while(blocks >= 4)
               {
               // ntz(4*i+1) == 0
               // ntz(4*i+2) == 1
               // ntz(4*i+3) == 0
               block_index += 4;
               const size_t ntz4 = var_ctz32(static_cast<uint32_t>(block_index));

               xor_buf(offsets, m_offset.data(), L0.data(), m_BS);
               offsets += m_BS;

               xor_buf(offsets, offsets - m_BS, L1.data(), m_BS);
               offsets += m_BS;

               xor_buf(m_offset.data(), L1.data(), m_BS);
               copy_mem(offsets, m_offset.data(), m_BS);
               offsets += m_BS;

               xor_buf(m_offset.data(), get(ntz4).data(), m_BS);
               copy_mem(offsets, m_offset.data(), m_BS);
               offsets += m_BS;

               blocks -= 4;
               }
            }

         for(size_t i = 0; i != blocks; ++i)
            { // could be done in parallel
            const size_t ntz = var_ctz32(static_cast<uint32_t>(block_index + i + 1));
            xor_buf(m_offset.data(), get(ntz).data(), m_BS);
            copy_mem(offsets, m_offset.data(), m_BS);
            offsets += m_BS;
            }

         return m_offset_buf.data();
         }

   private:
      secure_vector<uint8_t> poly_double(const secure_vector<uint8_t>& in) const
         {
         secure_vector<uint8_t> out(in.size());
         poly_double_n(out.data(), in.data(), out.size());
         return out;
         }

      const size_t m_BS, m_max_blocks;
      secure_vector<uint8_t> m_L_dollar, m_L_star;
      secure_vector<uint8_t> m_offset;
      mutable std::vector<secure_vector<uint8_t>> m_L;
      secure_vector<uint8_t> m_offset_buf;
   };

/**
* OCB Mode (base class for OCB_Encryption and OCB_Decryption). Note
* that OCB is patented, but is freely licensed in some circumstances.
*
* @see "The OCB Authenticated-Encryption Algorithm" RFC 7253
*      https://tools.ietf.org/html/rfc7253
* @see "OCB For Block Ciphers Without 128-Bit Blocks"
*      (draft-krovetz-ocb-wide-d3) for the extension of OCB to
*      block ciphers with larger block sizes.
* @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
* @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
*/
class BOTAN_PUBLIC_API(2,0) OCB_Mode : public AEAD_Mode
   {
   public:
      void set_associated_data(const uint8_t ad[], size_t ad_len) override;

      std::string name() const override;

      size_t update_granularity() const override;

      Key_Length_Specification key_spec() const override;

      bool valid_nonce_length(size_t) const override;

      size_t tag_size() const override { return m_tag_size; }

      void clear() override;

      void reset() override;

      ~OCB_Mode();
   protected:
      /**
      * @param cipher the block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Mode(BlockCipher* cipher, size_t tag_size);

      size_t block_size() const { return m_block_size; }
      size_t par_blocks() const { return m_par_blocks; }
      size_t par_bytes() const { return m_checksum.size(); }

      // fixme make these private
      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<L_computer> m_L;

      size_t m_block_index = 0;

      secure_vector<uint8_t> m_checksum;
      secure_vector<uint8_t> m_ad_hash;
   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;

      void key_schedule(const uint8_t key[], size_t length) override;

      const secure_vector<uint8_t>& update_nonce(const uint8_t nonce[], size_t nonce_len);

      const size_t m_tag_size;
      const size_t m_block_size;
      const size_t m_par_blocks;
      secure_vector<uint8_t> m_last_nonce;
      secure_vector<uint8_t> m_stretch;
      secure_vector<uint8_t> m_nonce_buf;
      secure_vector<uint8_t> m_offset;
   };

class BOTAN_PUBLIC_API(2,0) OCB_Encryption final : public OCB_Mode
   {
   public:
      /**
      * @param cipher the block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Encryption(BlockCipher* cipher, size_t tag_size = 16) :
         OCB_Mode(cipher, tag_size) {}

      size_t output_length(size_t input_length) const override
         { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }

      size_t process(uint8_t buf[], size_t size) override;

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
   private:
      void encrypt(uint8_t input[], size_t blocks);
   };

class BOTAN_PUBLIC_API(2,0) OCB_Decryption final : public OCB_Mode
   {
   public:
      /**
      * @param cipher the block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Decryption(BlockCipher* cipher, size_t tag_size = 16) :
         OCB_Mode(cipher, tag_size) {}

      size_t output_length(size_t input_length) const override
         {
         BOTAN_ASSERT(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
         }

      size_t minimum_final_size() const override { return tag_size(); }

      size_t process(uint8_t buf[], size_t size) override;

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
   private:
      void decrypt(uint8_t input[], size_t blocks);
   };

}

#endif
