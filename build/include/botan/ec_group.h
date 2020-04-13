/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECC_DOMAIN_PARAMETERS_H_
#define BOTAN_ECC_DOMAIN_PARAMETERS_H_

#include <botan/point_gfp.h>
#include <botan/asn1_oid.h>
#include <botan/mutex.h>
#include <botan/internal/point_mul.h>
#ifndef SOUP_BUILD
#include <memory>
#include <set>
#endif

namespace Botan {

/**
* This class represents elliptic curce domain parameters
*/
enum EC_Group_Encoding {
   EC_DOMPAR_ENC_EXPLICIT = 0,
   EC_DOMPAR_ENC_IMPLICITCA = 1,
   EC_DOMPAR_ENC_OID = 2
};

class CurveGFp;

class EC_Group_Data;
class EC_Group_Data_Map;

/**
* Class representing an elliptic curve
*
* The internal representation is stored in a shared_ptr, so copying an
* EC_Group is inexpensive.
*/
class BOTAN_PUBLIC_API(2,0) EC_Group final
   {
   public:

      /**
      * Construct Domain paramers from specified parameters
      * @param curve elliptic curve
      * @param base_point a base point
      * @param order the order of the base point
      * @param cofactor the cofactor
      */
      BOTAN_DEPRECATED("Use version taking all BigInts")
      EC_Group(const CurveGFp& curve,
               const PointGFp& base_point,
               const BigInt& order,
               const BigInt& cofactor) :
         EC_Group(curve.get_p(),
                  curve.get_a(),
                  curve.get_b(),
                  base_point.get_affine_x(),
                  base_point.get_affine_y(),
                  order,
                  cofactor,
                  OID()) {}

      /**
      * Construct Domain paramers from specified parameters
      * @param p the elliptic curve p
      * @param a the elliptic curve a param
      * @param b the elliptic curve b param
      * @param base_x the x coordinate of the base point
      * @param base_y the y coordinate of the base point
      * @param order the order of the base point
      * @param cofactor the cofactor
      * @param oid an optional OID used to identify this curve
      */
      EC_Group(const BigInt& p,
               const BigInt& a,
               const BigInt& b,
               const BigInt& base_x,
               const BigInt& base_y,
               const BigInt& order,
               const BigInt& cofactor,
               const OID& oid);

      /**
      * Decode a BER encoded ECC domain parameter set
      * @param ber_encoding the bytes of the BER encoding
      */
      explicit EC_Group(const std::vector<uint8_t>& ber_encoding);

      /**
      * Create an EC domain by OID (or throw if unknown)
      * @param oid the OID of the EC domain to create
      */
      explicit EC_Group(const OID& oid);

      /**
      * Create an EC domain from PEM encoding (as from PEM_encode), or
      * from an OID name (eg "secp256r1", or "1.2.840.10045.3.1.7")
      * @param pem_or_oid PEM-encoded data, or an OID
      */
      explicit EC_Group(const std::string& pem_or_oid);

      /**
      * Create an uninitialized EC_Group
      */
      EC_Group();

      ~EC_Group();

      EC_Group(const EC_Group&) = default;
      EC_Group(EC_Group&&) = default;

      EC_Group& operator=(const EC_Group&) = default;
      EC_Group& operator=(EC_Group&&) = default;

      /**
      * Create the DER encoding of this domain
      * @param form of encoding to use
      * @returns bytes encododed as DER
      */
      std::vector<uint8_t> DER_encode(EC_Group_Encoding form) const;

      /**
      * Return the PEM encoding (always in explicit form)
      * @return string containing PEM data
      */
      std::string PEM_encode() const;

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      BOTAN_DEPRECATED("Avoid CurveGFp") const CurveGFp& get_curve() const;

      /**
      * Return if a == -3 mod p
      */
      bool a_is_minus_3() const;

      /**
      * Return if a == 0 mod p
      */
      bool a_is_zero() const;

      /**
      * Return the size of p in bits (same as get_p().bits())
      */
      size_t get_p_bits() const;

      /**
      * Return the size of p in bits (same as get_p().bytes())
      */
      size_t get_p_bytes() const;

      /**
      * Return the size of group order in bits (same as get_order().bits())
      */
      size_t get_order_bits() const;

      /**
      * Return the size of p in bytes (same as get_order().bytes())
      */
      size_t get_order_bytes() const;

      /**
      * Return the prime modulus of the field
      */
      const BigInt& get_p() const;

      /**
      * Return the a parameter of the elliptic curve equation
      */
      const BigInt& get_a() const;

      /**
      * Return the b parameter of the elliptic curve equation
      */
      const BigInt& get_b() const;

      /**
      * Return group base point
      * @result base point
      */
      const PointGFp& get_base_point() const;

      /**
      * Return the x coordinate of the base point
      */
      const BigInt& get_g_x() const;

      /**
      * Return the y coordinate of the base point
      */
      const BigInt& get_g_y() const;

      /**
      * Return the order of the base point
      * @result order of the base point
      */
      const BigInt& get_order() const;

      /*
      * Reduce x modulo the order
      */
      BigInt mod_order(const BigInt& x) const;

      /*
      * Return inverse of x modulo the order
      */
      BigInt inverse_mod_order(const BigInt& x) const;

      /*
      * Reduce (x*x) modulo the order
      */
      BigInt square_mod_order(const BigInt& x) const;

      /*
      * Reduce (x*y) modulo the order
      */
      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const;

      /*
      * Reduce (x*y*z) modulo the order
      */
      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const;

      /**
      * Return the cofactor
      * @result the cofactor
      */
      const BigInt& get_cofactor() const;

      /**
      * Check if y is a plausible point on the curve
      *
      * In particular, checks that it is a point on the curve, not infinity,
      * and that it has order matching the group.
      */
      bool verify_public_element(const PointGFp& y) const;

      /**
      * Return the OID of these domain parameters
      * @result the OID as a string
      */
      std::string BOTAN_DEPRECATED("Use get_curve_oid") get_oid() const { return get_curve_oid().to_string(); }

      /**
      * Return the OID of these domain parameters
      * @result the OID
      */
      const OID& get_curve_oid() const;

      /**
      * Return a point on this curve with the affine values x, y
      */
      PointGFp point(const BigInt& x, const BigInt& y) const;

      /**
      * Multi exponentiate. Not constant time.
      * @return base_point*x + pt*y
      */
      PointGFp point_multiply(const BigInt& x, const PointGFp& pt, const BigInt& y) const;

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * @param k the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return base_point*k
      */
      PointGFp blinded_base_point_multiply(const BigInt& k,
                                           RandomNumberGenerator& rng,
                                           std::vector<BigInt>& ws) const;

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * Returns just the x coordinate of the point
      *
      * @param k the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return x coordinate of base_point*k
      */
      BigInt blinded_base_point_multiply_x(const BigInt& k,
                                           RandomNumberGenerator& rng,
                                           std::vector<BigInt>& ws) const;

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * @param point input point
      * @param k the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return point*k
      */
      PointGFp blinded_var_point_multiply(const PointGFp& point,
                                          const BigInt& k,
                                          RandomNumberGenerator& rng,
                                          std::vector<BigInt>& ws) const;

      /**
      * Return a random scalar ie an integer in [1,order)
      */
      BigInt random_scalar(RandomNumberGenerator& rng) const;

      /**
      * Return the zero (or infinite) point on this curve
      */
      PointGFp zero_point() const;

      size_t point_size(PointGFp::Compression_Type format) const;

      PointGFp OS2ECP(const uint8_t* bits, size_t len) const;

      template<typename Alloc>
      PointGFp OS2ECP(const std::vector<uint8_t, Alloc>& vec) const
         {
         return this->OS2ECP(vec.data(), vec.size());
         }

      bool initialized() const { return (m_data != nullptr); }

      /**
       * Verify EC_Group domain
       * @returns true if group is valid. false otherwise
       */
      bool verify_group(RandomNumberGenerator& rng,
                        bool strong = false) const;

      bool operator==(const EC_Group& other) const;

      /**
      * Return PEM representation of named EC group
      * Deprecated: Use EC_Group(name).PEM_encode() if this is needed
      */
      static std::string BOTAN_DEPRECATED("See header comment") PEM_for_named_group(const std::string& name);

      /**
      * Return a set of known named EC groups
      */
      static const std::set<std::string>& known_named_groups();

      /*
      * For internal use only
      */
      static std::shared_ptr<EC_Group_Data> EC_group_info(const OID& oid);

      static size_t clear_registered_curve_data();

   private:
      static EC_Group_Data_Map& ec_group_data();

      static std::shared_ptr<EC_Group_Data> BER_decode_EC_group(const uint8_t* bits, size_t len);

      static std::shared_ptr<EC_Group_Data>
         load_EC_group_info(const char* p,
                            const char* a,
                            const char* b,
                            const char* g_x,
                            const char* g_y,
                            const char* order,
                            const OID& oid);

      // Member data
      const EC_Group_Data& data() const;
      std::shared_ptr<EC_Group_Data> m_data;
   };

inline bool operator!=(const EC_Group& lhs,
                       const EC_Group& rhs)
   {
   return !(lhs == rhs);
   }

// For compatibility with 1.8
typedef EC_Group EC_Domain_Params;


class EC_Group_Data final
   {
   public:

      EC_Group_Data(const BigInt& p,
                    const BigInt& a,
                    const BigInt& b,
                    const BigInt& g_x,
                    const BigInt& g_y,
                    const BigInt& order,
                    const BigInt& cofactor,
                    const OID& oid) :
         m_curve(p, a, b),
         m_base_point(m_curve, g_x, g_y),
         m_g_x(g_x),
         m_g_y(g_y),
         m_order(order),
         m_cofactor(cofactor),
         m_mod_order(order),
         m_base_mult(m_base_point, m_mod_order),
         m_oid(oid),
         m_p_bits(p.bits()),
         m_order_bits(order.bits()),
         m_a_is_minus_3(a == p - 3),
         m_a_is_zero(a.is_zero())
         {
         }

      bool match(const BigInt& p, const BigInt& a, const BigInt& b,
                 const BigInt& g_x, const BigInt& g_y,
                 const BigInt& order, const BigInt& cofactor) const
         {
         return (this->p() == p &&
                 this->a() == a &&
                 this->b() == b &&
                 this->order() == order &&
                 this->cofactor() == cofactor &&
                 this->g_x() == g_x &&
                 this->g_y() == g_y);
         }

      const OID& oid() const { return m_oid; }
      const BigInt& p() const { return m_curve.get_p(); }
      const BigInt& a() const { return m_curve.get_a(); }
      const BigInt& b() const { return m_curve.get_b(); }
      const BigInt& order() const { return m_order; }
      const BigInt& cofactor() const { return m_cofactor; }
      const BigInt& g_x() const { return m_g_x; }
      const BigInt& g_y() const { return m_g_y; }

      size_t p_bits() const { return m_p_bits; }
      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      size_t order_bits() const { return m_order_bits; }
      size_t order_bytes() const { return (m_order_bits + 7) / 8; }

      const CurveGFp& curve() const { return m_curve; }
      const PointGFp& base_point() const { return m_base_point; }

      bool a_is_minus_3() const { return m_a_is_minus_3; }
      bool a_is_zero() const { return m_a_is_zero; }

      BigInt mod_order(const BigInt& x) const { return m_mod_order.reduce(x); }

      BigInt square_mod_order(const BigInt& x) const
         {
         return m_mod_order.square(x);
         }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const
         {
         return m_mod_order.multiply(x, y);
         }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const
         {
         return m_mod_order.multiply(m_mod_order.multiply(x, y), z);
         }

      BigInt inverse_mod_order(const BigInt& x) const
         {
         return inverse_mod(x, m_order);
         }

      PointGFp blinded_base_point_multiply(const BigInt& k,
                                           RandomNumberGenerator& rng,
                                           std::vector<BigInt>& ws) const
         {
         return m_base_mult.mul(k, rng, m_order, ws);
         }

   private:
      CurveGFp m_curve;
      PointGFp m_base_point;

      BigInt m_g_x;
      BigInt m_g_y;
      BigInt m_order;
      BigInt m_cofactor;
      Modular_Reducer m_mod_order;
      PointGFp_Base_Point_Precompute m_base_mult;
      OID m_oid;
      size_t m_p_bits;
      size_t m_order_bits;
      bool m_a_is_minus_3;
      bool m_a_is_zero;
   };

class EC_Group_Data_Map final
   {
   public:
      EC_Group_Data_Map() {}

      size_t clear()
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         size_t count = m_registered_curves.size();
         m_registered_curves.clear();
         return count;
         }

      std::shared_ptr<EC_Group_Data> lookup(const OID& oid)
         {
         lock_guard_type<mutex_type> lock(m_mutex);

         for(auto i : m_registered_curves)
            {
            if(i->oid() == oid)
               return i;
            }

         // Not found, check hardcoded data
         std::shared_ptr<EC_Group_Data> data = EC_Group::EC_group_info(oid);

         if(data)
            {
            m_registered_curves.push_back(data);
            return data;
            }

         // Nope, unknown curve
         return std::shared_ptr<EC_Group_Data>();
         }

      std::shared_ptr<EC_Group_Data> lookup_or_create(const BigInt& p,
                                                      const BigInt& a,
                                                      const BigInt& b,
                                                      const BigInt& g_x,
                                                      const BigInt& g_y,
                                                      const BigInt& order,
                                                      const BigInt& cofactor,
                                                      const OID& oid)
         {
         lock_guard_type<mutex_type> lock(m_mutex);

         for(auto i : m_registered_curves)
            {
            if(oid.has_value())
               {
               if(i->oid() == oid)
                  return i;
               else if(i->oid().has_value())
                  continue;
               }

            if(i->match(p, a, b, g_x, g_y, order, cofactor))
               return i;
            }

         // Not found - if OID is set try looking up that way

         if(oid.has_value())
            {
            // Not located in existing store - try hardcoded data set
            std::shared_ptr<EC_Group_Data> data = EC_Group::EC_group_info(oid);

            if(data)
               {
               m_registered_curves.push_back(data);
               return data;
               }
            }

         // Not found or no OID, add data and return
         return add_curve(p, a, b, g_x, g_y, order, cofactor, oid);
         }

   private:

      std::shared_ptr<EC_Group_Data> add_curve(const BigInt& p,
                                               const BigInt& a,
                                               const BigInt& b,
                                               const BigInt& g_x,
                                               const BigInt& g_y,
                                               const BigInt& order,
                                               const BigInt& cofactor,
                                               const OID& oid)
         {
         std::shared_ptr<EC_Group_Data> d =
            std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, cofactor, oid);

         // This function is always called with the lock held
         m_registered_curves.push_back(d);
         return d;
         }

      mutex_type m_mutex;
      std::vector<std::shared_ptr<EC_Group_Data>> m_registered_curves;
   };

}

#endif
