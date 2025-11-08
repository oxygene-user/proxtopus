#include "pch.h"
#if FEATURE_TLS

namespace Botan {

    namespace
    {
        /*oids-start*/
        const uint8_t oids[] = {
             0x28, 0xf4, 0x28, 0x03, 0x00, 0x05, // 1.0.14888.3.0.5
             0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11, // 1.2.156.10197.1.401
             0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78, // 1.2.156.10197.1.504
             0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x44, 0x01, 0x64, 0x04, 0x03, // 1.2.410.200004.1.100.4.3
             0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x44, 0x01, 0x64, 0x04, 0x04, // 1.2.410.200004.1.100.4.4
             0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x44, 0x01, 0x64, 0x04, 0x05, // 1.2.410.200004.1.100.4.5
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, // 1.2.840.113549.1.1.5
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, // 1.2.840.113549.1.1.8
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, // 1.2.840.113549.1.1.10
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, // 1.2.840.113549.1.1.11
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, // 1.2.840.113549.1.1.12
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, // 1.2.840.113549.1.1.13
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e, // 1.2.840.113549.1.1.14
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x10, // 1.2.840.113549.1.1.16
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, // 1.2.840.113549.1.9.1
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x12, // 1.2.840.113549.1.9.16.3.18
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07, // 1.2.840.113549.2.7
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08, // 1.2.840.113549.2.8
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09, // 1.2.840.113549.2.9
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a, // 1.2.840.113549.2.10
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b, // 1.2.840.113549.2.11
             0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d, // 1.2.840.113549.2.13
             0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01, // 1.2.840.10040.4.1
             0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03, // 1.2.840.10040.4.3
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, // 1.2.840.10045.1.1
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01, // 1.2.840.10045.4.1
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01, // 1.2.840.10045.4.3.1
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, // 1.2.840.10045.4.3.2
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, // 1.2.840.10045.4.3.3
             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, // 1.2.840.10045.4.3.4
             0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01, // 1.2.840.10046.2.1
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, // 1.3.6.1.5.5.7.1.1
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1a, // 1.3.6.1.5.5.7.1.26
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, // 1.3.6.1.5.5.7.3.1
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, // 1.3.6.1.5.5.7.3.2
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, // 1.3.6.1.5.5.7.3.9
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, // 1.3.6.1.5.5.7.48.1
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, // 1.3.6.1.5.5.7.48.1.1
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05, // 1.3.6.1.5.5.7.48.1.5
             0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, // 1.3.6.1.5.5.7.48.2
             0x2b, 0x0e, 0x03, 0x02, 0x1a, // 1.3.14.3.2.26
             0x2b, 0x24, 0x03, 0x02, 0x01, // 1.3.36.3.2.1
             0x2b, 0x24, 0x03, 0x03, 0x01, 0x02, // 1.3.36.3.3.1.2
             0x2b, 0x24, 0x03, 0x03, 0x02, 0x05, 0x02, 0x01, // 1.3.36.3.3.2.5.2.1
             0x2b, 0x24, 0x03, 0x03, 0x02, 0x05, 0x04, 0x01, // 1.3.36.3.3.2.5.4.1
             0x2b, 0x24, 0x03, 0x03, 0x02, 0x05, 0x04, 0x02, // 1.3.36.3.3.2.5.4.2
             0x2b, 0x24, 0x03, 0x03, 0x02, 0x05, 0x04, 0x03, // 1.3.36.3.3.2.5.4.3
             0x2b, 0x24, 0x03, 0x03, 0x02, 0x05, 0x04, 0x04, // 1.3.36.3.3.2.5.4.4
             0x2b, 0x24, 0x03, 0x03, 0x02, 0x05, 0x04, 0x05, // 1.3.36.3.3.2.5.4.5
             0x2b, 0x24, 0x03, 0x03, 0x02, 0x05, 0x04, 0x06, // 1.3.36.3.3.2.5.4.6
             0x2b, 0x65, 0x6e, // 1.3.101.110
             0x2b, 0x65, 0x6f, // 1.3.101.111
             0x2b, 0x65, 0x70, // 1.3.101.112
             0x2b, 0x81, 0x04, 0x00, 0x21, // 1.3.132.0.33
             0x2b, 0x81, 0x04, 0x00, 0x22, // 1.3.132.0.34
             0x2b, 0x81, 0x04, 0x00, 0x23, // 1.3.132.0.35
             0x2b, 0x81, 0x04, 0x01, 0x0c, // 1.3.132.1.12
             0x55, 0x04, 0x03, // 2.5.4.3
             0x55, 0x04, 0x05, // 2.5.4.5
             0x55, 0x04, 0x06, // 2.5.4.6
             0x55, 0x04, 0x07, // 2.5.4.7
             0x55, 0x04, 0x08, // 2.5.4.8
             0x55, 0x04, 0x0a, // 2.5.4.10
             0x55, 0x04, 0x0b, // 2.5.4.11
             0x55, 0x1d, 0x0e, // 2.5.29.14
             0x55, 0x1d, 0x0f, // 2.5.29.15
             0x55, 0x1d, 0x11, // 2.5.29.17
             0x55, 0x1d, 0x12, // 2.5.29.18
             0x55, 0x1d, 0x13, // 2.5.29.19
             0x55, 0x1d, 0x14, // 2.5.29.20
             0x55, 0x1d, 0x15, // 2.5.29.21
             0x55, 0x1d, 0x1c, // 2.5.29.28
             0x55, 0x1d, 0x1e, // 2.5.29.30
             0x55, 0x1d, 0x1f, // 2.5.29.31
             0x55, 0x1d, 0x20, // 2.5.29.32
             0x55, 0x1d, 0x23, // 2.5.29.35
             0x55, 0x1d, 0x25, // 2.5.29.37
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02, // 2.16.840.1.101.3.4.1.2
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06, // 2.16.840.1.101.3.4.1.6
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a, // 2.16.840.1.101.3.4.1.42
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e, // 2.16.840.1.101.3.4.1.46
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // 2.16.840.1.101.3.4.2.1
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, // 2.16.840.1.101.3.4.2.2
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, // 2.16.840.1.101.3.4.2.3
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, // 2.16.840.1.101.3.4.2.4
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, // 2.16.840.1.101.3.4.2.6
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, // 2.16.840.1.101.3.4.2.7
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, // 2.16.840.1.101.3.4.2.8
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, // 2.16.840.1.101.3.4.2.9
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, // 2.16.840.1.101.3.4.2.10
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01, // 2.16.840.1.101.3.4.3.1
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02, // 2.16.840.1.101.3.4.3.2
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03, // 2.16.840.1.101.3.4.3.3
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04, // 2.16.840.1.101.3.4.3.4
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x05, // 2.16.840.1.101.3.4.3.5
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x06, // 2.16.840.1.101.3.4.3.6
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x07, // 2.16.840.1.101.3.4.3.7
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x08, // 2.16.840.1.101.3.4.3.8
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09, // 2.16.840.1.101.3.4.3.9
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0a, // 2.16.840.1.101.3.4.3.10
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0b, // 2.16.840.1.101.3.4.3.11
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0c, // 2.16.840.1.101.3.4.3.12
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0d, // 2.16.840.1.101.3.4.3.13
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0e, // 2.16.840.1.101.3.4.3.14
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0f, // 2.16.840.1.101.3.4.3.15
             0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10, // 2.16.840.1.101.3.4.3.16
        };
        /*oids-end*/

#if 0
        consteval std::span<const uint8_t> t2id(const char* ids)
        {
            //constexpr int N = ids[3];


            return std::span(oids, ids[0] - '0');
        }
#endif
        //Algo_Group t2a(const char*)
        //{
        //    return Algo_Group();
        //}

    }

u8 g_oids_by_algs[static_cast<size_t>(oid_index::_count)] = {
    /*sorted_ba_start*/
    static_cast<u8>(oid_index::_1_3_14_3_2_26),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_1),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_2),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_4),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_3),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_6),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_7),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_8),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_9),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_2_10),
    static_cast<u8>(oid_index::_1_3_36_3_2_1),
    static_cast<u8>(oid_index::_1_2_156_10197_1_401),
    static_cast<u8>(oid_index::_1_2_840_10046_2_1),
    static_cast<u8>(oid_index::_1_3_132_1_12),
    static_cast<u8>(oid_index::_1_3_101_110),
    static_cast<u8>(oid_index::_1_3_101_111),
    static_cast<u8>(oid_index::_1_2_840_10040_4_1),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_1),
    static_cast<u8>(oid_index::_1_2_840_10045_2_1),
    static_cast<u8>(oid_index::_1_3_36_3_3_2_5_2_1),
    static_cast<u8>(oid_index::_1_0_14888_3_0_5),
    static_cast<u8>(oid_index::_1_3_101_112),
    static_cast<u8>(oid_index::_1_2_840_113549_1_9_16_3_18),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_1_6),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_1_46),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_1_2),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_1_42),
    static_cast<u8>(oid_index::_1_2_840_10045_3_1_7),
    static_cast<u8>(oid_index::_1_3_132_0_33),
    static_cast<u8>(oid_index::_1_3_132_0_34),
    static_cast<u8>(oid_index::_1_3_132_0_35),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_8),
    static_cast<u8>(oid_index::_1_2_840_10045_1_1),
    static_cast<u8>(oid_index::_2_5_29_19),
    static_cast<u8>(oid_index::_2_5_29_15),
    static_cast<u8>(oid_index::_2_5_29_14),
    static_cast<u8>(oid_index::_2_5_29_35),
    static_cast<u8>(oid_index::_2_5_29_17),
    static_cast<u8>(oid_index::_2_5_29_18),
    static_cast<u8>(oid_index::_2_5_29_37),
    static_cast<u8>(oid_index::_2_5_29_30),
    static_cast<u8>(oid_index::_2_5_29_32),
    static_cast<u8>(oid_index::_2_5_29_20),
    static_cast<u8>(oid_index::_2_5_29_21),
    static_cast<u8>(oid_index::_2_5_29_31),
    static_cast<u8>(oid_index::_2_5_29_28),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_1_1),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_48_1_5),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_1_26),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_3_1),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_3_2),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_3_9),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_48_1),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_48_1_1),
    static_cast<u8>(oid_index::_1_3_6_1_5_5_7_48_2),
    static_cast<u8>(oid_index::_1_2_840_113549_1_9_1),
    static_cast<u8>(oid_index::_2_5_4_3),
    static_cast<u8>(oid_index::_2_5_4_5),
    static_cast<u8>(oid_index::_2_5_4_6),
    static_cast<u8>(oid_index::_2_5_4_10),
    static_cast<u8>(oid_index::_2_5_4_11),
    static_cast<u8>(oid_index::_2_5_4_7),
    static_cast<u8>(oid_index::_2_5_4_8),
    static_cast<u8>(oid_index::_1_2_840_10040_4_3),
    static_cast<u8>(oid_index::_1_2_840_10045_4_1),
    static_cast<u8>(oid_index::_1_3_36_3_3_2_5_4_2),
    static_cast<u8>(oid_index::_1_2_410_200004_1_100_4_3),
    static_cast<u8>(oid_index::_1_2_840_113549_2_7),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_2),
    static_cast<u8>(oid_index::_1_2_840_10045_4_3_2),
    static_cast<u8>(oid_index::_1_3_36_3_3_2_5_4_4),
    static_cast<u8>(oid_index::_1_2_410_200004_1_100_4_5),
    static_cast<u8>(oid_index::_1_2_840_113549_2_9),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_3),
    static_cast<u8>(oid_index::_1_2_840_10045_4_3_3),
    static_cast<u8>(oid_index::_1_3_36_3_3_2_5_4_5),
    static_cast<u8>(oid_index::_1_2_840_113549_2_10),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_1),
    static_cast<u8>(oid_index::_1_2_840_10045_4_3_1),
    static_cast<u8>(oid_index::_1_3_36_3_3_2_5_4_3),
    static_cast<u8>(oid_index::_1_2_410_200004_1_100_4_4),
    static_cast<u8>(oid_index::_1_2_840_113549_2_8),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_4),
    static_cast<u8>(oid_index::_1_2_840_10045_4_3_4),
    static_cast<u8>(oid_index::_1_3_36_3_3_2_5_4_6),
    static_cast<u8>(oid_index::_1_2_840_113549_2_11),
    static_cast<u8>(oid_index::_1_2_840_113549_2_13),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_5),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_9),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_6),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_10),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_7),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_11),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_8),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_12),
    static_cast<u8>(oid_index::_1_3_36_3_3_2_5_4_1),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_10),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_5),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_11),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_12),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_14),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_13),
    static_cast<u8>(oid_index::_1_2_840_113549_1_1_16),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_13),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_14),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_15),
    static_cast<u8>(oid_index::_2_16_840_1_101_3_4_3_16),
    static_cast<u8>(oid_index::_1_3_36_3_3_1_2),
    static_cast<u8>(oid_index::_1_2_156_10197_1_504),
    /*sorted_ba_end*/
};

OID_core g_oids[] = {

    { std::span<const u8>(), Algo_Group() },

    /*sorted_start*/
    { std::span(oids+0, 6) /*oid*/ /*1.0.14888.3.0.5*/, Algo_Group(ALG::ECKCDSA)},
    { std::span(oids+6, 8) /*oid*/ /*1.2.156.10197.1.401*/, Algo_Group(ALG::SM3)},
    { std::span(oids+14, 8) /*oid*/ /*1.2.156.10197.1.504*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SM3)},
    { std::span(oids+22, 10) /*oid*/ /*1.2.410.200004.1.100.4.3*/, Algo_Group(ALG::ECKCDSA, ALG::SHA_1)},
    { std::span(oids+32, 10) /*oid*/ /*1.2.410.200004.1.100.4.4*/, Algo_Group(ALG::ECKCDSA, ALG::SHA_224)},
    { std::span(oids+42, 10) /*oid*/ /*1.2.410.200004.1.100.4.5*/, Algo_Group(ALG::ECKCDSA, ALG::SHA_256)},
    { std::span(oids+52, 9) /*oid*/ /*1.2.840.113549.1.1.1*/, Algo_Group(ALG::RSA)},
    { std::span(oids+61, 9) /*oid*/ /*1.2.840.113549.1.1.5*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_1)},
    { std::span(oids+70, 9) /*oid*/ /*1.2.840.113549.1.1.8*/, Algo_Group(ALG::MGF1)},
    { std::span(oids+79, 9) /*oid*/ /*1.2.840.113549.1.1.10*/, Algo_Group(ALG::RSA, ALG::EMSA4)},
    { std::span(oids+88, 9) /*oid*/ /*1.2.840.113549.1.1.11*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_256)},
    { std::span(oids+97, 9) /*oid*/ /*1.2.840.113549.1.1.12*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_384)},
    { std::span(oids+106, 9) /*oid*/ /*1.2.840.113549.1.1.13*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_512)},
    { std::span(oids+115, 9) /*oid*/ /*1.2.840.113549.1.1.14*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_224)},
    { std::span(oids+124, 9) /*oid*/ /*1.2.840.113549.1.1.16*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_512_256)},
    { std::span(oids+133, 9) /*oid*/ /*1.2.840.113549.1.9.1*/, Algo_Group(ALG::PKCS9_EmailAddress)},
    { std::span(oids+142, 11) /*oid*/ /*1.2.840.113549.1.9.16.3.18*/, Algo_Group(ALG::CHACHA20_POLY1305)},
    { std::span(oids+153, 8) /*oid*/ /*1.2.840.113549.2.7*/, Algo_Group(ALG::HMAC, ALG::SHA_1)},
    { std::span(oids+161, 8) /*oid*/ /*1.2.840.113549.2.8*/, Algo_Group(ALG::HMAC, ALG::SHA_224)},
    { std::span(oids+169, 8) /*oid*/ /*1.2.840.113549.2.9*/, Algo_Group(ALG::HMAC, ALG::SHA_256)},
    { std::span(oids+177, 8) /*oid*/ /*1.2.840.113549.2.10*/, Algo_Group(ALG::HMAC, ALG::SHA_384)},
    { std::span(oids+185, 8) /*oid*/ /*1.2.840.113549.2.11*/, Algo_Group(ALG::HMAC, ALG::SHA_512)},
    { std::span(oids+193, 8) /*oid*/ /*1.2.840.113549.2.13*/, Algo_Group(ALG::HMAC, ALG::SHA_512_256)},
    { std::span(oids+201, 7) /*oid*/ /*1.2.840.10040.4.1*/, Algo_Group(ALG::DSA)},
    { std::span(oids+208, 7) /*oid*/ /*1.2.840.10040.4.3*/, Algo_Group(ALG::DSA, ALG::SHA_1)},
    { std::span(oids+215, 7) /*oid*/ /*1.2.840.10045.1.1*/, Algo_Group(ALG::id_prime_Field)},
    { std::span(oids+222, 7) /*oid*/ /*1.2.840.10045.2.1*/, Algo_Group(ALG::ECDSA)},
    { std::span(oids+229, 8) /*oid*/ /*1.2.840.10045.3.1.7*/, Algo_Group(ALG::secp256r1)},
    { std::span(oids+237, 7) /*oid*/ /*1.2.840.10045.4.1*/, Algo_Group(ALG::ECDSA, ALG::SHA_1)},
    { std::span(oids+244, 8) /*oid*/ /*1.2.840.10045.4.3.1*/, Algo_Group(ALG::ECDSA, ALG::SHA_224)},
    { std::span(oids+252, 8) /*oid*/ /*1.2.840.10045.4.3.2*/, Algo_Group(ALG::ECDSA, ALG::SHA_256)},
    { std::span(oids+260, 8) /*oid*/ /*1.2.840.10045.4.3.3*/, Algo_Group(ALG::ECDSA, ALG::SHA_384)},
    { std::span(oids+268, 8) /*oid*/ /*1.2.840.10045.4.3.4*/, Algo_Group(ALG::ECDSA, ALG::SHA_512)},
    { std::span(oids+276, 7) /*oid*/ /*1.2.840.10046.2.1*/, Algo_Group(ALG::DH)},
    { std::span(oids+283, 8) /*oid*/ /*1.3.6.1.5.5.7.1.1*/, Algo_Group(ALG::PKIX_AuthorityInformationAccess)},
    { std::span(oids+291, 8) /*oid*/ /*1.3.6.1.5.5.7.1.26*/, Algo_Group(ALG::PKIX_TNAuthList)},
    { std::span(oids+299, 8) /*oid*/ /*1.3.6.1.5.5.7.3.1*/, Algo_Group(ALG::PKIX_ServerAuth)},
    { std::span(oids+307, 8) /*oid*/ /*1.3.6.1.5.5.7.3.2*/, Algo_Group(ALG::PKIX_ClientAuth)},
    { std::span(oids+315, 8) /*oid*/ /*1.3.6.1.5.5.7.3.9*/, Algo_Group(ALG::PKIX_OCSPSigning)},
    { std::span(oids+323, 8) /*oid*/ /*1.3.6.1.5.5.7.48.1*/, Algo_Group(ALG::PKIX_OCSP)},
    { std::span(oids+331, 9) /*oid*/ /*1.3.6.1.5.5.7.48.1.1*/, Algo_Group(ALG::PKIX_OCSP_BasicResponse)},
    { std::span(oids+340, 9) /*oid*/ /*1.3.6.1.5.5.7.48.1.5*/, Algo_Group(ALG::PKIX_OCSP_NoCheck)},
    { std::span(oids+349, 8) /*oid*/ /*1.3.6.1.5.5.7.48.2*/, Algo_Group(ALG::PKIX_CertificateAuthorityIssuers)},
    { std::span(oids+357, 5) /*oid*/ /*1.3.14.3.2.26*/, Algo_Group(ALG::SHA_1)},
    { std::span(oids+362, 5) /*oid*/ /*1.3.36.3.2.1*/, Algo_Group(ALG::RIPEMD_160)},
    { std::span(oids+367, 6) /*oid*/ /*1.3.36.3.3.1.2*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::RIPEMD_160)},
    { std::span(oids+373, 8) /*oid*/ /*1.3.36.3.3.2.5.2.1*/, Algo_Group(ALG::ECGDSA)},
    { std::span(oids+381, 8) /*oid*/ /*1.3.36.3.3.2.5.4.1*/, Algo_Group(ALG::ECGDSA, ALG::RIPEMD_160)},
    { std::span(oids+389, 8) /*oid*/ /*1.3.36.3.3.2.5.4.2*/, Algo_Group(ALG::ECGDSA, ALG::SHA_1)},
    { std::span(oids+397, 8) /*oid*/ /*1.3.36.3.3.2.5.4.3*/, Algo_Group(ALG::ECGDSA, ALG::SHA_224)},
    { std::span(oids+405, 8) /*oid*/ /*1.3.36.3.3.2.5.4.4*/, Algo_Group(ALG::ECGDSA, ALG::SHA_256)},
    { std::span(oids+413, 8) /*oid*/ /*1.3.36.3.3.2.5.4.5*/, Algo_Group(ALG::ECGDSA, ALG::SHA_384)},
    { std::span(oids+421, 8) /*oid*/ /*1.3.36.3.3.2.5.4.6*/, Algo_Group(ALG::ECGDSA, ALG::SHA_512)},
    { std::span(oids+429, 3) /*oid*/ /*1.3.101.110*/, Algo_Group(ALG::X25519)},
    { std::span(oids+432, 3) /*oid*/ /*1.3.101.111*/, Algo_Group(ALG::X448)},
    { std::span(oids+435, 3) /*oid*/ /*1.3.101.112*/, Algo_Group(ALG::Ed25519)},
    { std::span(oids+438, 5) /*oid*/ /*1.3.132.0.33*/, Algo_Group(ALG::secp224r1)},
    { std::span(oids+443, 5) /*oid*/ /*1.3.132.0.34*/, Algo_Group(ALG::secp384r1)},
    { std::span(oids+448, 5) /*oid*/ /*1.3.132.0.35*/, Algo_Group(ALG::secp521r1)},
    { std::span(oids+453, 5) /*oid*/ /*1.3.132.1.12*/, Algo_Group(ALG::ECDH)},
    { std::span(oids+458, 3) /*oid*/ /*2.5.4.3*/, Algo_Group(ALG::X520_CommonName)},
    { std::span(oids+461, 3) /*oid*/ /*2.5.4.5*/, Algo_Group(ALG::X520_SerialNumber)},
    { std::span(oids+464, 3) /*oid*/ /*2.5.4.6*/, Algo_Group(ALG::X520_Country)},
    { std::span(oids+467, 3) /*oid*/ /*2.5.4.7*/, Algo_Group(ALG::X520_Locality)},
    { std::span(oids+470, 3) /*oid*/ /*2.5.4.8*/, Algo_Group(ALG::X520_State)},
    { std::span(oids+473, 3) /*oid*/ /*2.5.4.10*/, Algo_Group(ALG::X520_Organization)},
    { std::span(oids+476, 3) /*oid*/ /*2.5.4.11*/, Algo_Group(ALG::X520_OrganizationalUnit)},
    { std::span(oids+479, 3) /*oid*/ /*2.5.29.14*/, Algo_Group(ALG::X509v3_SubjectKeyIdentifier)},
    { std::span(oids+482, 3) /*oid*/ /*2.5.29.15*/, Algo_Group(ALG::X509v3_KeyUsage)},
    { std::span(oids+485, 3) /*oid*/ /*2.5.29.17*/, Algo_Group(ALG::X509v3_SubjectAlternativeName)},
    { std::span(oids+488, 3) /*oid*/ /*2.5.29.18*/, Algo_Group(ALG::X509v3_IssuerAlternativeName)},
    { std::span(oids+491, 3) /*oid*/ /*2.5.29.19*/, Algo_Group(ALG::X509v3_BasicConstraints)},
    { std::span(oids+494, 3) /*oid*/ /*2.5.29.20*/, Algo_Group(ALG::X509v3_CRLNumber)},
    { std::span(oids+497, 3) /*oid*/ /*2.5.29.21*/, Algo_Group(ALG::X509v3_ReasonCode)},
    { std::span(oids+500, 3) /*oid*/ /*2.5.29.28*/, Algo_Group(ALG::X509v3_CRLIssuingDistributionPoint)},
    { std::span(oids+503, 3) /*oid*/ /*2.5.29.30*/, Algo_Group(ALG::X509v3_NameConstraints)},
    { std::span(oids+506, 3) /*oid*/ /*2.5.29.31*/, Algo_Group(ALG::X509v3_CRLDistributionPoints)},
    { std::span(oids+509, 3) /*oid*/ /*2.5.29.32*/, Algo_Group(ALG::X509v3_CertificatePolicies)},
    { std::span(oids+512, 3) /*oid*/ /*2.5.29.35*/, Algo_Group(ALG::X509v3_AuthorityKeyIdentifier)},
    { std::span(oids+515, 3) /*oid*/ /*2.5.29.37*/, Algo_Group(ALG::X509v3_ExtendedKeyUsage)},
    { std::span(oids+518, 9) /*oid*/ /*2.16.840.1.101.3.4.1.2*/, Algo_Group(ALG::AES_128_CBC)},
    { std::span(oids+527, 9) /*oid*/ /*2.16.840.1.101.3.4.1.6*/, Algo_Group(ALG::AES_128_GCM)},
    { std::span(oids+536, 9) /*oid*/ /*2.16.840.1.101.3.4.1.42*/, Algo_Group(ALG::AES_256_CBC) },
    { std::span(oids+545, 9) /*oid*/ /*2.16.840.1.101.3.4.1.46*/, Algo_Group(ALG::AES_256_GCM)},
    { std::span(oids+554, 9) /*oid*/ /*2.16.840.1.101.3.4.2.1*/, Algo_Group(ALG::SHA_256)},
    { std::span(oids+563, 9) /*oid*/ /*2.16.840.1.101.3.4.2.2*/, Algo_Group(ALG::SHA_384)},
    { std::span(oids+572, 9) /*oid*/ /*2.16.840.1.101.3.4.2.3*/, Algo_Group(ALG::SHA_512)},
    { std::span(oids+581, 9) /*oid*/ /*2.16.840.1.101.3.4.2.4*/, Algo_Group(ALG::SHA_224)},
    { std::span(oids+590, 9) /*oid*/ /*2.16.840.1.101.3.4.2.6*/, Algo_Group(ALG::SHA_512_256)},
    { std::span(oids+599, 9) /*oid*/ /*2.16.840.1.101.3.4.2.7*/, Algo_Group(ALG::SHA_3_224)},
    { std::span(oids+608, 9) /*oid*/ /*2.16.840.1.101.3.4.2.8*/, Algo_Group(ALG::SHA_3_256)},
    { std::span(oids+617, 9) /*oid*/ /*2.16.840.1.101.3.4.2.9*/, Algo_Group(ALG::SHA_3_384)},
    { std::span(oids+626, 9) /*oid*/ /*2.16.840.1.101.3.4.2.10*/, Algo_Group(ALG::SHA_3_512)},
    { std::span(oids+635, 9) /*oid*/ /*2.16.840.1.101.3.4.3.1*/, Algo_Group(ALG::DSA, ALG::SHA_224)},
    { std::span(oids+644, 9) /*oid*/ /*2.16.840.1.101.3.4.3.2*/, Algo_Group(ALG::DSA, ALG::SHA_256)},
    { std::span(oids+653, 9) /*oid*/ /*2.16.840.1.101.3.4.3.3*/, Algo_Group(ALG::DSA, ALG::SHA_384)},
    { std::span(oids+662, 9) /*oid*/ /*2.16.840.1.101.3.4.3.4*/, Algo_Group(ALG::DSA, ALG::SHA_512)},
    { std::span(oids+671, 9) /*oid*/ /*2.16.840.1.101.3.4.3.5*/, Algo_Group(ALG::DSA, ALG::SHA_3_224)},
    { std::span(oids+680, 9) /*oid*/ /*2.16.840.1.101.3.4.3.6*/, Algo_Group(ALG::DSA, ALG::SHA_3_256)},
    { std::span(oids+689, 9) /*oid*/ /*2.16.840.1.101.3.4.3.7*/, Algo_Group(ALG::DSA, ALG::SHA_3_384)},
    { std::span(oids+698, 9) /*oid*/ /*2.16.840.1.101.3.4.3.8*/, Algo_Group(ALG::DSA, ALG::SHA_3_512)},
    { std::span(oids+707, 9) /*oid*/ /*2.16.840.1.101.3.4.3.9*/, Algo_Group(ALG::ECDSA, ALG::SHA_3_224)},
    { std::span(oids+716, 9) /*oid*/ /*2.16.840.1.101.3.4.3.10*/, Algo_Group(ALG::ECDSA, ALG::SHA_3_256)},
    { std::span(oids+725, 9) /*oid*/ /*2.16.840.1.101.3.4.3.11*/, Algo_Group(ALG::ECDSA, ALG::SHA_3_384)},
    { std::span(oids+734, 9) /*oid*/ /*2.16.840.1.101.3.4.3.12*/, Algo_Group(ALG::ECDSA, ALG::SHA_3_512)},
    { std::span(oids+743, 9) /*oid*/ /*2.16.840.1.101.3.4.3.13*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_3_224)},
    { std::span(oids+752, 9) /*oid*/ /*2.16.840.1.101.3.4.3.14*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_3_256)},
    { std::span(oids+761, 9) /*oid*/ /*2.16.840.1.101.3.4.3.15*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_3_384)},
    { std::span(oids+770, 9) /*oid*/ /*2.16.840.1.101.3.4.3.16*/, Algo_Group(ALG::RSA, ALG::EMSA3, ALG::SHA_3_512)}
    /*sorted_end*/

    ,

        //{t2id("2.16.840.1.101.3.4.1.7"), Algo_Group(ALG::AES_128_CCM) },
        //{t2id("2.16.840.1.101.3.4.1.22"), Algo_Group(ALG::AES_192_CBC) },
        //{t2id("2.16.840.1.101.3.4.1.26"), Algo_Group(ALG::AES_192_GCM) },
        //{t2id("2.16.840.1.101.3.4.1.27"), Algo_Group(ALG::AES_192_CCM) },
        //{t2id("2.16.840.1.101.3.4.1.47"), Algo_Group(ALG::AES_256_CCM) },
        //{t2id("2.16.840.1.101.3.4.3.17"), t2a("ML-DSA-4x4") },
        //{t2id("2.16.840.1.101.3.4.3.18"), t2a("ML-DSA-6x5") },
        //{t2id("2.16.840.1.101.3.4.3.19"), t2a("ML-DSA-8x7") },
        //{t2id("1.2.156.10197.1.104.2"), t2a("SM4/CBC") },
        //{t2id("1.2.156.10197.1.104.8"), t2a("SM4/GCM") },
        //{t2id("1.2.156.10197.1.104.100"), t2a("SM4/OCB") },
        //{t2id("1.2.156.10197.1.301"), t2a("sm2p256v1") },
        //{t2id("1.2.156.10197.1.301.1"), t2a("SM2") },
        //{t2id("1.2.156.10197.1.301.2"), t2a("SM2_Kex") },
        //{t2id("1.2.156.10197.1.301.3"), t2a("SM2_Enc") },
        //{t2id("1.2.840.113549.1.1.2"), Algo_Group(ALG::RSA, ALG::EMSA3, ALG::MD2) },
      //{t2id("1.2.840.113549.1.1.4"), Algo_Group(ALG::RSA, ALG::EMSA3, ALG::MD5) },
      //{t2id("1.2.840.113549.1.1.7"), Algo_Group(ALG::RSA, ALG::OAEP) },
      //{t2id("0.3.4401.5.3.1.9.26"), t2a("Camellia-192/GCM")},
      //{t2id("0.3.4401.5.3.1.9.46"), t2a("Camellia-256/GCM")},
      //{t2id("0.3.4401.5.3.1.9.6"), t2a("Camellia-128/GCM")},
      //{t2id("0.4.0.127.0.15.1.1.13.0"), t2a("XMSS")},
      //{t2id("1.2.156.10197.1.501"), t2a("SM2_Sig/SM3")},
      //{t2id("1.2.250.1.223.101.256.1"), t2a("frp256v1")},
      //{t2id("1.2.392.200011.61.1.1.1.2"), t2a("Camellia-128/CBC")},
      //{t2id("1.2.392.200011.61.1.1.1.3"), t2a("Camellia-192/CBC")},
      //{t2id("1.2.392.200011.61.1.1.1.4"), t2a("Camellia-256/CBC")},
      //{t2id("1.2.410.200004.1.4"), t2a("SEED/CBC")},
      //{t2id("1.2.643.100.1"), t2a("GOST.OGRN")},
      //{t2id("1.2.643.100.111"), t2a("GOST.SubjectSigningTool")},
      //{t2id("1.2.643.100.112"), t2a("GOST.IssuerSigningTool")},
      //{t2id("1.2.643.2.2.19"), t2a("GOST-34.10")},
      //{t2id("1.2.643.2.2.3"), t2a("GOST-34.10/GOST-R-34.11-94")},
      //{t2id("1.2.643.2.2.35.1"), t2a("gost_256A")},
      //{t2id("1.2.643.2.2.36.0"), t2a("gost_256A")},
      //{t2id("1.2.643.3.131.1.1"), t2a("GOST.INN")},
      //{t2id("1.2.643.7.1.1.1.1"), t2a("GOST-34.10-2012-256")},
      //{t2id("1.2.643.7.1.1.1.2"), t2a("GOST-34.10-2012-512")},
      //{t2id("1.2.643.7.1.1.2.2"), t2a("Streebog-256")},
      //{t2id("1.2.643.7.1.1.2.3"), t2a("Streebog-512")},
      //{t2id("1.2.643.7.1.1.3.2"), t2a("GOST-34.10-2012-256/Streebog-256")},
      //{t2id("1.2.643.7.1.1.3.3"), t2a("GOST-34.10-2012-512/Streebog-512")},
      //{t2id("1.2.643.7.1.2.1.1.1"), t2a("gost_256A")},
      //{t2id("1.2.643.7.1.2.1.1.2"), t2a("gost_256B")},
      //{t2id("1.2.643.7.1.2.1.2.1"), t2a("gost_512A")},
      //{t2id("1.2.643.7.1.2.1.2.2"), t2a("gost_512B")},
      //{t2id("1.2.840.10045.3.1.1"), t2a("secp192r1")},
      //{t2id("1.2.840.10045.3.1.2"), t2a("x962_p192v2")},
      //{t2id("1.2.840.10045.3.1.3"), t2a("x962_p192v3")},
      //{t2id("1.2.840.10045.3.1.4"), t2a("x962_p239v1")},
      //{t2id("1.2.840.10045.3.1.5"), t2a("x962_p239v2")},
      //{t2id("1.2.840.10045.3.1.6"), t2a("x962_p239v3")},
      //{t2id("1.2.840.113533.7.66.10"), t2a("CAST-128/CBC")},
      //{t2id("1.2.840.113533.7.66.15"), t2a("KeyWrap.CAST-128")},
      //{t2id("1.2.840.113549.1.5.12"), t2a("PKCS5.PBKDF2")},
      //{t2id("1.2.840.113549.1.5.13"), t2a("PBE-PKCS5v20")},
      //{t2id("1.2.840.113549.1.9.14"), t2a("PKCS9.ExtensionRequest")},
      //{t2id("1.2.840.113549.1.9.16.3.17"), t2a("HSS-LMS")},
      //{t2id("1.2.840.113549.1.9.16.3.6"), t2a("KeyWrap.TripleDES")},
      //{t2id("1.2.840.113549.1.9.16.3.8"), t2a("Compression.Zlib")},
      //{t2id("1.2.840.113549.1.9.2"), t2a("PKCS9.UnstructuredName")},
      //{t2id("1.2.840.113549.1.9.3"), t2a("PKCS9.ContentType")},
      //{t2id("1.2.840.113549.1.9.4"), t2a("PKCS9.MessageDigest")},
      //{t2id("1.2.840.113549.1.9.7"), t2a("PKCS9.ChallengePassword")},
      //{t2id("1.2.840.113549.2.5"), t2a("MD5")},
      //{t2id("1.2.840.113549.3.7"), t2a("TripleDES/CBC")},
      //{t2id("1.3.101.113"), t2a("Ed448")},
      //{t2id("1.3.132.0.10"), t2a("secp256k1")},
      //{t2id("1.3.132.0.30"), t2a("secp160r2")},
      //{t2id("1.3.132.0.31"), t2a("secp192k1")},
      //{t2id("1.3.132.0.32"), t2a("secp224k1")},
      //{t2id("1.3.132.0.8"), t2a("secp160r1")},
      //{t2id("1.3.132.0.9"), t2a("secp160k1")},
      //{t2id("1.3.14.3.2.7"), t2a("DES/CBC")},
      //{t2id("1.3.36.3.3.2.8.1.1.1"), t2a("brainpool160r1")},
      //{t2id("1.3.36.3.3.2.8.1.1.11"), t2a("brainpool384r1")},
      //{t2id("1.3.36.3.3.2.8.1.1.13"), t2a("brainpool512r1")},
      //{t2id("1.3.36.3.3.2.8.1.1.3"), t2a("brainpool192r1")},
      //{t2id("1.3.36.3.3.2.8.1.1.5"), t2a("brainpool224r1")},
      //{t2id("1.3.36.3.3.2.8.1.1.7"), t2a("brainpool256r1")},
      //{t2id("1.3.36.3.3.2.8.1.1.9"), t2a("brainpool320r1")},
      //{t2id("1.3.6.1.4.1.11591.15.1"), t2a("OpenPGP.Ed25519")},
      //{t2id("1.3.6.1.4.1.11591.4.11"), t2a("Scrypt")},
      //{t2id("1.3.6.1.4.1.25258.1.10.1"), t2a("Dilithium-4x4-AES-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.10.2"), t2a("Dilithium-6x5-AES-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.10.3"), t2a("Dilithium-8x7-AES-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.11.1"), t2a("Kyber-512-90s-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.11.2"), t2a("Kyber-768-90s-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.11.3"), t2a("Kyber-1024-90s-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.12.1.1"), t2a("SphincsPlus-shake-128s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.1.2"), t2a("SphincsPlus-shake-128f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.1.3"), t2a("SphincsPlus-shake-192s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.1.4"), t2a("SphincsPlus-shake-192f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.1.5"), t2a("SphincsPlus-shake-256s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.1.6"), t2a("SphincsPlus-shake-256f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.2.1"), t2a("SphincsPlus-sha2-128s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.2.2"), t2a("SphincsPlus-sha2-128f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.2.3"), t2a("SphincsPlus-sha2-192s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.2.4"), t2a("SphincsPlus-sha2-192f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.2.5"), t2a("SphincsPlus-sha2-256s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.2.6"), t2a("SphincsPlus-sha2-256f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.3.1"), t2a("SphincsPlus-haraka-128s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.3.2"), t2a("SphincsPlus-haraka-128f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.3.3"), t2a("SphincsPlus-haraka-192s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.3.4"), t2a("SphincsPlus-haraka-192f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.3.5"), t2a("SphincsPlus-haraka-256s-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.12.3.6"), t2a("SphincsPlus-haraka-256f-r3.1")},
      //{t2id("1.3.6.1.4.1.25258.1.13"), t2a("HSS-LMS-Private-Key")},
      //{t2id("1.3.6.1.4.1.25258.1.14.1"), t2a("FrodoKEM-640-SHAKE")},
      //{t2id("1.3.6.1.4.1.25258.1.14.2"), t2a("FrodoKEM-976-SHAKE")},
      //{t2id("1.3.6.1.4.1.25258.1.14.3"), t2a("FrodoKEM-1344-SHAKE")},
      //{t2id("1.3.6.1.4.1.25258.1.15.1"), t2a("FrodoKEM-640-AES")},
      //{t2id("1.3.6.1.4.1.25258.1.15.2"), t2a("FrodoKEM-976-AES")},
      //{t2id("1.3.6.1.4.1.25258.1.15.3"), t2a("FrodoKEM-1344-AES")},
      //{t2id("1.3.6.1.4.1.25258.1.16.1"), t2a("eFrodoKEM-640-SHAKE")},
      //{t2id("1.3.6.1.4.1.25258.1.16.2"), t2a("eFrodoKEM-976-SHAKE")},
      //{t2id("1.3.6.1.4.1.25258.1.16.3"), t2a("eFrodoKEM-1344-SHAKE")},
      //{t2id("1.3.6.1.4.1.25258.1.17.1"), t2a("eFrodoKEM-640-AES")},
      //{t2id("1.3.6.1.4.1.25258.1.17.2"), t2a("eFrodoKEM-976-AES")},
      //{t2id("1.3.6.1.4.1.25258.1.17.3"), t2a("eFrodoKEM-1344-AES")},
      //{t2id("1.3.6.1.4.1.25258.1.3"), t2a("McEliece")},
      //{t2id("1.3.6.1.4.1.25258.1.5"), t2a("XMSS-draft6")},
      //{t2id("1.3.6.1.4.1.25258.1.6.1"), t2a("GOST-34.10-2012-256/SHA-256")},
      //{t2id("1.3.6.1.4.1.25258.1.7.1"), t2a("Kyber-512-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.7.2"), t2a("Kyber-768-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.7.3"), t2a("Kyber-1024-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.8"), t2a("XMSS-draft12")},
      //{t2id("1.3.6.1.4.1.25258.1.9.1"), t2a("Dilithium-4x4-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.9.2"), t2a("Dilithium-6x5-r3")},
      //{t2id("1.3.6.1.4.1.25258.1.9.3"), t2a("Dilithium-8x7-r3")},
      //{t2id("1.3.6.1.4.1.25258.3.1"), t2a("Serpent/CBC")},
      //{t2id("1.3.6.1.4.1.25258.3.101"), t2a("Serpent/GCM")},
      //{t2id("1.3.6.1.4.1.25258.3.102"), t2a("Twofish/GCM")},
      //{t2id("1.3.6.1.4.1.25258.3.2"), t2a("Threefish-512/CBC")},
      //{t2id("1.3.6.1.4.1.25258.3.2.1"), t2a("AES-128/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.2.2"), t2a("AES-192/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.2.3"), t2a("AES-256/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.2.4"), t2a("Serpent/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.2.5"), t2a("Twofish/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.2.6"), t2a("Camellia-128/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.2.7"), t2a("Camellia-192/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.2.8"), t2a("Camellia-256/OCB")},
      //{t2id("1.3.6.1.4.1.25258.3.3"), t2a("Twofish/CBC")},
      //{t2id("1.3.6.1.4.1.25258.3.4.1"), t2a("AES-128/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.2"), t2a("AES-192/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.3"), t2a("AES-256/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.4"), t2a("Serpent/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.5"), t2a("Twofish/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.6"), t2a("Camellia-128/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.7"), t2a("Camellia-192/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.8"), t2a("Camellia-256/SIV")},
      //{t2id("1.3.6.1.4.1.25258.3.4.9"), t2a("SM4/SIV")},
      //{t2id("1.3.6.1.4.1.25258.4.1"), t2a("numsp256d1")},
      //{t2id("1.3.6.1.4.1.25258.4.2"), t2a("numsp384d1")},
      //{t2id("1.3.6.1.4.1.25258.4.3"), t2a("numsp512d1")},
      //{t2id("1.3.6.1.4.1.3029.1.2.1"), t2a("ElGamal")},
      //{t2id("1.3.6.1.4.1.3029.1.5.1"), t2a("OpenPGP.Curve25519")},
      //{t2id("1.3.6.1.4.1.311.20.2.2"), t2a("Microsoft SmartcardLogon")},
      //{t2id("1.3.6.1.4.1.311.20.2.3"), t2a("Microsoft UPN")},
      //{t2id("1.3.6.1.4.1.8301.3.1.2.9.0.38"), t2a("secp521r1")},
      //{t2id("1.3.6.1.5.5.7.3.3"), t2a("PKIX.CodeSigning")},
      //{t2id("1.3.6.1.5.5.7.3.4"), t2a("PKIX.EmailProtection")},
      //{t2id("1.3.6.1.5.5.7.3.5"), t2a("PKIX.IPsecEndSystem")},
      //{t2id("1.3.6.1.5.5.7.3.6"), t2a("PKIX.IPsecTunnel")},
      //{t2id("1.3.6.1.5.5.7.3.7"), t2a("PKIX.IPsecUser")},
      //{t2id("1.3.6.1.5.5.7.3.8"), t2a("PKIX.TimeStamping")},
      //{t2id("1.3.6.1.5.5.7.8.5"), t2a("PKIX.XMPPAddr")},
      //{t2id("2.16.840.1.101.3.4.1.25"), t2a("KeyWrap.AES-192")},
      //{t2id("2.16.840.1.101.3.4.1.45"), t2a("KeyWrap.AES-256")},
      //{t2id("2.16.840.1.101.3.4.1.5"), t2a("KeyWrap.AES-128")},
      //{t2id("2.16.840.1.101.3.4.2.11"), t2a("SHAKE-128")},
      //{t2id("2.16.840.1.101.3.4.2.12"), t2a("SHAKE-256")},
      //{t2id("2.16.840.1.101.3.4.3.20"), t2a("SLH-DSA-SHA2-128s")},
      //{t2id("2.16.840.1.101.3.4.3.21"), t2a("SLH-DSA-SHA2-128f")},
      //{t2id("2.16.840.1.101.3.4.3.22"), t2a("SLH-DSA-SHA2-192s")},
      //{t2id("2.16.840.1.101.3.4.3.23"), t2a("SLH-DSA-SHA2-192f")},
      //{t2id("2.16.840.1.101.3.4.3.24"), t2a("SLH-DSA-SHA2-256s")},
      //{t2id("2.16.840.1.101.3.4.3.25"), t2a("SLH-DSA-SHA2-256f")},
      //{t2id("2.16.840.1.101.3.4.3.26"), t2a("SLH-DSA-SHAKE-128s")},
      //{t2id("2.16.840.1.101.3.4.3.27"), t2a("SLH-DSA-SHAKE-128f")},
      //{t2id("2.16.840.1.101.3.4.3.28"), t2a("SLH-DSA-SHAKE-192s")},
      //{t2id("2.16.840.1.101.3.4.3.29"), t2a("SLH-DSA-SHAKE-192f")},
      //{t2id("2.16.840.1.101.3.4.3.30"), t2a("SLH-DSA-SHAKE-256s")},
      //{t2id("2.16.840.1.101.3.4.3.31"), t2a("SLH-DSA-SHAKE-256f")},
      //{t2id("2.16.840.1.101.3.4.4.1"), t2a("ML-KEM-512")},
      //{t2id("2.16.840.1.101.3.4.4.2"), t2a("ML-KEM-768")},
      //{t2id("2.16.840.1.101.3.4.4.3"), t2a("ML-KEM-1024")},
      //{t2id("2.16.840.1.113730.1.13"), t2a("Certificate Comment")},
      //{t2id("2.5.29.16"), t2a("X509v3.PrivateKeyUsagePeriod")},
      //{t2id("2.5.29.23"), t2a("X509v3.HoldInstructionCode")},
      //{t2id("2.5.29.24"), t2a("X509v3.InvalidityDate")},
      //{t2id("2.5.29.32.0"), t2a("X509v3.AnyPolicy")},
      //{t2id("2.5.29.36"), t2a("X509v3.PolicyConstraints")},
      //{t2id("2.5.4.12"), t2a("X520.Title")},
      //{t2id("2.5.4.4"), t2a("X520.Surname")},
      //{t2id("2.5.4.42"), t2a("X520.GivenName")},
      //{t2id("2.5.4.43"), t2a("X520.Initials")},
      //{t2id("2.5.4.44"), t2a("X520.GenerationalQualifier")},
      //{t2id("2.5.4.46"), t2a("X520.DNQualifier")},
      //{t2id("2.5.4.65"), t2a("X520.Pseudonym")},
      //{t2id("2.5.4.9"), t2a("X520.StreetAddress")},
      //{t2id("2.5.8.1.1"), t2a("RSA"},
    };

    std::vector<uint32_t> id_decode(std::span<const uint8_t> id)
    {
        auto consume = [](BufferSlicer& data) -> uint32_t {
            BOTAN_ASSERT_NOMSG(!data.empty());
            uint32_t b = data.take_byte();

            if (b > 0x7F) {
                b &= 0x7F;

                // Even BER requires that the OID have minimal length, ie that
                // the first byte of a multibyte encoding cannot be zero
                // See X.690 section 8.19.2
                if (b == 0) {
                    throw Decoding_Error("Leading zero byte in multibyte OID encoding");
                }

                while (true) {
                    if (data.empty()) {
                        throw Decoding_Error("Truncated OID value");
                    }

                    const uint8_t next = data.take_byte();
                    const bool more = (next & 0x80);
                    const uint8_t value = next & 0x7F;

                    if ((b >> (32 - 7)) != 0) {
                        throw Decoding_Error("OID component overflow");
                    }

                    b = (b << 7) | value;

                    if (!more) {
                        break;
                    }
                }
            }

            return b;
            };

        BufferSlicer data(id);
        std::vector<uint32_t> parts;
        while (!data.empty()) {
            const uint32_t comp = consume(data);

            if (parts.empty()) {
                // divide into root and second arc

                const uint32_t root_arc = [](uint32_t b0) -> uint32_t {
                    if (b0 < 40) {
                        return 0;
                    }
                    else if (b0 < 80) {
                        return 1;
                    }
                    else {
                        return 2;
                    }
                    }(comp);

                parts.push_back(root_arc);
                BOTAN_ASSERT_NOMSG(comp >= 40 * root_arc);
                parts.push_back(comp - 40 * root_arc);
            }
            else {
                parts.push_back(comp);
            }
        }
        return parts;
    }

    inline std::strong_ordering operator <=> (u8 i1, Algo_Group ag)
    {

        u64 x1 = load_le<8>((const u8*)&g_oids[i1].alg, 0);
        u64 x2 = load_le<8>((const u8*)&ag, 0);

        return x1 <=> x2;

    }

    //static
    OID OID::from_ag(Algo_Group ag)
    {
        if (ag.empty()) {
            throw Invalid_Argument("OID::from_ag argument must be non-empty");
        }

        signed_t index;
        if (tools::find_sorted(g_oids_by_algs, index, ag))
            return OID(static_cast<oid_index>(g_oids_by_algs[index]));

        throw Lookup_Error(str::build_string("No OID associated with ag '$'", ag));
    }


    oid_index oid_find_index(std::span<const uint8_t> id)
    {
        signed_t index;
        if (tools::find_sorted(g_oids, index, id))
            return static_cast<oid_index>(index);

#ifdef _DEBUG
        auto parts = id_decode(id);
        str::astr oidp;
        for (u32 p : parts)
        {
            str::append_num(oidp, p, 0);
            oidp.push_back('.');
        }
        oidp.resize(oidp.length() - 1);

#endif

        return oid_index::_empty;
    }

} // namespace Botan

#if 0
/*enum_start*/
_1_0_14888_3_0_5,
_1_2_156_10197_1_401,
_1_2_156_10197_1_504,
_1_2_410_200004_1_100_4_3,
_1_2_410_200004_1_100_4_4,
_1_2_410_200004_1_100_4_5,
_1_2_840_113549_1_1_1,
_1_2_840_113549_1_1_5,
_1_2_840_113549_1_1_8,
_1_2_840_113549_1_1_10,
_1_2_840_113549_1_1_11,
_1_2_840_113549_1_1_12,
_1_2_840_113549_1_1_13,
_1_2_840_113549_1_1_14,
_1_2_840_113549_1_1_16,
_1_2_840_113549_1_9_1,
_1_2_840_113549_1_9_16_3_18,
_1_2_840_113549_2_7,
_1_2_840_113549_2_8,
_1_2_840_113549_2_9,
_1_2_840_113549_2_10,
_1_2_840_113549_2_11,
_1_2_840_113549_2_13,
_1_2_840_10040_4_1,
_1_2_840_10040_4_3,
_1_2_840_10045_1_1,
_1_2_840_10045_2_1,
_1_2_840_10045_3_1_7,
_1_2_840_10045_4_1,
_1_2_840_10045_4_3_1,
_1_2_840_10045_4_3_2,
_1_2_840_10045_4_3_3,
_1_2_840_10045_4_3_4,
_1_2_840_10046_2_1,
_1_3_6_1_5_5_7_1_1,
_1_3_6_1_5_5_7_1_26,
_1_3_6_1_5_5_7_3_1,
_1_3_6_1_5_5_7_3_2,
_1_3_6_1_5_5_7_3_9,
_1_3_6_1_5_5_7_48_1,
_1_3_6_1_5_5_7_48_1_1,
_1_3_6_1_5_5_7_48_1_5,
_1_3_6_1_5_5_7_48_2,
_1_3_14_3_2_26,
_1_3_36_3_2_1,
_1_3_36_3_3_1_2,
_1_3_36_3_3_2_5_2_1,
_1_3_36_3_3_2_5_4_1,
_1_3_36_3_3_2_5_4_2,
_1_3_36_3_3_2_5_4_3,
_1_3_36_3_3_2_5_4_4,
_1_3_36_3_3_2_5_4_5,
_1_3_36_3_3_2_5_4_6,
_1_3_101_110,
_1_3_101_111,
_1_3_101_112,
_1_3_132_0_33,
_1_3_132_0_34,
_1_3_132_0_35,
_1_3_132_1_12,
_2_5_4_3,
_2_5_4_5,
_2_5_4_6,
_2_5_4_7,
_2_5_4_8,
_2_5_4_10,
_2_5_4_11,
_2_5_29_14,
_2_5_29_15,
_2_5_29_17,
_2_5_29_18,
_2_5_29_19,
_2_5_29_20,
_2_5_29_21,
_2_5_29_28,
_2_5_29_30,
_2_5_29_31,
_2_5_29_32,
_2_5_29_35,
_2_5_29_37,
_2_16_840_1_101_3_4_1_2,
_2_16_840_1_101_3_4_1_6,
_2_16_840_1_101_3_4_1_42,
_2_16_840_1_101_3_4_1_46,
_2_16_840_1_101_3_4_2_1,
_2_16_840_1_101_3_4_2_2,
_2_16_840_1_101_3_4_2_3,
_2_16_840_1_101_3_4_2_4,
_2_16_840_1_101_3_4_2_6,
_2_16_840_1_101_3_4_2_7,
_2_16_840_1_101_3_4_2_8,
_2_16_840_1_101_3_4_2_9,
_2_16_840_1_101_3_4_2_10,
_2_16_840_1_101_3_4_3_1,
_2_16_840_1_101_3_4_3_2,
_2_16_840_1_101_3_4_3_3,
_2_16_840_1_101_3_4_3_4,
_2_16_840_1_101_3_4_3_5,
_2_16_840_1_101_3_4_3_6,
_2_16_840_1_101_3_4_3_7,
_2_16_840_1_101_3_4_3_8,
_2_16_840_1_101_3_4_3_9,
_2_16_840_1_101_3_4_3_10,
_2_16_840_1_101_3_4_3_11,
_2_16_840_1_101_3_4_3_12,
_2_16_840_1_101_3_4_3_13,
_2_16_840_1_101_3_4_3_14,
_2_16_840_1_101_3_4_3_15,
_2_16_840_1_101_3_4_3_16,
/*enum_end*/
#endif
#endif