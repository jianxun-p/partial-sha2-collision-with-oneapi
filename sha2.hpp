/**
 * @file sha2.hpp
 * @author Steven
 * @brief A header-only implementation of SHA-2 family hash functions (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256)
 * @version 0.1
 * @date 2026-02-12
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * 
 */

#include <cstddef>
#include <array>

template<typename T>
constexpr T rotate_left(T a, uint8_t n) noexcept {
    return (a << n) | (a >> (sizeof(T) * 8 - n));
}

template<typename T>
constexpr T rotate_right(T a, uint8_t n) noexcept {
    return (a >> n) | (a << (sizeof(T) * 8 - n));
}


template<typename block_t, std::size_t BLOCK_LEN = 8>
constexpr static std::array<block_t, BLOCK_LEN> message_to_blocks(const uint8_t *message) noexcept {
    constexpr std::size_t block_size = sizeof(block_t);
    std::array<block_t, BLOCK_LEN> msg_block = {0};
    for (std::size_t i = 0; i < BLOCK_LEN; ++i) {
        for (std::size_t j = 0; j < block_size; ++j) {
            msg_block[i] <<= 8;
            msg_block[i] |= message[i * block_size + j];
        }
    }
    return msg_block;
}

template<typename block_t, std::size_t BLOCK_LEN = 8>
constexpr static auto blocks_to_bytes(void *out, const std::array<block_t, BLOCK_LEN> &blocks) noexcept {
    constexpr std::size_t block_size = sizeof(block_t);
    for (std::size_t i = 0; i < BLOCK_LEN; ++i) {
        for (std::size_t j = 0; j < block_size; ++j) {
            static_cast<uint8_t *>(out)[block_size * i + j] = (blocks[i] >> (8 * (block_size - j - 1))) & 0xFF;
        }
    }
}

constexpr uint32_t _sigma_0_256(uint32_t x) noexcept {
    return rotate_right(x, static_cast<uint32_t>(7)) ^ rotate_right(x, static_cast<uint32_t>(18)) ^ (x >> 3);
}
constexpr uint32_t _sigma_1_256(uint32_t x) noexcept {
    return rotate_right(x, static_cast<uint32_t>(17)) ^ rotate_right(x, static_cast<uint32_t>(19)) ^ (x >> 10);
}
constexpr uint32_t _big_sigma_0_256(uint32_t x) noexcept {
    return rotate_right(x, static_cast<uint32_t>(2)) ^ rotate_right(x, static_cast<uint32_t>(13)) 
        ^ rotate_right(x, static_cast<uint32_t>(22));
}
constexpr uint32_t _big_sigma_1_256(uint32_t x) noexcept {
    return rotate_right(x, static_cast<uint32_t>(6)) 
        ^ rotate_right(x, static_cast<uint32_t>(11)) 
        ^ rotate_right(x, static_cast<uint32_t>(25));
}
constexpr std::array<uint32_t, 64>_ROUND_CONSTANTS_256{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
constexpr uint64_t _sigma_0_512(uint64_t x) noexcept {
    return rotate_right(x, static_cast<uint64_t>(1)) ^ rotate_right(x, static_cast<uint64_t>(8)) ^ (x >> 7);
}
constexpr uint64_t _sigma_1_512(uint64_t x) noexcept {
    return rotate_right(x, static_cast<uint64_t>(19)) ^ rotate_right(x, static_cast<uint64_t>(61)) ^ (x >> 6);
}
constexpr uint64_t _big_sigma_0_512(uint64_t x) noexcept {
    return rotate_right(x, static_cast<uint64_t>(28)) ^ rotate_right(x, static_cast<uint64_t>(34)) 
        ^ rotate_right(x, static_cast<uint64_t>(39));
}
constexpr uint64_t _big_sigma_1_512(uint64_t x) noexcept {
    return rotate_right(x, static_cast<uint64_t>(14)) ^ rotate_right(x,
        static_cast<uint64_t>(18)) ^ rotate_right(x, static_cast<uint64_t>(41));
}

constexpr std::array<uint64_t, 80>_ROUND_CONSTANTS_512 = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};


#define _SHA_CH(x, y, z) ((x & y) ^ ((~x) & z))
#define _SHA_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define CEIL_DIV(a, m) (((a) + (m) - 1) / (m))



template<
    std::size_t N, 
    std::size_t M, 
    typename word_t, 
    std::array<word_t, 8> INIT_HASH_VAL,
    std::size_t T
> 
class _SHA2_Base
{

private:

    std::array<uint8_t, 2 * N> tmp_message;
    std::size_t offset = 0;
    std::size_t consumed_len = 0;
    std::array<word_t, 8> hash_val = INIT_HASH_VAL;

    /**
     * @brief padding for SHA-1 and SHA-2 functions
     * @tparam B                block size in bytes (64 for SHA-1, SHA224, SHA-256; 128 for SHA-384, SHA-512, SHA-512/224 and SHA-512/256)
     * @param out               output buffer for padded data (must be at least ceil((length + 1 + 8) / B) * B bytes)
     * @param length            size of data to be preprocessed
     */
    static void sha_pad_end(
        void *out,
        const std::size_t length
    ) noexcept
    {
        constexpr std::size_t B = 2 * N;
        constexpr std::size_t min_pad_len = B / 8 + 1;
        auto out_len = B * CEIL_DIV(length + min_pad_len, B);
        auto zero_pad_len = out_len - length - min_pad_len;
        static_cast<uint8_t *>(out)[0] = 0x80;
        std::memset(static_cast<uint8_t*>(out) + 1, 0x00, zero_pad_len);
        auto len = static_cast<uint64_t>(length);
        auto len_ptr = static_cast<uint8_t*>(out) + 1 + zero_pad_len;
        if constexpr (B == 64) {
            blocks_to_bytes<uint64_t, 1>(len_ptr, { len * 8 });
        } else if constexpr (B == 128) {
            blocks_to_bytes<uint64_t, 2>(len_ptr, { len & 0xe000000000000000, len * 8});
        } else {
            static_assert(B == 64 || B == 128, "Invalid block size");
        }
    }

    void sha2_compression
    (
        const std::array<word_t, 2 * N / sizeof(word_t)> &msg_block
    ) noexcept 
    {
        std::array<word_t, T> w = {0};
        std::copy(msg_block.cbegin(), msg_block.cend(), w.begin());
        word_t a = hash_val[0], b = hash_val[1], c = hash_val[2], d = hash_val[3],
            e = hash_val[4], f = hash_val[5], g = hash_val[6], h = hash_val[7];
        for (decltype(T) i = 16; i < T; ++i) {
            if constexpr (N == 32) {
                w[i] = _sigma_1_256(w[i-2]) + w[i-7] + _sigma_0_256(w[i-15]) + w[i-16];
            } else if constexpr (N == 64) {
                w[i] = _sigma_1_512(w[i-2]) + w[i-7] + _sigma_0_512(w[i-15]) + w[i-16];
            } else {
                static_assert(false, "BAD N");
            }
        }
        for (decltype(T) i = 0; i < T; ++i) {
            word_t t1 = 0, t2 = 0;
            if constexpr (N == 32) {
                t1 = h + _big_sigma_1_256(e) + _SHA_CH(e, f, g) + _ROUND_CONSTANTS_256[i] + w[i];
                t2 = _big_sigma_0_256(a) + _SHA_MAJ(a, b, c);
            } else if constexpr (N == 64) {
                t1 = h + _big_sigma_1_512(e) + _SHA_CH(e, f, g) + _ROUND_CONSTANTS_512[i] + w[i];
                t2 = _big_sigma_0_512(a) + _SHA_MAJ(a, b, c);
            } else {
                static_assert(false, "BAD N");
            }
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        hash_val[0] += a;
        hash_val[1] += b;
        hash_val[2] += c;
        hash_val[3] += d;
        hash_val[4] += e;
        hash_val[5] += f;
        hash_val[6] += g;
        hash_val[7] += h;
    }

    void _update(const uint8_t *message) noexcept {
        auto block = message_to_blocks<word_t, 2 * N / sizeof(word_t)>(message);
        sha2_compression(block);
    }
    
    void _digest(void *out) noexcept {
        std::array<uint8_t, 2 * N> padded_tmp_message;
        std::copy(tmp_message.cbegin(), tmp_message.cbegin() + consumed_len % (2*N), padded_tmp_message.begin());
        sha_pad_end(padded_tmp_message.data() + consumed_len % (2*N), consumed_len);
        _update(padded_tmp_message.data());
        blocks_to_bytes<word_t, 8>(out, hash_val);
    }

public:

    static constexpr std::size_t OUTPUT_BITS = M * 8;
    static constexpr std::size_t OUTPUT_SIZE = M;

    void update(const void *message, const std::size_t length) noexcept {
        constexpr auto MESSAGE_BLOCK_SIZE = 2 * N;
        const auto msg = reinterpret_cast<const uint8_t *>(message);
        auto bytes_copied = std::min(length, MESSAGE_BLOCK_SIZE - consumed_len % MESSAGE_BLOCK_SIZE);
        std::copy(msg, msg + bytes_copied, tmp_message.data() + consumed_len % MESSAGE_BLOCK_SIZE);
        consumed_len += bytes_copied;
        while (consumed_len % MESSAGE_BLOCK_SIZE == 0) {
            _update(tmp_message.data());
            auto copy_len = std::min(length - bytes_copied, MESSAGE_BLOCK_SIZE);
            std::copy(msg + bytes_copied, msg + bytes_copied + copy_len, tmp_message.begin());
            bytes_copied += copy_len;
            consumed_len += copy_len;
        }
    }
    void digest(void *out) noexcept {
        std::array<uint8_t, N> val;
        _digest(static_cast<uint8_t *>(val.data()));
        std::copy(val.cbegin(), val.cbegin() + M, static_cast<uint8_t *>(out));
    }
    
};




class SHA224 : public _SHA2_Base<
    32, 
    28,
    uint32_t, 
    std::array<uint32_t, 8>{
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    },
    64
> {};

class SHA256 : public _SHA2_Base<
    32,
    32,
    uint32_t, 
    std::array<uint32_t, 8>{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    },
    64
> {};

class SHA384 : public _SHA2_Base<
    64, 
    48,
    uint64_t, 
    std::array<uint64_t, 8>{
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    },
    80
> {};

class SHA512 : public _SHA2_Base<
    64, 
    64,
    uint64_t, 
    std::array<uint64_t, 8>{
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    },
    80
> {};

class SHA512_224 : public _SHA2_Base<
    64, 
    28,
    uint64_t, 
    std::array<uint64_t, 8>{
        0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1
    },
    80
> {};

class SHA512_256 : public _SHA2_Base<
    64, 
    32,
    uint64_t, 
    std::array<uint64_t, 8>{
        0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
        0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2
    },
    80
> {};





