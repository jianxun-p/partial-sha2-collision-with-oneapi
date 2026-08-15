/**
 * @file md5.hpp
 * @author Steven
 * @brief Header-only implementation of the MD5 message-digest algorithm
 * @version 0.2
 * @date 2026-08-14
 * @see https://www.rfc-editor.org/rfc/rfc1321
 */

#ifndef MD5_HPP
#define MD5_HPP

#include <array>
#include <cstddef>
#include <cstdint>

class MD5
{
public:
    static constexpr std::size_t OUTPUT_BITS = 128;
    static constexpr std::size_t OUTPUT_SIZE = OUTPUT_BITS / 8;
    static constexpr std::size_t BLOCK_SIZE = 64;

    constexpr MD5() noexcept = default;

    void update(const void *message, std::size_t length) noexcept
    {
        if (length == 0) {
            return;
        }

        const auto *input = static_cast<const std::uint8_t *>(message);
        const std::size_t buffered = static_cast<std::size_t>(message_size_ % BLOCK_SIZE);
        message_size_ += static_cast<std::uint64_t>(length);

        std::size_t input_offset = 0;
        if (buffered != 0) {
            const std::size_t needed = BLOCK_SIZE - buffered;
            const std::size_t copied = length < needed ? length : needed;
            copy_bytes(buffer_.data() + buffered, input, copied);
            input_offset += copied;

            if (buffered + copied == BLOCK_SIZE) {
                transform(buffer_.data());
            }
        }

        while (length - input_offset >= BLOCK_SIZE) {
            transform(input + input_offset);
            input_offset += BLOCK_SIZE;
        }

        copy_bytes(buffer_.data(), input + input_offset, length - input_offset);
    }

    void digest(void *out) const noexcept
    {
        MD5 finalized = *this;
        finalized.finalize(static_cast<std::uint8_t *>(out));
    }

private:
    std::array<std::uint32_t, 4> state_{
        0x67452301u,
        0xefcdab89u,
        0x98badcfeu,
        0x10325476u
    };
    std::array<std::uint8_t, BLOCK_SIZE> buffer_{};
    std::uint64_t message_size_ = 0;

    inline static constexpr std::array<std::uint32_t, 64> constants_{
        0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
        0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
        0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
        0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
        0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
        0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
        0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
        0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
        0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
        0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
        0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
        0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
        0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
        0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
        0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
        0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
    };

    inline static constexpr std::array<std::uint8_t, 64> shifts_{
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    static constexpr std::uint32_t rotate_left(std::uint32_t value,
                                                std::uint8_t amount) noexcept
    {
        return (value << amount) | (value >> (32u - amount));
    }

    static void copy_bytes(std::uint8_t *destination,
                           const std::uint8_t *source,
                           std::size_t length) noexcept
    {
        for (std::size_t i = 0; i < length; ++i) {
            destination[i] = source[i];
        }
    }

    static constexpr std::uint32_t load_le32(const std::uint8_t *input) noexcept
    {
        return static_cast<std::uint32_t>(input[0])
             | (static_cast<std::uint32_t>(input[1]) << 8u)
             | (static_cast<std::uint32_t>(input[2]) << 16u)
             | (static_cast<std::uint32_t>(input[3]) << 24u);
    }

    static constexpr void store_le32(std::uint8_t *output,
                                     std::uint32_t value) noexcept
    {
        output[0] = static_cast<std::uint8_t>(value);
        output[1] = static_cast<std::uint8_t>(value >> 8u);
        output[2] = static_cast<std::uint8_t>(value >> 16u);
        output[3] = static_cast<std::uint8_t>(value >> 24u);
    }

    void transform(const std::uint8_t *block) noexcept
    {
        std::array<std::uint32_t, 16> words{};
        for (std::size_t i = 0; i < words.size(); ++i) {
            words[i] = load_le32(block + i * 4);
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];

        for (std::size_t i = 0; i < 64; ++i) {
            std::uint32_t function;
            std::size_t word_index;

            if (i < 16) {
                function = (b & c) | (~b & d);
                word_index = i;
            } else if (i < 32) {
                function = (d & b) | (~d & c);
                word_index = (5 * i + 1) % 16;
            } else if (i < 48) {
                function = b ^ c ^ d;
                word_index = (3 * i + 5) % 16;
            } else {
                function = c ^ (b | ~d);
                word_index = (7 * i) % 16;
            }

            const std::uint32_t next_d = d;
            d = c;
            c = b;
            b += rotate_left(a + function + constants_[i] + words[word_index],
                             shifts_[i]);
            a = next_d;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
    }

    void finalize(std::uint8_t *out) noexcept
    {
        const std::uint64_t message_bits = message_size_ * 8u;
        const std::uint8_t marker = 0x80u;
        update(&marker, 1);

        const std::uint8_t zero = 0;
        while (message_size_ % BLOCK_SIZE != 56) {
            update(&zero, 1);
        }

        std::array<std::uint8_t, 8> encoded_length{};
        for (std::size_t i = 0; i < encoded_length.size(); ++i) {
            encoded_length[i] = static_cast<std::uint8_t>(message_bits >> (8u * i));
        }
        update(encoded_length.data(), encoded_length.size());

        for (std::size_t i = 0; i < state_.size(); ++i) {
            store_le32(out + i * 4, state_[i]);
        }
    }
};

#endif // MD5_HPP
