/**
 * @file base64.hpp
 * @author Steven
 * @brief A header-only implementation for base64 encoding
 * @version 0.2
 * @date 2026-08-14
 */

#include <array>
#include <cstddef>
#include <cstdint>

template<std::size_t S>
constexpr std::array<std::uint8_t, 4 * (S / 3 + (S % 3 != 0))>
base64_encode(const std::array<std::uint8_t, S> &input) noexcept {
    constexpr auto base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::array<std::uint8_t, 4 * (S / 3 + (S % 3 != 0))> output{};
    std::size_t output_index = 0;
    for (std::size_t i = 0; i < S; i += 3) {
        const std::uint32_t triple =
            (static_cast<std::uint32_t>(input[i]) << 16) |
            (static_cast<std::uint32_t>(i + 1 < S ? input[i + 1] : 0) << 8) |
            static_cast<std::uint32_t>(i + 2 < S ? input[i + 2] : 0);
        output[output_index++] = base64_chars[(triple >> 18) & 0x3F];
        output[output_index++] = base64_chars[(triple >> 12) & 0x3F];
        output[output_index++] = (i + 1 < S) ? base64_chars[(triple >> 6) & 0x3F] : '=';
        output[output_index++] = (i + 2 < S) ? base64_chars[triple & 0x3F] : '=';
    }
    return output;
}
