#pragma once
#include <cstdint>
#include <cstring>
#include <array>

// Public domain SHA-1 implementation
class SHA1 {
public:
    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf_[buf_len_++] = data[i];
            if (buf_len_ == 64) { process_block(); buf_len_ = 0; }
        }
        total_ += len;
    }
    std::array<uint8_t, 20> finalize() {
        uint64_t bits = total_ * 8;
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 56) { while (buf_len_ < 64) buf_[buf_len_++] = 0; process_block(); buf_len_ = 0; }
        while (buf_len_ < 56) buf_[buf_len_++] = 0;
        for (int i = 7; i >= 0; i--) buf_[buf_len_++] = (bits >> (i * 8)) & 0xFF;
        process_block();
        std::array<uint8_t, 20> digest;
        for (int i = 0; i < 5; i++) {
            digest[i*4]   = (h_[i] >> 24) & 0xFF;
            digest[i*4+1] = (h_[i] >> 16) & 0xFF;
            digest[i*4+2] = (h_[i] >> 8) & 0xFF;
            digest[i*4+3] = h_[i] & 0xFF;
        }
        return digest;
    }
    static std::string hash_hex(const uint8_t* data, size_t len) {
        SHA1 s; s.update(data, len);
        auto d = s.finalize();
        char hex[41];
        for (int i = 0; i < 20; i++) snprintf(hex + i*2, 3, "%02x", d[i]);
        return std::string(hex, 40);
    }
private:
    uint32_t h_[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t buf_[64] = {};
    size_t buf_len_ = 0;
    uint64_t total_ = 0;

    static uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
    void process_block() {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t(buf_[i*4]) << 24) | (uint32_t(buf_[i*4+1]) << 16) |
                   (uint32_t(buf_[i*4+2]) << 8) | buf_[i*4+3];
        for (int i = 16; i < 80; i++)
            w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a=h_[0], b=h_[1], c=h_[2], d=h_[3], e=h_[2];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = temp;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
    }
};
