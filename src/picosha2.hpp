#ifndef PICOSHA2_HPP
#define PICOSHA2_HPP

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace picosha2
{
    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    inline uint32_t bsig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    inline uint32_t bsig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    inline uint32_t ssig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    inline uint32_t ssig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    inline void append_uint64_be(std::vector<unsigned char> &v, uint64_t x)
    {
        for (int i = 7; i >= 0; --i)
            v.push_back(static_cast<unsigned char>((x >> (8 * i)) & 0xff));
    }

    inline std::string bytes_to_hex_string(const std::vector<unsigned char> &bytes)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto b : bytes)
            oss << std::setw(2) << static_cast<int>(b);
        return oss.str();
    }

    inline std::string hash256_hex_string(const std::string &src)
    {
        std::vector<unsigned char> bytes(src.begin(), src.end());
        // padding
        uint64_t l = bytes.size() * 8ULL;
        bytes.push_back(0x80);
        while ((bytes.size() % 64) != 56)
            bytes.push_back(0x00);
        append_uint64_be(bytes, l);

        uint32_t h[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

        static const uint32_t k[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

        for (size_t chunk = 0; chunk < bytes.size(); chunk += 64)
        {
            uint32_t w[64];
            for (int t = 0; t < 16; ++t)
            {
                w[t] = (bytes[chunk + 4 * t] << 24) | (bytes[chunk + 4 * t + 1] << 16) |
                       (bytes[chunk + 4 * t + 2] << 8) | (bytes[chunk + 4 * t + 3]);
            }
            for (int t = 16; t < 64; ++t)
                w[t] = ssig1(w[t - 2]) + w[t - 7] + ssig0(w[t - 15]) + w[t - 16];
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int t = 0; t < 64; ++t)
            {
                uint32_t T1 = hh + bsig1(e) + ch(e, f, g) + k[t] + w[t];
                uint32_t T2 = bsig0(a) + maj(a, b, c);
                hh = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }
            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hh;
        }

        std::vector<unsigned char> digest;
        digest.reserve(32);
        for (int i = 0; i < 8; ++i)
        {
            digest.push_back((h[i] >> 24) & 0xff);
            digest.push_back((h[i] >> 16) & 0xff);
            digest.push_back((h[i] >> 8) & 0xff);
            digest.push_back(h[i] & 0xff);
        }
        return bytes_to_hex_string(digest);
    }

} // namespace picosha2

#endif // PICOSHA2_HPP
