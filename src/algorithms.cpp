#include "secure_delete.hpp"
#include <vector>
#include <cstdint>

std::vector<std::vector<uint8_t>> generate_algorithm_passes(
    OverwriteAlgorithm alg,
    uint64_t file_size)
{
    std::vector<std::vector<uint8_t>> passes;

    if (file_size == 0)
        file_size = 1;

    auto P = [&](uint8_t v)
    {
        return std::vector<uint8_t>(file_size, v);
    };

    if (alg == OverwriteAlgorithm::SIMPLE)
    {
        passes.push_back(P(0x00));
        passes.push_back(P(0xFF));
        passes.push_back(std::vector<uint8_t>(file_size));
        return passes;
    }

    if (alg == OverwriteAlgorithm::DOD)
    {
        passes.push_back(P(0x00));
        passes.push_back(P(0xFF));
        passes.push_back(std::vector<uint8_t>(file_size));
        passes.push_back(P(0x00));
        passes.push_back(P(0xFF));
        passes.push_back(std::vector<uint8_t>(file_size));
        passes.push_back(std::vector<uint8_t>(file_size));
        return passes;
    }

    if (alg == OverwriteAlgorithm::NSA)
    {
        passes.push_back(P(0x00));
        passes.push_back(P(0xFF));
        passes.push_back(std::vector<uint8_t>(file_size));
        passes.push_back(std::vector<uint8_t>(file_size));
        passes.push_back(std::vector<uint8_t>(file_size));
        passes.push_back(P(0xAA));
        passes.push_back(std::vector<uint8_t>(file_size));
        return passes;
    }

    if (alg == OverwriteAlgorithm::GUTMANN)
    {
        static const uint8_t gut_pats[35] = {
            0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB,
            0x49, 0x24, 0x92, 0x00, 0xFF, 0x6D, 0xB6, 0xDB};

        for (int i = 0; i < 35; i++)
            passes.push_back(P(gut_pats[i]));

        return passes;
    }

    return passes;
}
