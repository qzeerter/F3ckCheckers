#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>

namespace trace::scanners {

bool TryDecompressPrefetch(const uint8_t* mappedData, size_t fileSize, std::vector<uint8_t>& outDecompressed);

}