#include "Prefetch.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>

namespace trace::scanners {

using NTSTATUS = LONG;
using RtlGetCompressionWorkSpaceSize_t = NTSTATUS(NTAPI*)(USHORT, PULONG, PULONG);
using RtlDecompressBufferEx_t = NTSTATUS(NTAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);

#ifndef COMPRESSION_FORMAT_XPRESS
#define COMPRESSION_FORMAT_XPRESS (0x0003)
#endif
#ifndef COMPRESSION_FORMAT_XPRESS_HUFF
#define COMPRESSION_FORMAT_XPRESS_HUFF (0x0004)
#endif

bool TryDecompressPrefetch(const uint8_t* mappedData, size_t fileSize, std::vector<uint8_t>& outDecompressed) {
    if (fileSize < 8) return false;

    uint32_t header = 0;
    std::memcpy(&header, mappedData, sizeof(uint32_t));

    if ((header & 0x00FFFFFFu) != 0x004D414Du) {
        return false;
    }

    static HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    static auto pRtlGetWorkSpaceSize = reinterpret_cast<RtlGetCompressionWorkSpaceSize_t>(
        hNtdll ? GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize") : nullptr);
    static auto pRtlDecompressBufferEx = reinterpret_cast<RtlDecompressBufferEx_t>(
        hNtdll ? GetProcAddress(hNtdll, "RtlDecompressBufferEx") : nullptr);

    if (!pRtlGetWorkSpaceSize || !pRtlDecompressBufferEx) return false;

    uint32_t uncompressedSize = 0;
    std::memcpy(&uncompressedSize, mappedData + 4, sizeof(uint32_t));
    if (uncompressedSize == 0 || uncompressedSize > (32u * 1024u * 1024u)) {
        return false;
    }

    uint8_t flags = static_cast<uint8_t>((header >> 24) & 0x0Fu);
    USHORT format = (flags == 3) ? COMPRESSION_FORMAT_XPRESS : COMPRESSION_FORMAT_XPRESS_HUFF;

    bool hasChecksum = ((header >> 24) & 0x80u) != 0;
    size_t compressedOffset = hasChecksum ? 12 : 8;
    if (fileSize <= compressedOffset) return false;

    ULONG wsBufferSize = 0, wsFragSize = 0;
    if (pRtlGetWorkSpaceSize(format, &wsBufferSize, &wsFragSize) != 0) return false;

    std::vector<uint8_t> workspace(wsBufferSize);
    outDecompressed.resize(uncompressedSize);

    ULONG finalSize = 0;
    NTSTATUS status = pRtlDecompressBufferEx(
        format,
        outDecompressed.data(),
        uncompressedSize,
        const_cast<PUCHAR>(mappedData + compressedOffset),
        static_cast<ULONG>(fileSize - compressedOffset),
        &finalSize,
        workspace.data()
    );
    return (status == 0 && finalSize > 0);
}

}