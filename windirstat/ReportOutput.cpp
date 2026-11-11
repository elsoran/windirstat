// WinDirStat - Windows Directory Statistics
// Copyright © WinDirStat Team
//
// SPDX-License-Identifier: GPL-3.0-or-later
// Distributed WITHOUT ANY WARRANTY; see LICENSE.md for details.

#include "pch.h"
#include "ReportOutput.h"
#include <contrib/miniz/miniz.h>

static constexpr size_t ZipReadChunk = 4096;
static constexpr uint32_t ZipMax32 = 0xFFFFFFFF;
static constexpr uint16_t ZipVersion = 20;
static constexpr uint16_t ZipVersion64 = 45;
static constexpr uint16_t ZipFlags = 0x0808; // Sizes follow the data, UTF-8 name
static constexpr uint16_t ZipLocalSize = 30;
static constexpr uint16_t ZipCentralSize = 46;
static constexpr uint16_t ZipExtraSize = 20;
static constexpr uint16_t ZipDescriptorSize = 24;

template <class T>
static void PutLE(std::string& out, const T value)
{
    for (size_t i = 0; i < sizeof(T); ++i) out += static_cast<char>((value >> (8 * i)) & 0xFF);
}

static void PutZip64Extra(std::string& out, const uint64_t uncompressed, const uint64_t compressed)
{
    PutLE<uint16_t>(out, 0x0001);
    PutLE<uint16_t>(out, ZipExtraSize - 4);
    PutLE<uint64_t>(out, uncompressed);
    PutLE<uint64_t>(out, compressed);
}

// The size is unknown until the end, so the local header always has a ZIP64 field and the
// sizes follow the data in a 64-bit descriptor. Nothing is written twice. The central
// directory only uses ZIP64, and only asks for version 4.5, when a size or offset needs it,
// so older readers still open the usual small report.
struct ReportZipWriter::State : std::streambuf
{
    std::ostream& out;
    std::string name;
    tdefl_compressor compressor{};
    mz_ulong crc = MZ_CRC32_INIT;
    uint64_t uncompressed = 0;
    uint64_t compressed = 0;
    WORD dosTime = 0;
    WORD dosDate = 0;

    State(std::ostream& out, const std::string& name) : out(out), name(name) {}

    static mz_bool Put(const void* buf, const int len, void* user)
    {
        auto* state = static_cast<State*>(user);
        state->out.write(static_cast<const char*>(buf), len);
        state->compressed += static_cast<uint64_t>(len);
        return state->out.good() ? MZ_TRUE : MZ_FALSE;
    }

    bool Start()
    {
        SYSTEMTIME now;
        GetLocalTime(&now);
        FILETIME fileTime;
        SystemTimeToFileTime(&now, &fileTime);
        FileTimeToDosDateTime(&fileTime, &dosDate, &dosTime);

        if (tdefl_init(&compressor, Put, this, static_cast<int>(tdefl_create_comp_flags_from_zip_params(
            MZ_DEFAULT_LEVEL, -MZ_DEFAULT_WINDOW_BITS, MZ_DEFAULT_STRATEGY))) != TDEFL_STATUS_OKAY) return false;

        std::string header;
        PutLE<uint32_t>(header, 0x04034b50);
        PutLE<uint16_t>(header, ZipVersion);
        PutLE<uint16_t>(header, ZipFlags);
        PutLE<uint16_t>(header, MZ_DEFLATED);
        PutLE<uint16_t>(header, dosTime);
        PutLE<uint16_t>(header, dosDate);
        PutLE<uint32_t>(header, 0);
        PutLE<uint32_t>(header, 0);
        PutLE<uint32_t>(header, 0);
        PutLE<uint16_t>(header, static_cast<uint16_t>(name.size()));
        PutLE<uint16_t>(header, ZipExtraSize);
        header += name;
        PutZip64Extra(header, 0, 0);
        out.write(header.data(), static_cast<std::streamsize>(header.size()));
        return out.good();
    }

    bool Deflate(const char* data, const size_t size)
    {
        crc = mz_crc32(crc, reinterpret_cast<const unsigned char*>(data), size);
        uncompressed += size;
        return tdefl_compress_buffer(&compressor, data, size, TDEFL_NO_FLUSH) == TDEFL_STATUS_OKAY;
    }

    std::streamsize xsputn(const char* data, const std::streamsize size) override
    {
        return Deflate(data, static_cast<size_t>(size)) ? size : 0;
    }

    int_type overflow(const int_type ch) override
    {
        if (traits_type::eq_int_type(ch, traits_type::eof())) return traits_type::not_eof(ch);
        const char c = traits_type::to_char_type(ch);
        return Deflate(&c, 1) ? ch : traits_type::eof();
    }

    bool Finish()
    {
        if (tdefl_compress_buffer(&compressor, nullptr, 0, TDEFL_FINISH) != TDEFL_STATUS_DONE) return false;

        const auto nameSize = static_cast<uint16_t>(name.size());
        const uint64_t centralOffset = ZipLocalSize + nameSize + ZipExtraSize + compressed + ZipDescriptorSize;
        const bool zip64 = uncompressed >= ZipMax32 || compressed >= ZipMax32 || centralOffset >= ZipMax32;
        const uint64_t centralSize = ZipCentralSize + nameSize + (zip64 ? ZipExtraSize : 0);
        const uint16_t version = zip64 ? ZipVersion64 : ZipVersion;

        std::string trailer;
        PutLE<uint32_t>(trailer, 0x08074b50);
        PutLE<uint32_t>(trailer, static_cast<uint32_t>(crc));
        PutLE<uint64_t>(trailer, compressed);
        PutLE<uint64_t>(trailer, uncompressed);

        PutLE<uint32_t>(trailer, 0x02014b50);
        PutLE<uint16_t>(trailer, version);
        PutLE<uint16_t>(trailer, version);
        PutLE<uint16_t>(trailer, ZipFlags);
        PutLE<uint16_t>(trailer, MZ_DEFLATED);
        PutLE<uint16_t>(trailer, dosTime);
        PutLE<uint16_t>(trailer, dosDate);
        PutLE<uint32_t>(trailer, static_cast<uint32_t>(crc));
        PutLE<uint32_t>(trailer, zip64 ? ZipMax32 : static_cast<uint32_t>(compressed));
        PutLE<uint32_t>(trailer, zip64 ? ZipMax32 : static_cast<uint32_t>(uncompressed));
        PutLE<uint16_t>(trailer, nameSize);
        PutLE<uint16_t>(trailer, zip64 ? ZipExtraSize : 0);
        PutLE<uint16_t>(trailer, 0);
        PutLE<uint16_t>(trailer, 0);
        PutLE<uint16_t>(trailer, 0);
        PutLE<uint32_t>(trailer, 0);
        PutLE<uint32_t>(trailer, 0);
        trailer += name;
        if (zip64)
        {
            PutZip64Extra(trailer, uncompressed, compressed);

            PutLE<uint32_t>(trailer, 0x06064b50);
            PutLE<uint64_t>(trailer, 44);
            PutLE<uint16_t>(trailer, ZipVersion64);
            PutLE<uint16_t>(trailer, ZipVersion64);
            PutLE<uint32_t>(trailer, 0);
            PutLE<uint32_t>(trailer, 0);
            PutLE<uint64_t>(trailer, 1);
            PutLE<uint64_t>(trailer, 1);
            PutLE<uint64_t>(trailer, centralSize);
            PutLE<uint64_t>(trailer, centralOffset);

            PutLE<uint32_t>(trailer, 0x07064b50);
            PutLE<uint32_t>(trailer, 0);
            PutLE<uint64_t>(trailer, centralOffset + centralSize);
            PutLE<uint32_t>(trailer, 1);
        }

        PutLE<uint32_t>(trailer, 0x06054b50);
        PutLE<uint16_t>(trailer, 0);
        PutLE<uint16_t>(trailer, 0);
        PutLE<uint16_t>(trailer, 1);
        PutLE<uint16_t>(trailer, 1);
        PutLE<uint32_t>(trailer, static_cast<uint32_t>(centralSize));
        PutLE<uint32_t>(trailer, zip64 ? ZipMax32 : static_cast<uint32_t>(centralOffset));
        PutLE<uint16_t>(trailer, 0);

        out.write(trailer.data(), static_cast<std::streamsize>(trailer.size()));
        out.flush();
        return out.good();
    }
};

ReportZipWriter::ReportZipWriter(std::ostream& output, const std::string& entryName) :
    std::ostream(nullptr), m_state(std::make_unique<State>(output, entryName))
{
    rdbuf(m_state.get());
    if (!m_state->Start()) setstate(std::ios::badbit);
}

ReportZipWriter::~ReportZipWriter() = default;

bool ReportZipWriter::Finish()
{
    return good() && m_state->Finish();
}

static size_t ReadArchiveCallback(void* opaque, mz_uint64 ofs, void* buf, size_t n)
{
    auto* in = static_cast<std::ifstream*>(opaque);
    // A read that reached EOF leaves the stream failed, and miniz then seeks back to a local header.
    in->clear();
    in->seekg(static_cast<std::streamoff>(ofs));
    in->read(static_cast<char*>(buf), static_cast<std::streamsize>(n));
    return static_cast<size_t>(in->gcount());
}

struct ReportZipLoad::State : std::streambuf
{
    std::ifstream file;
    mz_zip_archive zip{};
    mz_zip_reader_extract_iter_state* iter = nullptr;
    std::istream stream{ this };
    char buffer[ZipReadChunk] = {};
    bool json = false;

    ~State()
    {
        if (iter != nullptr) mz_zip_reader_extract_iter_free(iter);
        mz_zip_reader_end(&zip);
    }

    int_type underflow() override
    {
        if (iter == nullptr) return traits_type::eof();
        const size_t got = mz_zip_reader_extract_iter_read(iter, buffer, sizeof buffer);
        if (got == 0) return traits_type::eof();
        setg(buffer, buffer, buffer + got);
        return traits_type::to_int_type(*gptr());
    }
};

ReportZipLoad::ReportZipLoad() : m_state(std::make_unique<State>()) {}
ReportZipLoad::~ReportZipLoad() = default;

bool ReportZipLoad::Open(const std::wstring& path)
{
    State& state = *m_state;
    state.file.open(path, std::ios::binary);
    if (!state.file.is_open()) return false;
    state.file.seekg(0, std::ios::end);

    state.zip.m_pRead = ReadArchiveCallback;
    state.zip.m_pIO_opaque = &state.file;
    if (!mz_zip_reader_init(&state.zip, static_cast<mz_uint64>(state.file.tellg()), 0)) return false;

    unsigned files = 0;
    mz_uint index = 0;
    std::string entryName;
    for (mz_uint i = 0; i < mz_zip_reader_get_num_files(&state.zip); ++i)
    {
        mz_zip_archive_file_stat stat{};
        if (!mz_zip_reader_file_stat(&state.zip, i, &stat)) return false;
        if (stat.m_is_directory) continue;
        ++files;
        index = i;
        entryName = stat.m_filename;
    }
    if (files != 1) return false;

    state.json = entryName.size() >= 5 && _stricmp(entryName.c_str() + entryName.size() - 5, ".json") == 0;
    state.iter = mz_zip_reader_extract_iter_new(&state.zip, index, 0);
    return state.iter != nullptr;
}

std::istream& ReportZipLoad::Stream()
{
    return m_state->stream;
}

bool ReportZipLoad::Json() const
{
    return m_state->json;
}

bool ReportZipLoad::Finish()
{
    // The JSON parser stops at ']'. Read the rest so the CRC covers the whole entry.
    State& state = *m_state;
    while (mz_zip_reader_extract_iter_read(state.iter, state.buffer, sizeof state.buffer) != 0) {}
    const bool crcOk = mz_zip_reader_extract_iter_free(state.iter) == MZ_TRUE;
    state.iter = nullptr;
    return crcOk;
}
