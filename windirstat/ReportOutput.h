// WinDirStat - Windows Directory Statistics
// Copyright © WinDirStat Team
//
// SPDX-License-Identifier: GPL-3.0-or-later
// Distributed WITHOUT ANY WARRANTY; see LICENSE.md for details.

#pragma once

#include "pch.h"

// Deflates everything written to it into a zip archive with one entry, at compression level 6.
// Finish writes the central directory. Without it the partial archive is left in place.
class ReportZipWriter : public std::ostream
{
public:
    ReportZipWriter(std::ostream& output, const std::string& entryName);
    ~ReportZipWriter() override;
    ReportZipWriter(const ReportZipWriter&) = delete;
    ReportZipWriter& operator=(const ReportZipWriter&) = delete;

    bool Finish();

private:
    struct State;
    std::unique_ptr<State> m_state;
};

class ReportZipLoad
{
public:
    ReportZipLoad();
    ~ReportZipLoad();
    ReportZipLoad(const ReportZipLoad&) = delete;
    ReportZipLoad& operator=(const ReportZipLoad&) = delete;

    // False unless the archive has exactly one file entry. Directory entries are ignored.
    bool Open(const std::wstring& path);
    std::istream& Stream();
    bool Json() const;
    // Reads the rest of the entry and checks its CRC. False on a short read or a mismatch.
    bool Finish();

private:
    struct State;
    std::unique_ptr<State> m_state;
};
