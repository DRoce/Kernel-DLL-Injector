#define NOMINMAX

#include <Windows.h>
#include <bcrypt.h>
#include <Psapi.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct ServiceInfo
{
    std::wstring name;
    std::wstring display_name;
    std::wstring image_path;
    std::wstring normalized_path;
    std::wstring start_type;
    std::wstring state;
};

struct DosLink
{
    std::wstring name;
    std::wstring target;
};

struct StaticAnalysis
{
    int ioctl_score = 0;
    std::set<std::wstring> indicators;
    std::set<std::wstring> dos_links;
};

struct DriverRecord
{
    std::wstring sha256;
    std::wstring base_name;
    std::wstring image_path;
    std::wstring normalized_path;
    std::wstring service_name;
    std::wstring service_display;
    std::wstring service_start;
    std::wstring service_state;
    std::wstring company;
    std::wstring file_description;
    std::wstring file_version;
    int ioctl_score = 0;
    std::wstring ioctl_indicators;
    std::wstring dos_links;
};

static const std::vector<std::wstring> kColumns = {
    L"sha256",
    L"base_name",
    L"image_path",
    L"normalized_path",
    L"service_name",
    L"service_display",
    L"service_start",
    L"service_state",
    L"company",
    L"file_description",
    L"file_version",
    L"ioctl_score",
    L"ioctl_indicators",
    L"dos_links",
};

static std::wstring to_lower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    return value;
}

static bool starts_with_i(const std::wstring& value, const std::wstring& prefix)
{
    if (value.size() < prefix.size())
        return false;
    return to_lower(value.substr(0, prefix.size())) == to_lower(prefix);
}

static size_t find_i(const std::wstring& value, const std::wstring& needle, size_t start = 0)
{
    const std::wstring lowered_value = to_lower(value);
    const std::wstring lowered_needle = to_lower(needle);
    return lowered_value.find(lowered_needle, start);
}

static bool contains_i(const std::wstring& value, const std::wstring& needle)
{
    return find_i(value, needle) != std::wstring::npos;
}

static std::wstring trim(std::wstring value)
{
    while (!value.empty() && iswspace(value.front()))
        value.erase(value.begin());
    while (!value.empty() && iswspace(value.back()))
        value.pop_back();
    return value;
}

static std::wstring replace_char(std::wstring value, wchar_t from, wchar_t to)
{
    std::replace(value.begin(), value.end(), from, to);
    return value;
}

static std::wstring clean_cell(std::wstring value)
{
    for (wchar_t& ch : value)
    {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n')
            ch = L' ';
    }
    return trim(value);
}

static std::wstring join_set(const std::set<std::wstring>& values, const std::wstring& separator)
{
    std::wstring result;
    for (const auto& value : values)
    {
        if (!result.empty())
            result += separator;
        result += value;
    }
    return result;
}

static std::string utf8(const std::wstring& value)
{
    if (value.empty())
        return {};

    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};

    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), needed, nullptr, nullptr);
    return result;
}

static std::wstring from_utf8(const std::string& value)
{
    if (value.empty())
        return {};

    const int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0)
        return {};

    std::wstring result(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), needed);
    return result;
}

static std::wstring get_windows_directory()
{
    wchar_t buffer[MAX_PATH] = {};
    const UINT length = GetWindowsDirectoryW(buffer, static_cast<UINT>(std::size(buffer)));
    if (length == 0 || length >= std::size(buffer))
        return L"C:\\Windows";
    return buffer;
}

static std::wstring expand_environment(std::wstring value)
{
    value = trim(value);
    if (value.empty())
        return value;

    DWORD needed = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (needed == 0)
        return value;

    std::wstring expanded(needed, L'\0');
    DWORD written = ExpandEnvironmentStringsW(value.c_str(), expanded.data(), needed);
    if (written == 0 || written > needed)
        return value;

    if (!expanded.empty() && expanded.back() == L'\0')
        expanded.pop_back();
    return expanded;
}

static std::wstring strip_path_arguments(std::wstring value)
{
    value = trim(value);
    if (value.empty())
        return value;

    if (value.front() == L'"')
    {
        const size_t end_quote = value.find(L'"', 1);
        if (end_quote != std::wstring::npos)
            return value.substr(1, end_quote - 1);
    }

    const size_t sys_pos = find_i(value, L".sys");
    if (sys_pos != std::wstring::npos)
        return value.substr(0, sys_pos + 4);

    const size_t first_space = value.find(L' ');
    if (first_space != std::wstring::npos)
        return value.substr(0, first_space);

    return value;
}

static std::vector<std::pair<std::wstring, std::wstring>> build_volume_device_map()
{
    std::vector<std::pair<std::wstring, std::wstring>> mappings;

    wchar_t drives[512] = {};
    const DWORD chars = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)), drives);
    if (chars == 0 || chars >= std::size(drives))
        return mappings;

    for (const wchar_t* cursor = drives; *cursor; cursor += wcslen(cursor) + 1)
    {
        std::wstring drive = cursor;
        if (!drive.empty() && drive.back() == L'\\')
            drive.pop_back();

        wchar_t target[1024] = {};
        if (QueryDosDeviceW(drive.c_str(), target, static_cast<DWORD>(std::size(target))) != 0)
            mappings.emplace_back(drive, target);
    }

    std::sort(mappings.begin(), mappings.end(), [](const auto& left, const auto& right) {
        return left.second.size() > right.second.size();
    });
    return mappings;
}

static std::wstring device_path_to_dos_path(const std::wstring& path)
{
    static const auto mappings = build_volume_device_map();
    for (const auto& [drive, target] : mappings)
    {
        if (starts_with_i(path, target))
            return drive + path.substr(target.size());
    }
    return path;
}

static std::wstring normalize_path(std::wstring path)
{
    path = strip_path_arguments(expand_environment(path));
    path = replace_char(path, L'/', L'\\');

    if (path.empty())
        return path;

    const std::wstring windows_dir = get_windows_directory();
    const std::wstring system_drive = windows_dir.size() >= 2 ? windows_dir.substr(0, 2) : L"C:";

    if (starts_with_i(path, L"\\??\\"))
        path = path.substr(4);
    else if (starts_with_i(path, L"\\\\?\\"))
        path = path.substr(4);

    if (starts_with_i(path, L"\\SystemRoot\\"))
        path = windows_dir + path.substr(std::wstring(L"\\SystemRoot").size());
    else if (starts_with_i(path, L"SystemRoot\\"))
        path = windows_dir + L"\\" + path.substr(std::wstring(L"SystemRoot\\").size());
    else if (starts_with_i(path, L"\\Windows\\"))
        path = system_drive + path;
    else if (starts_with_i(path, L"System32\\"))
        path = windows_dir + L"\\" + path;
    else if (starts_with_i(path, L"\\Device\\"))
        path = device_path_to_dos_path(path);

    return path;
}

static std::wstring filename_from_path(const std::wstring& path)
{
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return path;
    return path.substr(slash + 1);
}

static bool file_exists(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static std::wstring hex_bytes(const std::vector<unsigned char>& bytes)
{
    std::wostringstream stream;
    stream << std::hex << std::setfill(L'0');
    for (const unsigned char byte : bytes)
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    return stream.str();
}

static std::wstring sha256_file(const std::wstring& path)
{
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return {};

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::wstring result;

    do
    {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            break;

        DWORD object_length = 0;
        DWORD hash_length = 0;
        DWORD written = 0;

        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &written, 0) < 0)
            break;
        if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &written, 0) < 0)
            break;

        std::vector<unsigned char> hash_object(object_length);
        std::vector<unsigned char> hash_bytes_buffer(hash_length);

        if (BCryptCreateHash(algorithm, &hash, hash_object.data(), object_length, nullptr, 0, 0) < 0)
            break;

        std::vector<unsigned char> buffer(64 * 1024);
        DWORD bytes_read = 0;
        bool read_failed = false;
        bool hash_failed = false;
        while (true)
        {
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr))
            {
                read_failed = true;
                break;
            }
            if (bytes_read == 0)
                break;

            if (BCryptHashData(hash, buffer.data(), bytes_read, 0) < 0)
            {
                hash_failed = true;
                break;
            }
        }

        if (read_failed || hash_failed)
            break;

        if (BCryptFinishHash(hash, hash_bytes_buffer.data(), hash_length, 0) < 0)
            break;

        result = hex_bytes(hash_bytes_buffer);
    } while (false);

    if (hash)
        BCryptDestroyHash(hash);
    if (algorithm)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    return result;
}

static std::vector<unsigned char> read_file_bytes(const std::wstring& path, uintmax_t max_size = 64ull * 1024ull * 1024ull)
{
    std::error_code ec;
    const uintmax_t size = fs::file_size(path, ec);
    if (ec || size == 0 || size > max_size)
        return {};

    std::ifstream input(fs::path(path), std::ios::binary);
    if (!input)
        return {};

    std::vector<unsigned char> data(static_cast<size_t>(size));
    input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!input)
        return {};
    return data;
}

static std::wstring query_version_string(const std::vector<unsigned char>& version_data, WORD language, WORD code_page, const wchar_t* key)
{
    wchar_t sub_block[128] = {};
    swprintf_s(sub_block, L"\\StringFileInfo\\%04x%04x\\%s", language, code_page, key);

    void* value = nullptr;
    UINT value_length = 0;
    if (!VerQueryValueW(version_data.data(), sub_block, &value, &value_length) || !value || value_length == 0)
        return {};
    return static_cast<const wchar_t*>(value);
}

static std::map<std::wstring, std::wstring> get_version_fields(const std::wstring& path)
{
    std::map<std::wstring, std::wstring> fields;

    DWORD handle = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0)
        return fields;

    std::vector<unsigned char> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data()))
        return fields;

    struct Translation
    {
        WORD language;
        WORD code_page;
    };

    Translation* translations = nullptr;
    UINT translation_bytes = 0;
    WORD language = 0x0409;
    WORD code_page = 0x04B0;

    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translations), &translation_bytes) &&
        translations &&
        translation_bytes >= sizeof(Translation))
    {
        language = translations[0].language;
        code_page = translations[0].code_page;
    }

    fields[L"CompanyName"] = query_version_string(data, language, code_page, L"CompanyName");
    fields[L"FileDescription"] = query_version_string(data, language, code_page, L"FileDescription");
    fields[L"FileVersion"] = query_version_string(data, language, code_page, L"FileVersion");

    if (fields[L"FileVersion"].empty())
    {
        VS_FIXEDFILEINFO* fixed = nullptr;
        UINT fixed_length = 0;
        if (VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&fixed), &fixed_length) && fixed && fixed->dwSignature == 0xFEEF04BD)
        {
            std::wostringstream version;
            version << HIWORD(fixed->dwFileVersionMS) << L'.'
                    << LOWORD(fixed->dwFileVersionMS) << L'.'
                    << HIWORD(fixed->dwFileVersionLS) << L'.'
                    << LOWORD(fixed->dwFileVersionLS);
            fields[L"FileVersion"] = version.str();
        }
    }

    return fields;
}

static std::wstring service_start_type(DWORD value)
{
    switch (value)
    {
    case SERVICE_BOOT_START: return L"boot";
    case SERVICE_SYSTEM_START: return L"system";
    case SERVICE_AUTO_START: return L"auto";
    case SERVICE_DEMAND_START: return L"demand";
    case SERVICE_DISABLED: return L"disabled";
    default: return L"unknown";
    }
}

static std::wstring service_state(DWORD value)
{
    switch (value)
    {
    case SERVICE_STOPPED: return L"stopped";
    case SERVICE_START_PENDING: return L"start_pending";
    case SERVICE_STOP_PENDING: return L"stop_pending";
    case SERVICE_RUNNING: return L"running";
    case SERVICE_CONTINUE_PENDING: return L"continue_pending";
    case SERVICE_PAUSE_PENDING: return L"pause_pending";
    case SERVICE_PAUSED: return L"paused";
    default: return L"unknown";
    }
}

static std::vector<ServiceInfo> collect_driver_services()
{
    std::vector<ServiceInfo> services;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
        return services;

    DWORD bytes_needed = 0;
    DWORD services_returned = 0;
    DWORD resume_handle = 0;
    EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_DRIVER,
        SERVICE_STATE_ALL,
        nullptr,
        0,
        &bytes_needed,
        &services_returned,
        &resume_handle,
        nullptr);

    if (GetLastError() != ERROR_MORE_DATA || bytes_needed == 0)
    {
        CloseServiceHandle(scm);
        return services;
    }

    std::vector<unsigned char> buffer(bytes_needed);
    resume_handle = 0;
    if (!EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytes_needed,
            &services_returned,
            &resume_handle,
            nullptr))
    {
        CloseServiceHandle(scm);
        return services;
    }

    const auto* rows = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    for (DWORD index = 0; index < services_returned; ++index)
    {
        ServiceInfo info;
        info.name = rows[index].lpServiceName ? rows[index].lpServiceName : L"";
        info.display_name = rows[index].lpDisplayName ? rows[index].lpDisplayName : L"";
        info.state = service_state(rows[index].ServiceStatusProcess.dwCurrentState);

        SC_HANDLE service = OpenServiceW(scm, info.name.c_str(), SERVICE_QUERY_CONFIG);
        if (service)
        {
            DWORD config_needed = 0;
            QueryServiceConfigW(service, nullptr, 0, &config_needed);
            if (config_needed > 0)
            {
                std::vector<unsigned char> config_buffer(config_needed);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_buffer.data());
                if (QueryServiceConfigW(service, config, config_needed, &config_needed))
                {
                    info.image_path = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
                    info.normalized_path = normalize_path(info.image_path);
                    info.start_type = service_start_type(config->dwStartType);
                }
            }
            CloseServiceHandle(service);
        }

        services.push_back(std::move(info));
    }

    CloseServiceHandle(scm);
    return services;
}

static std::vector<DosLink> collect_dos_links()
{
    std::vector<DosLink> links;
    std::vector<wchar_t> names(64 * 1024);

    DWORD chars = QueryDosDeviceW(nullptr, names.data(), static_cast<DWORD>(names.size()));
    if (chars == 0)
        return links;

    for (const wchar_t* cursor = names.data(); *cursor; cursor += wcslen(cursor) + 1)
    {
        std::vector<wchar_t> target(4096);
        if (QueryDosDeviceW(cursor, target.data(), static_cast<DWORD>(target.size())) == 0)
            continue;

        links.push_back({cursor, target.data()});
    }

    return links;
}

static bool rva_to_offset(
    DWORD rva,
    const IMAGE_SECTION_HEADER* sections,
    WORD section_count,
    DWORD size_of_headers,
    size_t file_size,
    size_t& offset)
{
    if (rva < size_of_headers && rva < file_size)
    {
        offset = rva;
        return true;
    }

    for (WORD index = 0; index < section_count; ++index)
    {
        const auto& section = sections[index];
        const uint64_t virtual_address = section.VirtualAddress;
        const uint64_t span = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (rva >= virtual_address && rva < virtual_address + span)
        {
            const uint64_t candidate = static_cast<uint64_t>(section.PointerToRawData) + (rva - virtual_address);
            if (candidate < file_size)
            {
                offset = static_cast<size_t>(candidate);
                return true;
            }
        }
    }

    return false;
}

static std::string read_ascii_string(const std::vector<unsigned char>& data, size_t offset, size_t max_chars = 512)
{
    std::string value;
    for (size_t index = offset; index < data.size() && value.size() < max_chars; ++index)
    {
        const unsigned char ch = data[index];
        if (ch == 0)
            break;
        if (ch < 32 || ch > 126)
            break;
        value.push_back(static_cast<char>(ch));
    }
    return value;
}

static std::set<std::wstring> parse_pe_imports(const std::vector<unsigned char>& data)
{
    std::set<std::wstring> imports;
    if (data.size() < sizeof(IMAGE_DOS_HEADER))
        return imports;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return imports;

    const size_t nt_offset = static_cast<size_t>(dos->e_lfanew);
    if (nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) >= data.size())
        return imports;

    const auto* signature = reinterpret_cast<const DWORD*>(data.data() + nt_offset);
    if (*signature != IMAGE_NT_SIGNATURE)
        return imports;

    const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(data.data() + nt_offset + sizeof(DWORD));
    const unsigned char* optional_base = data.data() + nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optional_base + sizeof(WORD) > data.data() + data.size())
        return imports;

    const WORD magic = *reinterpret_cast<const WORD*>(optional_base);
    IMAGE_DATA_DIRECTORY import_directory = {};
    const IMAGE_SECTION_HEADER* sections = nullptr;
    DWORD size_of_headers = 0;
    bool is_64_bit = false;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > data.size())
            return imports;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data.data() + nt_offset);
        import_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        sections = IMAGE_FIRST_SECTION(nt);
        size_of_headers = nt->OptionalHeader.SizeOfHeaders;
        is_64_bit = true;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (nt_offset + sizeof(IMAGE_NT_HEADERS32) > data.size())
            return imports;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(data.data() + nt_offset);
        import_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        sections = IMAGE_FIRST_SECTION(nt);
        size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    }
    else
    {
        return imports;
    }

    if (!import_directory.VirtualAddress)
        return imports;

    size_t descriptor_offset = 0;
    if (!rva_to_offset(import_directory.VirtualAddress, sections, file_header->NumberOfSections, size_of_headers, data.size(), descriptor_offset))
        return imports;

    for (size_t descriptor_index = 0; descriptor_index < 256; ++descriptor_index)
    {
        const size_t current_descriptor = descriptor_offset + descriptor_index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (current_descriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR) > data.size())
            break;

        const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(data.data() + current_descriptor);
        if (descriptor->Name == 0 && descriptor->FirstThunk == 0)
            break;

        size_t dll_name_offset = 0;
        std::wstring dll_name;
        if (descriptor->Name && rva_to_offset(descriptor->Name, sections, file_header->NumberOfSections, size_of_headers, data.size(), dll_name_offset))
            dll_name = from_utf8(read_ascii_string(data, dll_name_offset));

        const DWORD thunk_rva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
        size_t thunk_offset = 0;
        if (!thunk_rva || !rva_to_offset(thunk_rva, sections, file_header->NumberOfSections, size_of_headers, data.size(), thunk_offset))
            continue;

        for (size_t thunk_index = 0; thunk_index < 4096; ++thunk_index)
        {
            uint64_t thunk_value = 0;
            if (is_64_bit)
            {
                const size_t current_thunk = thunk_offset + thunk_index * sizeof(uint64_t);
                if (current_thunk + sizeof(uint64_t) > data.size())
                    break;
                thunk_value = *reinterpret_cast<const uint64_t*>(data.data() + current_thunk);
                if (thunk_value == 0)
                    break;
                if ((thunk_value & IMAGE_ORDINAL_FLAG64) != 0)
                    continue;
            }
            else
            {
                const size_t current_thunk = thunk_offset + thunk_index * sizeof(uint32_t);
                if (current_thunk + sizeof(uint32_t) > data.size())
                    break;
                thunk_value = *reinterpret_cast<const uint32_t*>(data.data() + current_thunk);
                if (thunk_value == 0)
                    break;
                if ((thunk_value & IMAGE_ORDINAL_FLAG32) != 0)
                    continue;
            }

            size_t import_name_offset = 0;
            if (!rva_to_offset(static_cast<DWORD>(thunk_value), sections, file_header->NumberOfSections, size_of_headers, data.size(), import_name_offset))
                continue;
            if (import_name_offset + sizeof(WORD) >= data.size())
                continue;

            const std::wstring import_name = from_utf8(read_ascii_string(data, import_name_offset + sizeof(WORD)));
            if (!import_name.empty())
                imports.insert(dll_name.empty() ? import_name : dll_name + L"!" + import_name);
        }
    }

    return imports;
}

static std::vector<std::wstring> extract_printable_strings(const std::vector<unsigned char>& data)
{
    std::vector<std::wstring> strings;

    std::wstring current;
    for (unsigned char byte : data)
    {
        if (byte >= 32 && byte <= 126)
        {
            current.push_back(static_cast<wchar_t>(byte));
        }
        else
        {
            if (current.size() >= 4)
                strings.push_back(current);
            current.clear();
        }
    }
    if (current.size() >= 4)
        strings.push_back(current);

    current.clear();
    for (size_t index = 0; index + 1 < data.size(); index += 2)
    {
        const wchar_t ch = static_cast<wchar_t>(data[index] | (data[index + 1] << 8));
        if (ch >= 32 && ch <= 126)
        {
            current.push_back(ch);
        }
        else
        {
            if (current.size() >= 4)
                strings.push_back(current);
            current.clear();
        }
    }
    if (current.size() >= 4)
        strings.push_back(current);

    return strings;
}

static bool is_device_name_char(wchar_t ch)
{
    return iswalnum(ch) ||
        ch == L'\\' ||
        ch == L'/' ||
        ch == L'_' ||
        ch == L'-' ||
        ch == L'.' ||
        ch == L':' ||
        ch == L'{' ||
        ch == L'}';
}

static void extract_device_names(const std::wstring& text, std::set<std::wstring>& names)
{
    const std::vector<std::wstring> prefixes = {L"\\Device\\", L"\\DosDevices\\"};
    for (const auto& prefix : prefixes)
    {
        size_t position = 0;
        while ((position = find_i(text, prefix, position)) != std::wstring::npos)
        {
            size_t end = position;
            while (end < text.size() && is_device_name_char(text[end]) && (end - position) < 160)
                ++end;

            if (end > position + prefix.size())
                names.insert(text.substr(position, end - position));

            position = end;
        }
    }
}

static bool add_indicator(std::set<std::wstring>& indicators, const std::wstring& value, int weight, int& score)
{
    if (indicators.insert(value).second)
    {
        score += weight;
        return true;
    }
    return false;
}

static StaticAnalysis analyze_driver_file(const std::wstring& path, const std::vector<DosLink>& dos_links)
{
    StaticAnalysis analysis;
    const auto data = read_file_bytes(path);
    if (data.empty())
        return analysis;

    const auto imports = parse_pe_imports(data);
    for (const auto& import_name : imports)
    {
        const std::wstring lowered = to_lower(import_name);
        if (contains_i(lowered, L"!iocreatedevice") || contains_i(lowered, L"!iocreatedevicesecure"))
            add_indicator(analysis.indicators, L"import:IoCreateDevice", 2, analysis.ioctl_score);
        if (contains_i(lowered, L"!iocreatesymboliclink"))
            add_indicator(analysis.indicators, L"import:IoCreateSymbolicLink", 2, analysis.ioctl_score);
        if (contains_i(lowered, L"!wdfdevicecreate"))
            add_indicator(analysis.indicators, L"import:WdfDeviceCreate", 2, analysis.ioctl_score);
        if (contains_i(lowered, L"!wdfioqueuecreate"))
            add_indicator(analysis.indicators, L"import:WdfIoQueueCreate", 2, analysis.ioctl_score);
        if (contains_i(lowered, L"!wdfrequestretrieveinputbuffer") || contains_i(lowered, L"!wdfrequestretrieveoutputbuffer"))
            add_indicator(analysis.indicators, L"import:WdfRequestBuffer", 1, analysis.ioctl_score);
    }

    std::set<std::wstring> device_names;
    const auto strings = extract_printable_strings(data);
    for (const auto& text : strings)
    {
        if (contains_i(text, L"IRP_MJ_DEVICE_CONTROL"))
            add_indicator(analysis.indicators, L"string:IRP_MJ_DEVICE_CONTROL", 3, analysis.ioctl_score);
        if (contains_i(text, L"IRP_MJ_INTERNAL_DEVICE_CONTROL"))
            add_indicator(analysis.indicators, L"string:IRP_MJ_INTERNAL_DEVICE_CONTROL", 2, analysis.ioctl_score);
        if (contains_i(text, L"EvtIoDeviceControl"))
            add_indicator(analysis.indicators, L"string:EvtIoDeviceControl", 3, analysis.ioctl_score);
        if (contains_i(text, L"DeviceIoControl"))
            add_indicator(analysis.indicators, L"string:DeviceIoControl", 2, analysis.ioctl_score);
        if (contains_i(text, L"CTL_CODE") || contains_i(text, L"IOCTL_"))
            add_indicator(analysis.indicators, L"string:IOCTL", 1, analysis.ioctl_score);

        extract_device_names(text, device_names);
    }

    if (!device_names.empty())
        add_indicator(analysis.indicators, L"string:device_name", 1, analysis.ioctl_score);

    for (const auto& device_name : device_names)
    {
        std::wstring link_name;
        if (starts_with_i(device_name, L"\\DosDevices\\"))
            link_name = device_name.substr(std::wstring(L"\\DosDevices\\").size());

        for (const auto& link : dos_links)
        {
            bool matched = false;
            if (!link_name.empty() && to_lower(link.name) == to_lower(link_name))
                matched = true;
            if (starts_with_i(device_name, L"\\Device\\") &&
                (starts_with_i(link.target, device_name) || starts_with_i(device_name, link.target)))
                matched = true;

            if (matched)
            {
                analysis.dos_links.insert(L"\\\\.\\" + link.name + L" -> " + link.target);
                if (analysis.dos_links.size() >= 8)
                    break;
            }
        }
    }

    if (!analysis.dos_links.empty())
        add_indicator(analysis.indicators, L"namespace:dos_device_link", 2, analysis.ioctl_score);

    return analysis;
}

static std::wstring read_reg_dword(HKEY root, const wchar_t* subkey, const wchar_t* value_name)
{
    DWORD value = 0;
    DWORD value_size = sizeof(value);
    DWORD type = 0;
    const LSTATUS status = RegGetValueW(root, subkey, value_name, RRF_RT_REG_DWORD, &type, &value, &value_size);
    if (status != ERROR_SUCCESS)
        return L"not_present";
    return std::to_wstring(value);
}

static bool is_elevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elevation = {};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

static std::wstring current_utc_stamp()
{
    SYSTEMTIME time = {};
    GetSystemTime(&time);

    std::wostringstream stream;
    stream << std::setfill(L'0')
           << std::setw(4) << time.wYear
           << std::setw(2) << time.wMonth
           << std::setw(2) << time.wDay
           << L"_"
           << std::setw(2) << time.wHour
           << std::setw(2) << time.wMinute
           << std::setw(2) << time.wSecond
           << L"Z";
    return stream.str();
}

static fs::path default_output_dir()
{
    wchar_t local_app_data[MAX_PATH] = {};
    const DWORD chars = GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, static_cast<DWORD>(std::size(local_app_data)));
    if (chars > 0 && chars < std::size(local_app_data))
        return fs::path(local_app_data) / L"Aegis" / L"VulnerableDriverScanner";

    wchar_t temp_path[MAX_PATH] = {};
    GetTempPathW(static_cast<DWORD>(std::size(temp_path)), temp_path);
    return fs::path(temp_path) / L"Aegis" / L"VulnerableDriverScanner";
}

static std::wstring sanitize_name(std::wstring name)
{
    name = trim(name);
    if (name.empty())
        name = L"snapshot";

    for (wchar_t& ch : name)
    {
        if (!(iswalnum(ch) || ch == L'-' || ch == L'_' || ch == L'.'))
            ch = L'_';
    }
    return name;
}

static std::vector<DriverRecord> collect_loaded_drivers()
{
    std::vector<DriverRecord> records;

    std::vector<LPVOID> driver_bases(2048);
    DWORD bytes_needed = 0;
    if (!EnumDeviceDrivers(driver_bases.data(), static_cast<DWORD>(driver_bases.size() * sizeof(LPVOID)), &bytes_needed))
        return records;

    if (bytes_needed > driver_bases.size() * sizeof(LPVOID))
    {
        driver_bases.resize(bytes_needed / sizeof(LPVOID));
        if (!EnumDeviceDrivers(driver_bases.data(), static_cast<DWORD>(driver_bases.size() * sizeof(LPVOID)), &bytes_needed))
            return records;
    }

    const DWORD driver_count = bytes_needed / sizeof(LPVOID);
    const auto services = collect_driver_services();
    const auto dos_links = collect_dos_links();

    std::map<std::wstring, const ServiceInfo*> services_by_path;
    std::map<std::wstring, const ServiceInfo*> services_by_base_name;
    for (const auto& service : services)
    {
        if (!service.normalized_path.empty())
            services_by_path[to_lower(service.normalized_path)] = &service;

        const std::wstring base_name = filename_from_path(service.normalized_path.empty() ? service.image_path : service.normalized_path);
        if (!base_name.empty())
            services_by_base_name[to_lower(base_name)] = &service;
    }

    for (DWORD index = 0; index < driver_count; ++index)
    {
        wchar_t image_path[2048] = {};
        wchar_t base_name[512] = {};
        GetDeviceDriverFileNameW(driver_bases[index], image_path, static_cast<DWORD>(std::size(image_path)));
        GetDeviceDriverBaseNameW(driver_bases[index], base_name, static_cast<DWORD>(std::size(base_name)));

        DriverRecord record;
        record.image_path = image_path;
        record.normalized_path = normalize_path(record.image_path);
        record.base_name = base_name[0] ? base_name : filename_from_path(record.normalized_path);

        const ServiceInfo* service = nullptr;
        const auto path_match = services_by_path.find(to_lower(record.normalized_path));
        if (path_match != services_by_path.end())
            service = path_match->second;
        else
        {
            const auto base_match = services_by_base_name.find(to_lower(record.base_name));
            if (base_match != services_by_base_name.end())
                service = base_match->second;
        }

        if (service)
        {
            record.service_name = service->name;
            record.service_display = service->display_name;
            record.service_start = service->start_type;
            record.service_state = service->state;
        }

        if (file_exists(record.normalized_path))
        {
            record.sha256 = sha256_file(record.normalized_path);
            const auto version_fields = get_version_fields(record.normalized_path);
            if (version_fields.count(L"CompanyName"))
                record.company = version_fields.at(L"CompanyName");
            if (version_fields.count(L"FileDescription"))
                record.file_description = version_fields.at(L"FileDescription");
            if (version_fields.count(L"FileVersion"))
                record.file_version = version_fields.at(L"FileVersion");

            const StaticAnalysis analysis = analyze_driver_file(record.normalized_path, dos_links);
            record.ioctl_score = analysis.ioctl_score;
            record.ioctl_indicators = join_set(analysis.indicators, L";");
            record.dos_links = join_set(analysis.dos_links, L";");
        }

        records.push_back(std::move(record));
    }

    std::sort(records.begin(), records.end(), [](const DriverRecord& left, const DriverRecord& right) {
        if (left.ioctl_score != right.ioctl_score)
            return left.ioctl_score > right.ioctl_score;
        return to_lower(left.base_name) < to_lower(right.base_name);
    });

    return records;
}

static std::wstring row_for_record(const DriverRecord& record)
{
    std::vector<std::wstring> cells = {
        record.sha256,
        record.base_name,
        record.image_path,
        record.normalized_path,
        record.service_name,
        record.service_display,
        record.service_start,
        record.service_state,
        record.company,
        record.file_description,
        record.file_version,
        std::to_wstring(record.ioctl_score),
        record.ioctl_indicators,
        record.dos_links,
    };

    std::wstring line;
    for (size_t index = 0; index < cells.size(); ++index)
    {
        if (index)
            line += L'\t';
        line += clean_cell(cells[index]);
    }
    return line;
}

static fs::path write_snapshot(const std::wstring& name, const fs::path& output_dir, const std::vector<DriverRecord>& records)
{
    fs::create_directories(output_dir);

    fs::path output_path = output_dir / (sanitize_name(name) + L".tsv");
    std::wstring text;

    text += L"# Aegis VulnerableDriverScanner snapshot\n";
    text += L"# created_utc=" + current_utc_stamp() + L"\n";
    text += L"# elevated=" + std::wstring(is_elevated() ? L"true" : L"false") + L"\n";
    text += L"# vulnerable_driver_blocklist_reg=" +
        read_reg_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable") + L"\n";
    text += L"# hvci_enabled_reg=" +
        read_reg_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Enabled") + L"\n";

    for (size_t index = 0; index < kColumns.size(); ++index)
    {
        if (index)
            text += L'\t';
        text += kColumns[index];
    }
    text += L'\n';

    for (const auto& record : records)
    {
        text += row_for_record(record);
        text += L'\n';
    }

    std::ofstream output(output_path, std::ios::binary);
    const std::string bytes = utf8(text);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return output_path;
}

static std::vector<std::wstring> split_tab(const std::wstring& line)
{
    std::vector<std::wstring> cells;
    size_t start = 0;
    while (start <= line.size())
    {
        const size_t tab = line.find(L'\t', start);
        if (tab == std::wstring::npos)
        {
            cells.push_back(line.substr(start));
            break;
        }
        cells.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }
    return cells;
}

struct SnapshotRow
{
    std::map<std::wstring, std::wstring> cells;
    std::wstring original_line;
};

static std::vector<SnapshotRow> read_snapshot(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
        return {};

    std::string bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::wistringstream stream(from_utf8(bytes));
    std::wstring line;
    std::vector<std::wstring> columns;
    std::vector<SnapshotRow> rows;

    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == L'\r')
            line.pop_back();
        if (line.empty() || line[0] == L'#')
            continue;

        const auto cells = split_tab(line);
        if (columns.empty())
        {
            columns = cells;
            continue;
        }

        SnapshotRow row;
        row.original_line = line;
        for (size_t index = 0; index < columns.size() && index < cells.size(); ++index)
            row.cells[columns[index]] = cells[index];
        rows.push_back(std::move(row));
    }

    return rows;
}

static std::wstring cell_or_empty(const SnapshotRow& row, const std::wstring& key)
{
    const auto it = row.cells.find(key);
    return it == row.cells.end() ? L"" : it->second;
}

static std::wstring compare_key(const SnapshotRow& row)
{
    const std::wstring sha = trim(cell_or_empty(row, L"sha256"));
    if (!sha.empty())
        return L"sha:" + to_lower(sha);

    const std::wstring normalized_path = trim(cell_or_empty(row, L"normalized_path"));
    if (!normalized_path.empty())
        return L"path:" + to_lower(normalized_path);

    const std::wstring base_name = trim(cell_or_empty(row, L"base_name"));
    if (!base_name.empty())
        return L"name:" + to_lower(base_name);

    return {};
}

static int ioctl_score_for_row(const SnapshotRow& row)
{
    try
    {
        return std::stoi(cell_or_empty(row, L"ioctl_score"));
    }
    catch (...)
    {
        return 0;
    }
}

static fs::path resolve_snapshot_path(const std::wstring& argument, const fs::path& output_dir)
{
    fs::path direct(argument);
    if (fs::exists(direct))
        return fs::absolute(direct);

    if (direct.has_extension())
    {
        fs::path under_output = output_dir / direct.filename();
        if (fs::exists(under_output))
            return under_output;
        return under_output;
    }

    return output_dir / (sanitize_name(argument) + L".tsv");
}

static fs::path compare_snapshots(const fs::path& before_path, const fs::path& after_path, const fs::path& output_dir)
{
    const auto before_rows = read_snapshot(before_path);
    const auto after_rows = read_snapshot(after_path);

    std::map<std::wstring, SnapshotRow> after_by_key;
    for (const auto& row : after_rows)
    {
        const std::wstring key = compare_key(row);
        if (!key.empty())
            after_by_key[key] = row;
    }

    std::vector<SnapshotRow> missing;
    for (const auto& row : before_rows)
    {
        const std::wstring key = compare_key(row);
        if (!key.empty() && after_by_key.find(key) == after_by_key.end())
            missing.push_back(row);
    }

    std::sort(missing.begin(), missing.end(), [](const SnapshotRow& left, const SnapshotRow& right) {
        return ioctl_score_for_row(left) > ioctl_score_for_row(right);
    });

    fs::create_directories(output_dir);
    const std::wstring report_name =
        L"compare_" +
        sanitize_name(before_path.stem().wstring()) +
        L"_vs_" +
        sanitize_name(after_path.stem().wstring()) +
        L".tsv";
    const fs::path report_path = output_dir / report_name;

    std::wstring text;
    text += L"# Aegis VulnerableDriverScanner comparison\n";
    text += L"# created_utc=" + current_utc_stamp() + L"\n";
    text += L"# before=" + before_path.wstring() + L"\n";
    text += L"# after=" + after_path.wstring() + L"\n";
    text += L"# note=Missing drivers are blocklist candidates, not proof of vulnerability.\n";
    text += L"candidate_reason";
    for (const auto& column : kColumns)
        text += L'\t' + column;
    text += L'\n';

    for (const auto& row : missing)
    {
        const int score = ioctl_score_for_row(row);
        text += score >= 3 ? L"missing_after_restart;ioctl_surface_likely" : L"missing_after_restart";
        for (const auto& column : kColumns)
            text += L'\t' + clean_cell(cell_or_empty(row, column));
        text += L'\n';
    }

    std::ofstream output(report_path, std::ios::binary);
    const std::string bytes = utf8(text);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));

    std::wcout << L"[+] Before rows: " << before_rows.size() << L"\n";
    std::wcout << L"[+] After rows:  " << after_rows.size() << L"\n";
    std::wcout << L"[+] Missing candidates: " << missing.size() << L"\n";

    const size_t top_count = std::min<size_t>(missing.size(), 10);
    for (size_t index = 0; index < top_count; ++index)
    {
        const auto& row = missing[index];
        std::wcout << L"    score=" << ioctl_score_for_row(row)
                   << L" driver=" << cell_or_empty(row, L"base_name")
                   << L" service=" << cell_or_empty(row, L"service_name")
                   << L"\n";
    }

    return report_path;
}

static void print_usage()
{
    std::wcout
        << L"VulnerableDriverScanner\n\n"
        << L"Usage:\n"
        << L"  VulnerableDriverScanner.exe snapshot list1 [--out <dir>]\n"
        << L"  VulnerableDriverScanner.exe snapshot list2 [--out <dir>]\n"
        << L"  VulnerableDriverScanner.exe compare list1 list2 [--out <dir>]\n\n"
        << L"Default output folder:\n"
        << L"  " << default_output_dir().wstring() << L"\n\n"
        << L"Recommended flow:\n"
        << L"  1. Run snapshot list1 before enabling the Microsoft blocklist.\n"
        << L"  2. Enable the blocklist, restart Windows, then run snapshot list2.\n"
        << L"  3. Run compare list1 list2.\n";
}

int wmain(int argc, wchar_t** argv)
{
    fs::path output_dir = default_output_dir();
    std::vector<std::wstring> args;

    for (int index = 1; index < argc; ++index)
    {
        const std::wstring arg = argv[index];
        if ((arg == L"--out" || arg == L"--output-dir") && index + 1 < argc)
        {
            output_dir = argv[++index];
            continue;
        }
        args.push_back(arg);
    }

    if (args.empty())
    {
        print_usage();
        return 0;
    }

    const std::wstring command = to_lower(args[0]);
    if (command == L"snapshot" || command == L"capture" || command == L"scan")
    {
        const std::wstring name = args.size() >= 2 ? args[1] : L"snapshot";

        if (!is_elevated())
            std::wcout << L"[!] Not running elevated. Some driver metadata may be unavailable.\n";

        std::wcout << L"[*] Collecting loaded driver snapshot...\n";
        auto records = collect_loaded_drivers();
        const fs::path output_path = write_snapshot(name, output_dir, records);

        std::wcout << L"[+] Drivers captured: " << records.size() << L"\n";
        std::wcout << L"[+] Snapshot saved: " << output_path.wstring() << L"\n";
        std::wcout << L"[+] Blocklist registry value: "
                   << read_reg_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable")
                   << L"\n";
        std::wcout << L"[+] HVCI registry value: "
                   << read_reg_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Enabled")
                   << L"\n";
        return 0;
    }

    if (command == L"compare")
    {
        if (args.size() < 3)
        {
            print_usage();
            return 2;
        }

        const fs::path before_path = resolve_snapshot_path(args[1], output_dir);
        const fs::path after_path = resolve_snapshot_path(args[2], output_dir);

        if (!fs::exists(before_path))
        {
            std::wcerr << L"[-] Before snapshot not found: " << before_path.wstring() << L"\n";
            return 2;
        }
        if (!fs::exists(after_path))
        {
            std::wcerr << L"[-] After snapshot not found: " << after_path.wstring() << L"\n";
            return 2;
        }

        const fs::path report_path = compare_snapshots(before_path, after_path, output_dir);
        std::wcout << L"[+] Comparison saved: " << report_path.wstring() << L"\n";
        return 0;
    }

    print_usage();
    return 2;
}
