
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <exception>
#include <functional>
#include <string>
#include <vector>

#define UNICODE
#define _UNICODE
#ifndef NOMINMAX
#  define NOMINMAX
#endif // NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <knownfolders.h>

// msvc2013 compat

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER >= 1900)
#define ITW_NOEXCEPT noexcept
#define ITW_NOEXCEPT_SUPPORTED
#else // MSVC 2013
#define ITW_NOEXCEPT
#endif

// mingw-w64 compat

#ifdef __MINGW32__
const GUID ITW_FOLDERID_LocalAppData = { 0xF1B32785, 0x6FBA, 0x4FCF, { 0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91 } };
#else // MSVC
const GUID ITW_FOLDERID_LocalAppData = FOLDERID_LocalAppData;
#endif //__MINGW32__

// implementation

namespace itw {

namespace detail_defer {

// http://stackoverflow.com/a/17356259/314015
template<typename T>
class defer_guard {
    T func;
    bool moved_out = false;
    
public:
    explicit defer_guard(T func) :
    func(std::move(func)) { }

    defer_guard(const defer_guard&) = delete;
    defer_guard& operator=(const defer_guard&) = delete;
    
    defer_guard(defer_guard&& other) ITW_NOEXCEPT :
    func(std::move(other.func)) {
        other.moved_out = true;
    }

    defer_guard& operator=(defer_guard&&) = delete;

    ~defer_guard() ITW_NOEXCEPT {
#ifdef ITW_NOEXCEPT_SUPPORTED
        static_assert(noexcept(func()),
                "Please check that the defer block cannot throw, "
                "and mark the lambda as 'noexcept'.");
#endif
        if (!moved_out) {
            func();
        }
    }
};

} // namespace

template<typename T>
detail_defer::defer_guard<T> defer(T func) {
    return detail_defer::defer_guard<T>(std::move(func));
}

std::string errcode_to_string(unsigned long code) ITW_NOEXCEPT;

class itw_exception : public std::exception {
protected:
    std::string message{};

public:
    itw_exception(const std::string& message) :
    message(message) { }

    virtual const char* what() const ITW_NOEXCEPT {
        return message.c_str();
    }
};

std::wstring widen(const std::string& st) {
    int size_needed = ::MultiByteToWideChar(
            CP_UTF8,
            0,
            st.c_str(),
            static_cast<int>(st.length()),
            nullptr,
            0);
    if (0 == size_needed) {
        throw itw_exception(std::string("Error on string widen calculation,") +
            " string: [" + st + "], error: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto res = std::wstring();
    res.resize(size_needed);
    int chars_copied = ::MultiByteToWideChar(
            CP_UTF8,
            0,
            st.c_str(),
            static_cast<int>(st.size()),
            std::addressof(res.front()),
            size_needed);
    if (chars_copied != size_needed) {
        throw itw_exception(std::string("Error on string widen execution,") +
            " string: [" + st + "], error: [" + errcode_to_string(::GetLastError()) + "]");
    }
    return res;
}

std::string narrow(const wchar_t* wstring, size_t length) {
    int size_needed = ::WideCharToMultiByte(
            CP_UTF8,
            0,
            wstring,
            static_cast<int>(length),
            nullptr,
            0,
            nullptr,
            nullptr);
    if (0 == size_needed) {
        throw itw_exception(std::string("Error on string narrow calculation,") +
            " string length: [" + std::to_string(length) + "], error code: [" + std::to_string(::GetLastError()) + "]");
    }
    auto vec = std::vector<char>();
    vec.resize(size_needed);
    int bytes_copied = ::WideCharToMultiByte(
            CP_UTF8,
            0,
            wstring,
            static_cast<int>(length),
            vec.data(),
            size_needed,
            nullptr,
            nullptr);
    if (bytes_copied != size_needed) {
        throw itw_exception(std::string("Error on string narrow execution,") +
            " string length: [" + std::to_string(vec.size()) + "], error code: [" + std::to_string(::GetLastError()) + "]");
    }
    return std::string(vec.begin(), vec.end());
}

std::string errcode_to_string(unsigned long code) ITW_NOEXCEPT {
    if (0 == code) {
        return std::string();
    }
    wchar_t* buf = nullptr;
    size_t size = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            reinterpret_cast<wchar_t*>(&buf),
            0,
            nullptr);
    if (0 == size) {
        return "Cannot format code: [" + std::to_string(code) + "]" +
            " into message, error code: [" + std::to_string(::GetLastError()) + "]";
    }
    auto deferred = defer([buf]() ITW_NOEXCEPT {
        ::LocalFree(buf);
    });
    if (size <= 2) {
        return "code: [" + std::to_string(code) + "], message: []";
    }
    try {
        std::string msg = narrow(buf, size - 2);
        return "code: [" + std::to_string(code) + "], message: [" + msg + "]";
    } catch(const std::exception& e) {
        return "Cannot format code: [" + std::to_string(code) + "]" +
            " into message, narrow error: [" + e.what() + "]";
    }
}

std::string process_dir() {
    auto vec = std::vector<wchar_t>();
    vec.resize(MAX_PATH);
    auto success = ::GetModuleFileNameW(
            nullptr,
            vec.data(),
            static_cast<DWORD>(vec.size()));
    if (0 == success) {
        throw itw_exception(std::string("Error getting current executable dir,") +
            " error: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto path = narrow(vec.data(), vec.size());
    std::replace(path.begin(), path.end(), '\\', '/');
    auto sid = path.rfind('/');
    return std::string::npos != sid ? path.substr(0, sid + 1) : path;
}

std::string userdata_dir() {
    wchar_t* wbuf = nullptr;
    auto err = ::SHGetKnownFolderPath(
            ITW_FOLDERID_LocalAppData,
            KF_FLAG_CREATE,
            nullptr,
            std::addressof(wbuf));
    if (S_OK != err || nullptr == wbuf) {
        throw itw_exception("Error getting userdata dir");
    }
    auto deferred = defer([wbuf]() ITW_NOEXCEPT {
        ::CoTaskMemFree(wbuf);
    });
    auto path = narrow(wbuf, ::wcslen(wbuf));
    std::replace(path.begin(), path.end(), '\\', '/');
    path.push_back('/');
    return path;
}

void create_dir(const std::string& dirpath) {
    auto wpath = widen(dirpath);
    BOOL err = ::CreateDirectoryW(
            std::addressof(wpath.front()),
            nullptr);
    if (0 == err && ERROR_ALREADY_EXISTS != ::GetLastError()) {
        throw itw_exception(std::string("Error getting creating dir,") +
            " path: [" + dirpath + "], error: [" + errcode_to_string(::GetLastError()) + "]");
    }
}

int start_process(const std::string& executable, const std::vector<std::string>& args, const std::string& out) {
    // open stdout file
    auto wout = widen(out);
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE; 
    HANDLE out_handle = ::CreateFileW(
            std::addressof(wout.front()), 
            FILE_WRITE_DATA | FILE_APPEND_DATA,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            std::addressof(sa),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    if (INVALID_HANDLE_VALUE == out_handle) {
        throw itw_exception(std::string("Error opening log file descriptor,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]," +
                " specified out path: [" + out + "]");
    }
    auto deferred_outhandle = defer([out_handle]() ITW_NOEXCEPT {
        ::CloseHandle(out_handle);
    });

    // prepare list of handles to inherit
    // see: https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873
    SIZE_T tasize;
    auto err_tasize = ::InitializeProcThreadAttributeList(
            nullptr,
            1,
            0,
            std::addressof(tasize));
    
    if (0 != err_tasize || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        throw itw_exception(std::string("Error preparing attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto talist = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(std::malloc(tasize));
    if (nullptr == talist) {
        throw itw_exception(std::string("Error preparing attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto deferred_talist = defer([talist]() ITW_NOEXCEPT {
        std::free(talist);
    });
    auto err_ta = ::InitializeProcThreadAttributeList(
            talist,
            1,
            0,
            std::addressof(tasize));
    if (0 == err_ta) {
        throw itw_exception(std::string("Error initializing attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto deferred_talist_delete = defer([talist]() ITW_NOEXCEPT {
        ::DeleteProcThreadAttributeList(talist);
    });
    auto err_taset = ::UpdateProcThreadAttribute(
        talist,
        0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        std::addressof(out_handle),
        sizeof(HANDLE),
        nullptr,
        nullptr); 
    if (0 == err_taset) {
        throw itw_exception(std::string("Error filling attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }

    // prepare process
    STARTUPINFOEXW si;
    std::memset(std::addressof(si), 0, sizeof(STARTUPINFOEXW));
    si.StartupInfo = [out_handle] {
        STARTUPINFOW info;
        std::memset(std::addressof(info), 0, sizeof(STARTUPINFOW));
        info.dwFlags = STARTF_USESTDHANDLES;
        info.hStdInput = nullptr;
        info.hStdError = out_handle;
        info.hStdOutput = out_handle;
        return info;
    }();
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = talist;

    PROCESS_INFORMATION pi;
    memset(std::addressof(pi), 0, sizeof(PROCESS_INFORMATION));
    std::string cmd_string = "\"" + executable + "\"";
    for (const std::string& arg : args) {
        cmd_string += " ";
        cmd_string += arg;
    }

    // run process
    auto wcmd = widen(cmd_string);
    auto ret = ::CreateProcessW(
            nullptr, 
            std::addressof(wcmd.front()), 
            nullptr, 
            nullptr, 
            true, 
            CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, 
            nullptr, 
            nullptr, 
            std::addressof(si.StartupInfo), 
            std::addressof(pi));
    if (0 == ret) {
        throw itw_exception(std::string("Process create error: [") + errcode_to_string(::GetLastError()) + "]," +
            " command line: [" + cmd_string + "]");
    }
    ::CloseHandle(pi.hThread);
    int res = ::GetProcessId(pi.hProcess);
    ::CloseHandle(pi.hProcess);
    return res;
}

HRESULT error_dialog_cb(HWND, UINT uNotification, WPARAM, LPARAM lParam, LONG_PTR) {
    if (TDN_HYPERLINK_CLICKED != uNotification) {
        return S_OK;
    }
    HINSTANCE res = ::ShellExecuteW(
            nullptr,
            nullptr,
            reinterpret_cast<LPCTSTR> (lParam),
            nullptr,
            nullptr,
            SW_SHOW);
    int64_t intres = reinterpret_cast<int64_t> (res);
    bool success = intres > 32;
    if (!success) {
        static std::wstring wtitle = widen("IcedTea-Web");
        static std::wstring werror = widen("Error starting default web-browser");
        static std::wstring wempty = widen(std::string());
        ::TaskDialog(
                nullptr,
                ::GetModuleHandleW(nullptr),
                wtitle.c_str(),
                werror.c_str(),
                wempty.c_str(),
                TDCBF_CLOSE_BUTTON,
                TD_ERROR_ICON,
                nullptr);
    }
    return S_OK;
}

void show_error_dialog(const std::string& error) {
    static std::wstring wtitle = widen("IcedTea-Web");
    static std::string url = "http://icedtea.classpath.org/wiki/IcedTea-Web";
    auto link = std::string("<a href=\"") + url + "\">" + url + "</a>";
    auto wlink = widen(link);
    static std::wstring wmain = widen("IcedTea-Web was unable to start Java VM.\n\nPlease follow the link below for troubleshooting information.");
    static std::wstring wexpanded = widen("Hide detailed error message");
    static std::wstring wcollapsed = widen("Show detailed error message");
    std::wstring werror = widen(error);

    TASKDIALOGCONFIG cf;
    // memset(std::addressof(cf), '\0', sizeof(TASKDIALOGCONFIG));
    cf.cbSize = sizeof(TASKDIALOGCONFIG);
    cf.hwndParent = nullptr;
    cf.hInstance = ::GetModuleHandleW(nullptr);
    cf.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_EXPAND_FOOTER_AREA | TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
    cf.dwCommonButtons = TDCBF_CLOSE_BUTTON;
    cf.pszWindowTitle = wtitle.c_str();
    cf.pszMainIcon = MAKEINTRESOURCEW(111);
    cf.pszMainInstruction = wmain.c_str();
    cf.pszContent = nullptr;
    cf.cButtons = 0;
    cf.pButtons = nullptr;
    cf.nDefaultButton = 0;
    cf.cRadioButtons = 0;
    cf.pRadioButtons = nullptr;
    cf.nDefaultRadioButton = 0;
    cf.pszVerificationText = nullptr;
    cf.pszExpandedInformation = werror.c_str();
    cf.pszExpandedControlText = wexpanded.c_str();
    cf.pszCollapsedControlText = wcollapsed.c_str();
    cf.pszFooterIcon = MAKEINTRESOURCEW(111);
    cf.pszFooter = wlink.c_str();    
    cf.pfCallback = reinterpret_cast<PFTASKDIALOGCALLBACK>(error_dialog_cb);
    cf.lpCallbackData = 0;
    cf.cxWidth = 0;
    
    ::TaskDialogIndirect(
            std::addressof(cf),
            nullptr,
            nullptr,
            nullptr);
}

std::string find_java_exe() {
    static std::string jdk_key_name = "SOFTWARE\\JavaSoft\\Java Development Kit";
    static std::wstring wjdk_key_name = widen(jdk_key_name);
    static std::string jdk_prefix = "1.8.0";
    static std::string java_home = "JavaHome";
    static std::wstring wjava_home = widen("JavaHome");
    static std::string java_exe_postfix = "bin/java.exe";
    // open root
    HKEY jdk_key;
    auto err_jdk = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wjdk_key_name.c_str(), 
            0,
            KEY_READ | KEY_ENUMERATE_SUB_KEYS,
            std::addressof(jdk_key));
    if (ERROR_SUCCESS != err_jdk) {
        throw itw_exception(std::string("Error opening registry key,") +
                " name: [" + jdk_key_name + "]," +
                " message: [" + errcode_to_string(err_jdk) + "]");
    }
    auto deferred_jdk = defer([jdk_key]() ITW_NOEXCEPT {
        ::RegCloseKey(jdk_key);
    });
    // identify buffer size for children
    DWORD subkeys_num = 0;
    DWORD max_subkey_len = 0;
    auto err_info = ::RegQueryInfoKeyW(
            jdk_key,
            nullptr,
            nullptr,
            nullptr,
            std::addressof(subkeys_num),
            std::addressof(max_subkey_len),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);
    if (ERROR_SUCCESS != err_info) {
        throw itw_exception(std::string("Error querieing registry key,") +
                " name: [" + jdk_key_name + "]," +
                " message: [" + errcode_to_string(err_info) + "]");
    }
    // collect children names
    auto vec = std::vector<std::string>();
    vec.reserve(subkeys_num);
    max_subkey_len += 1; // NUL-terminator
    std::wstring subkey_buf;
    subkey_buf.resize(max_subkey_len);
    for (DWORD i = 0; i < subkeys_num; i++) {
        DWORD len = max_subkey_len;
        auto err_enum = ::RegEnumKeyExW(
                jdk_key,
                i,
                std::addressof(subkey_buf.front()),
                std::addressof(len),
                nullptr,
                nullptr,
                nullptr,
                nullptr);
        if (ERROR_SUCCESS != err_enum) {
            throw itw_exception(std::string("Error enumerating registry key,") +
                    " name: [" + jdk_key_name + "]," +
                    " message: [" + errcode_to_string(err_enum) + "]");
        }
        vec.emplace_back(narrow(subkey_buf.data(), len));
    }
    // look for prefix match
    std::sort(vec.begin(), vec.end());
    std::string versions;
    for (auto& el : vec) {
        if (!versions.empty()) {
            versions.append(", ");
        }
        versions.append(el);
        if (0 == el.compare(0, jdk_prefix.length(), jdk_prefix)) {
            // found match, open it
            std::string subkey_name = jdk_key_name + "\\" + el;
            std::wstring wsubkey_name = widen(subkey_name);
            HKEY jdk_subkey;
            auto err_jdk_subkey = ::RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    wsubkey_name.c_str(), 
                    0,
                    KEY_READ,
                    std::addressof(jdk_subkey));
            if (ERROR_SUCCESS != err_jdk_subkey) {
                throw itw_exception(std::string("Error opening registry key,") +
                        " name: [" + subkey_name + "]," +
                        " message: [" + errcode_to_string(err_jdk_subkey) + "]");
            }
            auto deferred_sub = defer([jdk_subkey]() ITW_NOEXCEPT {
                ::RegCloseKey(jdk_subkey);
            });
            // find out value len
            DWORD value_len = 0;
            DWORD value_type = 0;
            auto err_len = ::RegQueryValueExW(
                    jdk_subkey,
                    wjava_home.c_str(),
                    nullptr,
                    std::addressof(value_type),
                    nullptr,
                    std::addressof(value_len));
            if (ERROR_SUCCESS != err_len || !(value_len > 0) || REG_SZ != value_type) {
                throw itw_exception(std::string("Error opening registry value len,") +
                        " key: [" + subkey_name + "]," +
                        " value: [" + java_home + "]," +
                        " message: [" + errcode_to_string(err_len) + "]");
            }
            // get value
            std::wstring wvalue;
            wvalue.resize(((value_len)/sizeof(wchar_t)));
            auto err_val = ::RegQueryValueExW(
                    jdk_subkey,
                    wjava_home.c_str(),
                    nullptr,
                    nullptr,
                    reinterpret_cast<LPBYTE>(std::addressof(wvalue.front())),
                    std::addressof(value_len));
            if (ERROR_SUCCESS != err_val) {
                throw itw_exception(std::string("Error opening registry value,") +
                        " key: [" + subkey_name + "]," +
                        " value: [" + java_home + "]," +
                        " message: [" + errcode_to_string(err_val) + "]");
            }
            // format and return path
            std::string jpath = narrow(wvalue.data(), wvalue.length() - 1);
            std::replace(jpath.begin(), jpath.end(), '\\', '/');
            if ('/' != jpath[jpath.length() - 1]) {
                jpath.push_back('/');
            }
            jpath.append(java_exe_postfix);
            return jpath;
        }
    }
    throw itw_exception("JDK 8 runtime directory not found, please install JDK 8, available versions: [" + versions + "].");
}

} // namespace

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    static std::string log_dir_name = "IcedTeaWeb/";
    static std::string log_file_name = "javaws_last_log.txt";
    try {
        auto cline = std::string(lpCmdLine);
        if (cline.empty()) {
            throw itw::itw_exception("No arguments specified. Please specify a path to JNLP file or a 'jnlp://' URL.");
        }
        auto localdir = itw::process_dir();
        std::string java = itw::find_java_exe();
        std::vector<std::string> args;
        args.emplace_back("-Xbootclasspath/a:" + localdir + "lib.jar");
        args.emplace_back("-splash:" + localdir + "javaws_splash.png");
        args.emplace_back("net.sourceforge.jnlp.runtime.Boot");
        args.emplace_back(cline);
        auto uddir = itw::userdata_dir();
        auto logdir = uddir + log_dir_name;
        itw::create_dir(logdir);
        auto logfile = logdir + log_file_name;
        itw::start_process(java, args, logfile);
        return 0;
    } catch (const std::exception& e) {
        itw::show_error_dialog(e.what());
        return 1;
    } catch (...) {
        itw::show_error_dialog("System error");
        return 1;
    }
}
