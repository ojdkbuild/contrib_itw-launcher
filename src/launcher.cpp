/*
 * Copyright 2016 akashche at redhat.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "launcher.hpp"

#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <exception>
#include <iterator>
#include <sstream>
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

// http://svn.wxwidgets.org/viewvc/wx/wxWidgets/trunk/src/msw/msgdlg.cpp?r1=70409&r2=70408&pathrev=70409
#ifndef TDF_SIZE_TO_CONTENT
#define TDF_SIZE_TO_CONTENT 0x1000000
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1900
#define ITW_NOEXCEPT noexcept
#define ITW_NOEXCEPT_SUPPORTED
#else // MSVC 2010, 2013
#define ITW_NOEXCEPT
#endif

const size_t ITW_MAX_RC_LEN = 1 << 12;
HINSTANCE ITW_HANDLE_INSTANCE = nullptr;

namespace itw {

// C++11 utils

template<typename T>
std::string itw_to_string(const T& obj) {
    std::stringstream ss;
    ss << obj;
    return ss.str();
}

template<typename T>
T* itw_addressof(T& t) {
    return &t;
}

// golang's defer

// http://stackoverflow.com/a/17356259/314015
template<typename T>
class defer_guard {
    T func;
    mutable bool moved_out;
    
    defer_guard& operator=(const defer_guard&);
public:
    explicit defer_guard(T func) :
    func(func),
    moved_out(false) { }

    defer_guard(const defer_guard&) :
    func(other.func) {
        other.moved_out = true;
    }

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

template<typename T>
defer_guard<T> defer(T func) {
    return defer_guard<T>(func);
}

// "lambda" for C++98

template<typename Func, typename Arg>
class itw_lambda {
    Func func;
    Arg arg;
public:
    itw_lambda(Func func, Arg arg) :
    func(func),
    arg(arg) { }

    void operator()() ITW_NOEXCEPT {
        func(arg);
    }
};

template<typename Func, typename Arg>
itw_lambda<Func, Arg> make_itw_lambda(Func func, Arg arg) {
    return itw_lambda<Func, Arg>(func, arg);
}

// forward declaration
std::string errcode_to_string(unsigned long code) ITW_NOEXCEPT;

// exception with message
class itw_exception : public std::exception {
protected:
    std::string message;

public:
    itw_exception(const std::string& message) :
    message(message) { }

    virtual const char* what() const ITW_NOEXCEPT {
        return message.c_str();
    }
};

// implementation

std::wstring widen(const std::string& st) {
    if (st.empty()) return std::wstring();
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
            itw_addressof(res.front()),
            size_needed);
    if (chars_copied != size_needed) {
        throw itw_exception(std::string("Error on string widen execution,") +
            " string: [" + st + "], error: [" + errcode_to_string(::GetLastError()) + "]");
    }
    return res;
}

std::string narrow(const wchar_t* wstring, size_t length) {
    if (0 == length) return std::string();
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
            " string length: [" + itw_to_string(length) + "], error code: [" + itw_to_string(::GetLastError()) + "]");
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
            " string length: [" + itw_to_string(vec.size()) + "], error code: [" + itw_to_string(::GetLastError()) + "]");
    }
    return std::string(vec.begin(), vec.end());
}

std::string narrow(const std::wstring& wstring) {
    return narrow(wstring.c_str(), wstring.length());
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
        return "Cannot format code: [" + itw_to_string(code) + "]" +
            " into message, error code: [" + itw_to_string(::GetLastError()) + "]";
    }
    auto deferred = defer(make_itw_lambda(::LocalFree, buf));
    if (size <= 2) {
        return "code: [" + itw_to_string(code) + "], message: []";
    }
    try {
        std::string msg = narrow(buf, size - 2);
        return "code: [" + itw_to_string(code) + "], message: [" + msg + "]";
    } catch(const std::exception& e) {
        return "Cannot format code: [" + itw_to_string(code) + "]" +
            " into message, narrow error: [" + e.what() + "]";
    }
}

std::wstring load_resource_string(UINT id) {
    std::wstring wstr;
    wstr.resize(ITW_MAX_RC_LEN);
    int loaded = ::LoadStringW(
        ITW_HANDLE_INSTANCE,
        id,
        itw_addressof(wstr.front()),
        static_cast<int>(wstr.length()));
    if (loaded > 0) {
        wstr.resize(loaded);
        return wstr;
    } else {
        auto errres = std::string("ERROR_LOAD_RESOURCE_") + itw_to_string(id);
        return widen(errres);
    }
}

std::string load_resource_narrow(UINT id) {
    auto wide = load_resource_string(id);
    return narrow(wide);
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
            FOLDERID_LocalAppData,
            KF_FLAG_CREATE,
            nullptr,
            itw_addressof(wbuf));
    if (S_OK != err || nullptr == wbuf) {
        throw itw_exception("Error getting userdata dir");
    }
    auto deferred = defer(make_itw_lambda(::CoTaskMemFree, wbuf));
    auto path = narrow(wbuf, ::wcslen(wbuf));
    std::replace(path.begin(), path.end(), '\\', '/');
    path.push_back('/');
    return path;
}

void create_dir(const std::string& dirpath) {
    auto wpath = widen(dirpath);
    BOOL err = ::CreateDirectoryW(
            itw_addressof(wpath.front()),
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
            itw_addressof(wout.front()), 
            FILE_WRITE_DATA | FILE_APPEND_DATA,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            itw_addressof(sa),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    if (INVALID_HANDLE_VALUE == out_handle) {
        throw itw_exception(std::string("Error opening log file descriptor,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]," +
                " specified out path: [" + out + "]");
    }
    auto deferred_outhandle = defer(make_itw_lambda(::CloseHandle, out_handle));

    // prepare list of handles to inherit
    // see: https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873
    SIZE_T tasize;
    auto err_tasize = ::InitializeProcThreadAttributeList(
            nullptr,
            1,
            0,
            itw_addressof(tasize));
    
    if (0 != err_tasize || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        throw itw_exception(std::string("Error preparing attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto talist = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(std::malloc(tasize));
    if (nullptr == talist) {
        throw itw_exception(std::string("Error preparing attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto deferred_talist = defer(make_itw_lambda(std::free, talist));
    auto err_ta = ::InitializeProcThreadAttributeList(
            talist,
            1,
            0,
            itw_addressof(tasize));
    if (0 == err_ta) {
        throw itw_exception(std::string("Error initializing attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }
    auto deferred_talist_delete = defer(make_itw_lambda(::DeleteProcThreadAttributeList, talist));
    auto err_taset = ::UpdateProcThreadAttribute(
        talist,
        0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        itw_addressof(out_handle),
        sizeof(HANDLE),
        nullptr,
        nullptr); 
    if (0 == err_taset) {
        throw itw_exception(std::string("Error filling attrlist,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }

    // prepare process
    STARTUPINFOEXW si;
    std::memset(itw_addressof(si), 0, sizeof(STARTUPINFOEXW));
    std::memset(itw_addressof(si.StartupInfo), 0, sizeof(STARTUPINFOW));
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nullptr;
    si.StartupInfo.hStdError = out_handle;
    si.StartupInfo.hStdOutput = out_handle;
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = talist;

    PROCESS_INFORMATION pi;
    memset(itw_addressof(pi), 0, sizeof(PROCESS_INFORMATION));
    std::string cmd_string = "\"" + executable + "\"";
    for (size_t i = 0; i < args.size(); i++) {
        cmd_string += " ";
        cmd_string += args.at(i);
    }

    // log cmdline
    auto cmd_string_log = "Starting Netx, command: [" + cmd_string + "]\r\n";
    DWORD bytes_written = 0;
    auto err_logcmd = ::WriteFile(
        out_handle,
        cmd_string_log.c_str(),
        static_cast<DWORD>(cmd_string_log.length()),
        itw_addressof(bytes_written),
        nullptr);
    if (0 == err_logcmd) {
        throw itw_exception(std::string("Error logging cmdline,") + 
                " message: [" + errcode_to_string(::GetLastError()) + "]");
    }

    // run process
    auto wcmd = widen(cmd_string);
    auto ret = ::CreateProcessW(
            nullptr, 
            itw_addressof(wcmd.front()), 
            nullptr, 
            nullptr, 
            true, 
            CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, 
            nullptr, 
            nullptr, 
            itw_addressof(si.StartupInfo), 
            itw_addressof(pi));
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
        std::wstring wtitle = load_resource_string(IDS_ERROR_DIALOG_TITLE);
        std::wstring werror = load_resource_string(IDS_BROWSER_ERROR_TEXT);
        std::wstring wempty = widen(std::string());
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
    std::wstring wtitle = load_resource_string(IDS_ERROR_DIALOG_TITLE);
    std::string url = load_resource_narrow(IDS_ERROR_HELP_URL);
    auto link = std::string("<a href=\"") + url + "\">" + url + "</a>";
    auto wlink = widen(link);
    auto header = load_resource_narrow(IDS_ERROR_DIALOG_HEADER);
    auto subheader = load_resource_narrow(IDS_ERROR_DIALOG_SUBHEADER);
    auto fullheader = header + "\n\n" + subheader;
    std::wstring wmain = widen(fullheader);
    std::wstring wexpanded = widen("Hide detailed error message");
    std::wstring wcollapsed = widen("Show detailed error message");
    std::wstring werror = widen(error);

    TASKDIALOGCONFIG cf;
    std::memset(itw_addressof(cf), '\0', sizeof(TASKDIALOGCONFIG));
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
            itw_addressof(cf),
            nullptr,
            nullptr,
            nullptr);
}

void purge_work_dir() ITW_NOEXCEPT {
    // find out dirs
    auto uddir = itw::userdata_dir();
    auto vendor_name = load_resource_narrow(IDS_VENDOR_DIRNAME);
    auto vendor_dir = uddir + vendor_name;
    auto app_name = load_resource_narrow(IDS_APP_DIRNAME);
    auto app_dir = vendor_dir + "/" + app_name;
    auto ws_dir = app_dir + "/webstart";

    // prepare double-terminated path
    auto ws_dir_wide = widen(ws_dir);
    auto ws_dir_terminated = std::vector<wchar_t>();
    std::copy(ws_dir_wide.begin(), ws_dir_wide.end(), std::back_inserter(ws_dir_terminated));
    ws_dir_terminated.push_back('\0');
    ws_dir_terminated.push_back('\0');

    // delete webstart dir recursively
    SHFILEOPSTRUCT shop;
    std::memset(itw_addressof(shop), '\0', sizeof(shop));
    shop.wFunc = FO_DELETE;
    shop.pFrom = ws_dir_terminated.data();
    shop.fFlags = FOF_NO_UI;
    auto err_shop = ::SHFileOperation(itw_addressof(shop));
    (void) err_shop;

    // try to delete other dirs only if there are
    // no contents from other installed components inside
    auto app_dir_wide = widen(app_dir);
    auto err_app = ::RemoveDirectoryW(app_dir_wide.c_str());
    (void) err_app;
    auto vendor_dir_wide = widen(vendor_dir);
    auto err_vendor = ::RemoveDirectoryW(vendor_dir_wide.c_str());
    (void) err_vendor;
}

std::string prepare_webstart_dir() {
    auto uddir = itw::userdata_dir();
    auto vendor_name = load_resource_narrow(IDS_VENDOR_DIRNAME);
    auto vendor_dir = uddir + vendor_name;
    itw::create_dir(vendor_dir);
    auto app_name = load_resource_narrow(IDS_APP_DIRNAME);
    auto app_dir = vendor_dir + "/" + app_name;
    itw::create_dir(app_dir);
    auto ws_dir = app_dir + "/webstart/";
    itw::create_dir(ws_dir);
    return ws_dir;
}

} // namespace

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int) {
    ITW_HANDLE_INSTANCE = hInstance;
    std::string jvm_flags = itw::load_resource_narrow(IDS_JVM_OPTIONS);
    try {
        auto cline = std::string(lpCmdLine);
        if (cline.empty()) {
            std::string msg = itw::load_resource_narrow(IDS_NO_ARGS_ERROR_MESSAGE);
            throw itw::itw_exception(msg);
        } else if ("-d" == cline) {
            itw::purge_work_dir();
            return 0;
        }
        auto localdir = itw::process_dir();
        auto wsdir = itw::prepare_webstart_dir();
        auto jdkdir = localdir + "../";
        auto help_url = itw::load_resource_narrow(IDS_ERROR_HELP_URL);
        std::vector<std::string> args;
        args.push_back(jvm_flags);
        //args.push_back("-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005");
        args.push_back("-splash:\"" + localdir + "javaws_splash.png\"");
        args.push_back("-Xbootclasspath/a:\"" + localdir + "javaws.jar\"");
        args.push_back("-classpath");
        args.push_back("\"" + jdkdir + "jre/lib/rt.jar\"");
        args.push_back("-Ditw.userdata=\"" + wsdir + "\"");
        args.push_back("-Dicedtea-web.bin.name=javaws.exe");
        args.push_back("-Dicedtea-web.bin.location=\"" + localdir + "javaws.exe\"");
        args.push_back("net.sourceforge.jnlp.runtime.Boot");
        args.push_back("-Xnofork");
        args.push_back("-helpurl=\"" + help_url + "\"");
        args.push_back(cline);
        itw::start_process(jdkdir + "bin/java.exe", args, wsdir + "javaws_last_log.txt");
        return 0;
    } catch (const std::exception& e) {
        itw::show_error_dialog(e.what());
        return 1;
    } catch (...) {
        itw::show_error_dialog("System error");
        return 1;
    }
}
