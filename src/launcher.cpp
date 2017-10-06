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

#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <exception>
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

#if defined(_MSC_VER) && _MSC_VER >= 1900
#define ITW_NOEXCEPT noexcept
#define ITW_NOEXCEPT_SUPPORTED
#else // MSVC 2010, 2013
#define ITW_NOEXCEPT
#endif

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

    // run process
    auto wcmd = widen(cmd_string);
    //::MessageBox(NULL, wcmd.c_str(), widen("foo").c_str(), MB_OK);
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
    std::memset(itw_addressof(cf), '\0', sizeof(TASKDIALOGCONFIG));
    cf.cbSize = sizeof(TASKDIALOGCONFIG);
    cf.hwndParent = nullptr;
    cf.hInstance = ::GetModuleHandleW(nullptr);
    cf.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_EXPAND_FOOTER_AREA | TDF_ALLOW_DIALOG_CANCELLATION /* | TDF_SIZE_TO_CONTENT */ ; 
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

} // namespace

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    static std::string log_dir_name = "IcedTeaWeb/";
    static std::string log_file_name = "javaws_last_log.txt";
    static std::string jvm_flags = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1 -XX:+UseSerialGC -XX:MinHeapFreeRatio=20 -XX:MaxHeapFreeRatio=40";
    try {
        auto cline = std::string(lpCmdLine);
        if (cline.empty()) {
            throw itw::itw_exception("No arguments specified. Please specify a path to JNLP file or a 'jnlp://' URL.");
        }
        auto localdir = itw::process_dir();
        //auto userdir = itw::userdata_dir();
        auto jdkdir = localdir + "../";
        auto java_exe = jdkdir + "bin/java.exe";
        std::vector<std::string> args;
        args.push_back(jvm_flags);
        args.push_back("-splash:\"" + localdir + "javaws_splash.png\"");
        args.push_back("-Xbootclasspath/a:\"" + localdir + "javaws.jar\"");
        args.push_back("-classpath");
        args.push_back("\"" + jdkdir + "jre/lib/rt.jar\"");
        //args.push_back("-Duser.home=\"" + userdir + "\"");
        args.push_back("-Dicedtea-web.bin.name=javaws.exe");
        args.push_back("-Dicedtea-web.bin.location=\"" + localdir + "javaws.exe\"");
        args.push_back("net.sourceforge.jnlp.runtime.Boot");
        args.push_back("-Xnofork");
        args.push_back(cline);
        auto uddir = itw::userdata_dir();
        auto logdir = uddir + log_dir_name;
        itw::create_dir(logdir);
        auto logfile = logdir + log_file_name;
        itw::start_process(java_exe, args, logfile);
        return 0;
    } catch (const std::exception& e) {
        itw::show_error_dialog(e.what());
        return 1;
    } catch (...) {
        itw::show_error_dialog("System error");
        return 1;
    }
}
