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
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "ojdkbuild/utils/windows.hpp"
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <knownfolders.h>

#include "ojdkbuild/utils.hpp"

// http://svn.wxwidgets.org/viewvc/wx/wxWidgets/trunk/src/msw/msgdlg.cpp?r1=70409&r2=70408&pathrev=70409
#ifndef TDF_SIZE_TO_CONTENT
#define TDF_SIZE_TO_CONTENT 0x1000000
#endif

const size_t ITW_MAX_RC_LEN = 1 << 12;
HINSTANCE ITW_HANDLE_INSTANCE = nullptr;

namespace itw {

std::wstring load_resource_string(UINT id) {
    std::wstring wstr;
    wstr.resize(ITW_MAX_RC_LEN);
    int loaded = ::LoadStringW(
        ITW_HANDLE_INSTANCE,
        id,
        ojb::addressof(wstr.front()),
        static_cast<int>(wstr.length()));
    if (loaded > 0) {
        wstr.resize(loaded);
        return wstr;
    } else {
        auto errres = std::string("ERROR_LOAD_RESOURCE_") + ojb::to_string(id);
        return ojb::widen(errres);
    }
}

std::string load_resource_narrow(UINT id) {
    auto wide = load_resource_string(id);
    return ojb::narrow(wide);
}

void create_dir(const std::string& dirpath) {
    auto wpath = ojb::widen(dirpath);
    BOOL err = ::CreateDirectoryW(
            ojb::addressof(wpath.front()),
            nullptr);
    if (0 == err && ERROR_ALREADY_EXISTS != ::GetLastError()) {
        throw ojb::exception(std::string("Error getting creating dir,") +
            " path: [" + dirpath + "], error: [" + ojb::errcode_to_string(::GetLastError()) + "]");
    }
}

int start_process(const std::string& executable, const std::vector<std::string>& args, const std::string& out) {
    // open stdout file
    auto wout = ojb::widen(out);
    SECURITY_ATTRIBUTES sa;
    std::memset(ojb::addressof(sa), '\0', sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE; 
    HANDLE out_handle = ::CreateFileW(
            ojb::addressof(wout.front()),
            FILE_WRITE_DATA | FILE_APPEND_DATA,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            ojb::addressof(sa),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    if (INVALID_HANDLE_VALUE == out_handle) {
        throw ojb::exception(std::string("Error opening log file descriptor,") +
                " message: [" + ojb::errcode_to_string(::GetLastError()) + "]," +
                " specified out path: [" + out + "]");
    }
    auto deferred_outhandle = ojb::defer(ojb::make_lambda(::CloseHandle, out_handle));

    // prepare list of handles to inherit
    // see: https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873
    SIZE_T tasize;
    auto err_tasize = ::InitializeProcThreadAttributeList(
            nullptr,
            1,
            0,
            ojb::addressof(tasize));
    
    if (0 != err_tasize || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        throw ojb::exception(std::string("Error preparing attrlist,") +
                " message: [" + ojb::errcode_to_string(::GetLastError()) + "]");
    }
    auto talist = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(std::malloc(tasize));
    if (nullptr == talist) {
        throw ojb::exception(std::string("Error preparing attrlist,") +
                " message: [" + ojb::errcode_to_string(::GetLastError()) + "]");
    }
    auto deferred_talist = ojb::defer(ojb::make_lambda(std::free, talist));
    auto err_ta = ::InitializeProcThreadAttributeList(
            talist,
            1,
            0,
            ojb::addressof(tasize));
    if (0 == err_ta) {
        throw ojb::exception(std::string("Error initializing attrlist,") +
                " message: [" + ojb::errcode_to_string(::GetLastError()) + "]");
    }
    auto deferred_talist_delete = ojb::defer(ojb::make_lambda(::DeleteProcThreadAttributeList, talist));
    auto err_taset = ::UpdateProcThreadAttribute(
        talist,
        0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        ojb::addressof(out_handle),
        sizeof(HANDLE),
        nullptr,
        nullptr); 
    if (0 == err_taset) {
        throw ojb::exception(std::string("Error filling attrlist,") +
                " message: [" + ojb::errcode_to_string(::GetLastError()) + "]");
    }

    // prepare process
    STARTUPINFOEXW si;
    std::memset(ojb::addressof(si), '\0', sizeof(STARTUPINFOEXW));
    std::memset(ojb::addressof(si.StartupInfo), '\0', sizeof(STARTUPINFOW));
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nullptr;
    si.StartupInfo.hStdError = out_handle;
    si.StartupInfo.hStdOutput = out_handle;
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = talist;

    PROCESS_INFORMATION pi;
    std::memset(ojb::addressof(pi), '\0', sizeof(PROCESS_INFORMATION));
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
        ojb::addressof(bytes_written),
        nullptr);
    if (0 == err_logcmd) {
        throw ojb::exception(std::string("Error logging cmdline,") +
                " message: [" + ojb::errcode_to_string(::GetLastError()) + "]");
    }

    // run process
    auto wcmd = ojb::widen(cmd_string);
    auto ret = ::CreateProcessW(
            nullptr, 
            ojb::addressof(wcmd.front()),
            nullptr, 
            nullptr, 
            true, 
            CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, 
            nullptr, 
            nullptr, 
            ojb::addressof(si.StartupInfo),
            ojb::addressof(pi));
    if (0 == ret) {
        throw ojb::exception(std::string("Process create error: [") + ojb::errcode_to_string(::GetLastError()) + "]," +
            " command line: [" + cmd_string + "]");
    }
    ::CloseHandle(pi.hThread);
    int res = ::GetProcessId(pi.hProcess);
    ::CloseHandle(pi.hProcess);
    return res;
}

HRESULT CALLBACK error_dialog_cb(HWND, UINT uNotification, WPARAM, LPARAM lParam, LONG_PTR) {
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
        std::wstring wempty = ojb::widen(std::string());
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
    auto wlink = ojb::widen(link);
    auto noargs_msg = load_resource_narrow(IDS_NO_ARGS_ERROR_LABEL);
    auto header = std::string();
    if (noargs_msg == error) {
        header = load_resource_narrow(IDS_NO_ARGS_ERROR_HEADER);
    } else {
        header = load_resource_narrow(IDS_ERROR_DIALOG_HEADER);
    }
    auto subheader = load_resource_narrow(IDS_ERROR_DIALOG_SUBHEADER);
    auto fullheader = header + "\n\n" + subheader;
    std::wstring wmain = ojb::widen(fullheader);
    std::wstring wexpanded = ojb::widen("Hide detailed error message");
    std::wstring wcollapsed = ojb::widen("Show detailed error message");
    std::wstring werror = ojb::widen(error);

    TASKDIALOGCONFIG cf;
    std::memset(ojb::addressof(cf), '\0', sizeof(TASKDIALOGCONFIG));
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
            ojb::addressof(cf),
            nullptr,
            nullptr,
            nullptr);
}

void purge_work_dir() OJDKBUILD_NOEXCEPT {
    // find out dirs
    auto uddir = ojb::localappdata_dir();
    auto vendor_name = load_resource_narrow(IDS_VENDOR_DIRNAME);
    auto vendor_dir = uddir + vendor_name;
    auto app_name = load_resource_narrow(IDS_APP_DIRNAME);
    auto app_dir = vendor_dir + "/" + app_name;
    auto ws_dir = app_dir + "/webstart";

    // prepare double-terminated path
    auto ws_dir_wide = ojb::widen(ws_dir);
    auto ws_dir_terminated = std::vector<wchar_t>();
    std::copy(ws_dir_wide.begin(), ws_dir_wide.end(), std::back_inserter(ws_dir_terminated));
    ws_dir_terminated.push_back('\0');
    ws_dir_terminated.push_back('\0');

    // delete webstart dir recursively
    SHFILEOPSTRUCTW shop;
    std::memset(ojb::addressof(shop), '\0', sizeof(SHFILEOPSTRUCTW));
    shop.wFunc = FO_DELETE;
    shop.pFrom = ws_dir_terminated.data();
    shop.fFlags = FOF_NO_UI;
    auto err_shop = ::SHFileOperationW(ojb::addressof(shop));
    (void) err_shop;

    // try to delete other dirs only if there are
    // no contents from other installed components inside
    auto app_dir_wide = ojb::widen(app_dir);
    auto err_app = ::RemoveDirectoryW(app_dir_wide.c_str());
    (void) err_app;
    auto vendor_dir_wide = ojb::widen(vendor_dir);
    auto err_vendor = ::RemoveDirectoryW(vendor_dir_wide.c_str());
    (void) err_vendor;
}

std::string prepare_webstart_dir() {
    auto uddir = ojb::localappdata_dir();
    auto vendor_name = load_resource_narrow(IDS_VENDOR_DIRNAME);
    auto vendor_dir = uddir + vendor_name;
    create_dir(vendor_dir);
    auto app_name = load_resource_narrow(IDS_APP_DIRNAME);
    auto app_dir = vendor_dir + "/" + app_name;
    create_dir(app_dir);
    auto ws_dir = app_dir + "/webstart/";
    create_dir(ws_dir);
    return ws_dir;
}

std::vector<std::string> load_options(const std::string& optfile, const std::string& localdir,
        const std::string& wsdir, const std::string& jdkdir) {
    auto woptfile = ojb::widen(optfile);

    // check size
    WIN32_FILE_ATTRIBUTE_DATA fad;
    std::memset(ojb::addressof(fad), '\0', sizeof(WIN32_FILE_ATTRIBUTE_DATA));
    auto atcode = ::GetFileAttributesExW(woptfile.c_str(), GetFileExInfoStandard, ojb::addressof(fad));
    if (0 == atcode) {
        throw ojb::exception(std::string("Error opening options file,") +
            " path: [" + optfile + "]" +
            " error: [" + ojb::errcode_to_string(::GetLastError()) + "]");
    }
    LARGE_INTEGER size;
    size.HighPart = fad.nFileSizeHigh;
    size.LowPart = fad.nFileSizeLow;
    if(size.QuadPart > (1<<20)) {
        throw ojb::exception(std::string("Options file max size exceeded,") +
            " path: [" + optfile + "]" +
            " size: [" + ojb::to_string(size.QuadPart) + "]");
    }

    // read file
    auto res = std::vector<std::string>();
    auto stream = std::ifstream(woptfile);
    if (!stream.is_open()) {
        throw ojb::exception(std::string("Error opening options file,") +
                " path: [" + optfile + "]");
    }
    auto line = std::string();
    while (std::getline(stream, line)) {
        auto trimmed = ojb::str_trim(line);
        if (trimmed.length() > 0 && '#' != trimmed.at(0)) {
            ojb::str_replace(trimmed, "{{wsdir}}", wsdir);
            ojb::str_replace(trimmed, "{{localdir}}", localdir);
            ojb::str_replace(trimmed, "{{jdkdir}}", jdkdir);
            res.push_back(trimmed);
        }
    }
    if (stream.bad()) {
        throw ojb::exception(std::string("Error reading options file,") +
                " path: [" + optfile + "]");
    }
    return res;
}

void migrate_webstart_dir() OJDKBUILD_NOEXCEPT {
    // check dest dir doesn't exist
    auto uddir = ojb::localappdata_dir();
    auto vendor_name = load_resource_narrow(IDS_VENDOR_DIRNAME);
    auto vendor_dir = uddir + vendor_name + "/";
    auto app_name = load_resource_narrow(IDS_APP_DIRNAME);
    auto app_dir = vendor_dir + app_name + "/";
    auto dest_dir = app_dir + "webstart/";
    auto wdest_dir = ojb::widen(dest_dir);
    auto dest_attrs = ::GetFileAttributesW(wdest_dir.c_str());
    if (INVALID_FILE_ATTRIBUTES != dest_attrs) {
        return;
    }

    // list previous versions and find the most recent version
    auto dirs_list = std::vector<std::string>();
    auto appdir_prefix = load_resource_narrow(IDS_MIGRATE_APPDIR_PREFIX);
    auto search_req = vendor_dir + appdir_prefix + "*";
    auto wsearch_req = ojb::widen(search_req);
    WIN32_FIND_DATAW ffd;
    std::memset(ojb::addressof(ffd), '\0', sizeof(WIN32_FIND_DATAW));
    auto ha = ::FindFirstFileW(wsearch_req.c_str(), ojb::addressof(ffd));
    if (INVALID_HANDLE_VALUE != ha) {
        auto deferred = ojb::defer(ojb::make_lambda(::FindClose, ha));
        do {
            auto wname = std::wstring(ffd.cFileName);
            auto name = ojb::narrow(wname);
            if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                auto adir = vendor_dir + name + "/";
                auto wa_dir = adir + "webstart/";
                auto wwa_dir = ojb::widen(wa_dir);
                auto wa_attrs = ::GetFileAttributesW(wwa_dir.c_str());
                if ((INVALID_FILE_ATTRIBUTES != wa_attrs) && (wa_attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    dirs_list.push_back(name);
                }
            }
        } while(0 != ::FindNextFile(ha, ojb::addressof(ffd)));
    }
    if (0 == dirs_list.size()) {
        return;
    }

    // find the most recent version
    std::sort(dirs_list.begin(), dirs_list.end());
    auto old_app_name = dirs_list.back();
    auto old_app_dir = vendor_dir + old_app_name + "/";
    auto src_dir = old_app_dir + "webstart/";

    // migrate the most recent version
    create_dir(vendor_dir);
    create_dir(app_dir);
    auto wsrc_dir = ojb::widen(src_dir);
    auto err_move = ::MoveFileW(wsrc_dir.c_str(), wdest_dir.c_str());

    // cleanup
    if (0 != err_move) {
        auto wold_app_dir = ojb::widen(old_app_dir);
        auto err_old_app = ::RemoveDirectoryW(wold_app_dir.c_str());
        (void) err_old_app;
    }

    // adjust recently_used descriptor
    auto ru_dir = dest_dir + ".cache/icedtea-web/cache/";
    auto ru_path = ru_dir + "recently_used";
    auto ru_bak_path = ru_path + "." + old_app_name;
    auto wru_path = ojb::widen(ru_path);
    auto wru_bak_path = ojb::widen(ru_bak_path);
    auto err_bak = ::MoveFileW(wru_path.c_str(), wru_bak_path.c_str());
    if (0 == err_bak) {
        return;
    }
    {
        auto is = std::ifstream(wru_bak_path);
        if (!is.is_open()) {
            return;
        }
        auto os = std::ofstream(wru_path);
        if (!os.is_open()) {
            return;
        }
        auto line = std::string();
        while (std::getline(is, line)) {
            ojb::str_replace(line, old_app_name, app_name);
            os << line;
            os << "\n";
        }
    }
    auto err_del = ::DeleteFileW(wru_bak_path.c_str());
    (void) err_del;
}

} // namespace

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int) {
    ITW_HANDLE_INSTANCE = hInstance;
    try {
        auto cline = std::string(lpCmdLine);
        if (cline.empty()) {
            std::string msg = itw::load_resource_narrow(IDS_NO_ARGS_ERROR_LABEL);
            throw ojb::exception(msg);
        } else if ("-d" == cline) {
            itw::purge_work_dir();
            return 0;
        } else if ("-m" == cline) {
            itw::migrate_webstart_dir();
            return 0;
        }
        auto localdir = ojb::current_executable_dir();
        auto wsdir = itw::prepare_webstart_dir();
        auto jdkdir = localdir + "../";
        std::vector<std::string> args;
        auto opts = itw::load_options(localdir + "javaws_options.txt", localdir, wsdir, jdkdir);
        std::copy(opts.begin(), opts.end(), std::back_inserter(args));
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
