/*
 * Copyright 2019 akashche at redhat.com
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

#include <fstream>
#include <string>
#include <vector>

#include "ojdkbuild/utils/windows.hpp"
#include <shellapi.h>

#include "ojdkbuild/utils.hpp"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {

    auto trace = std::string();

    // expected options
    auto exedir = ojb::current_executable_dir();
    auto sid = exedir.substr(0, exedir.length() - 1).rfind('/');
    auto basedir = exedir.substr(0, sid + 1);
    auto jdkdir = basedir + "webstart/../";
    auto localdir = basedir + "webstart/";
    auto optfile = exedir + "../webstart/javaws_options.txt";
    auto woptfile = ojb::widen(optfile);
    auto expected = std::vector<std::string>();
    {
        auto stream = std::ifstream(woptfile);
        auto line = std::string();
        while (std::getline(stream, line)) {
            auto trimmed = ojb::str_trim(line);
            if (trimmed.length() > 0 && '#' != trimmed.at(0)) {
                //ojb::str_replace(trimmed, "{{wsdir}}", wsdir);
                ojb::str_replace(trimmed, "{{localdir}}", localdir);
                ojb::str_replace(trimmed, "{{jdkdir}}", jdkdir);
                ojb::str_replace(trimmed, "\"", "");
                expected.push_back(trimmed);
            }
        }
    }

    // actual options
    auto actual = std::vector<std::string>();
    {
        int argc = -1;
        auto wargv = ::CommandLineToArgvW(::GetCommandLineW(), ojb::addressof(argc));
        auto deferred = ojb::defer(ojb::make_lambda(::LocalFree, wargv));
        for (int i = 1; i < argc; i++) {
            auto wa = std::wstring(wargv[i]);
            auto st = ojb::narrow(wa);
            actual.push_back(st);

            trace.append("\n");
            trace.append(st);
        }
    }

    // checks
    auto error = std::string();

    // size
    if (error.empty() && actual.size() != expected.size() + 2) {
        error = "FAIL: Invalid size, ";
        error.append(ojb::to_string(expected.size()));
        error.append(":");
        error.append(ojb::to_string(actual.size()));
    }

    // appargs
    if (error.empty() &&
            "foo" != actual.at(actual.size() - 2) &&
            "bar baz" != actual.at(actual.size() - 1)) {
        error.append("FAIL: Invalid app args");
    }

    // entries
    for (size_t i = 0; error.empty() && i < expected.size(); i++) {
        auto ex = expected.at(i);
        auto ac = actual.at(i);
        if (std::string::npos == ex.find("{{wsdir}}")) {
            if (ac != ex) {
                error.append("FAIL:");
                error.append(" idx: [" + ojb::to_string(i) + "],");
                error.append(" expected: [" + ex + "],");
                error.append(" actual: [" + ac + "]");
            }
        } else {
            if (0 != ac.rfind("-Ditw.userdata=", 0)) {
                error.append("FAIL:");
                error.append(" idx: [" + ojb::to_string(i) + "],");
                error.append(" expected (wsdir): [" + ex + "],");
                error.append(" actual: [" + ac + "]");
            }
        }
    }

    if (error.empty()) {
        error.append("SUCCESS:");
    }
    auto msg = error + trace;
    MessageBoxW(nullptr, ojb::widen(msg).c_str(), ojb::widen("itw_launcher_test").c_str(), MB_OK);
    return 0;
}
