#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <chrono>

using namespace std;

// parses timestamp in format "YYYY-MM-DD_HH-MM-SS" into a time_point
chrono::system_clock::time_point parseTimestamp(const string &timestamp) {
    int year, month, day, hour, minute, second;

    sscanf(timestamp.c_str(), "%d-%d-%d_%d-%d-%d",
            &year, &month, &day, &hour, &minute, &second);

    struct tm tm = {};  // <- Proper way to zero-initialize

    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;

    return chrono::system_clock::from_time_t(mktime(&tm));  
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <days>" << endl;
        return 1;
    }

    int days = atoi(argv[1]);

    if (days < 0) {
        cout << "Error: days must be non-negative." << endl;
        return 1;
    }

    // File to modify
    string home = getenv("HOME") ? getenv("HOME") : "";
    if (home.empty()) {
        cout << "Error: $HOME not set." << endl;
        return 1;
    }
    string auth_file = home + "/.ssh/authorized_keys";

    ifstream infile(auth_file);
    if (!infile) {
        cout << "Error opening " << auth_file << endl;
        return 1;
    }

    vector<string> kept_lines;

    string line;
    //pattern to match bastion-client timestamp
    //e.g.: bastion-client-key_2025-05-14_07-16-14
    std::regex pattern(R"(bastion-client-key_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}))");

    auto now = chrono::system_clock::now();

    while (getline(infile, line)) {
        smatch match;
        if (regex_search(line, match, pattern)) {
            if (match.size() == 2) {
                string timestamp = match[1].str();

                auto parsed = parseTimestamp(timestamp);
                auto age = chrono::duration_cast<chrono::hours>(now - parsed).count() / 24;

                if (age > days) {
                    cout << "Removing key with timestamp " << timestamp << endl;
                    continue; // Skip adding this to kept_lines
                }
            }
        }
        kept_lines.push_back(line);
    }

    infile.close();

    ofstream outfile(auth_file, ios::trunc);
    if (!outfile) {
        cout << "Error opening " << auth_file << " for write." << endl;
        return 1;
    }

    for (const auto &l : kept_lines) {
        outfile << l << endl;
    }

    outfile.close();

    cout << "Done. Removed keys older than " << days << " days." << endl;

    return 0;
}
