#include "attacks.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdint>

using namespace std;


// constructor
PasswordCracker::PasswordCracker() {
    precomputeNumbers();
}



// PRE: a string input
// POST: the strings hash value
string PasswordCracker::sha1(const string& input) const {
    // SHA-1 constants
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Prepare message
    vector<uint8_t> msg(input.begin(), input.end());
    uint64_t ml = input.length() * 8; // Message length in bits

    // Padding
    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) {
        msg.push_back(0x00);
    }

    // Append length as 64-bit big-endian
    for (int i = 7; i >= 0; i--) {
        msg.push_back((ml >> (i * 8)) & 0xFF);
    }

    // Process message in 512-bit chunks
    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[80];

        // Break chunk into sixteen 32-bit big-endian words
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[chunk + i*4] << 24) |
                   (msg[chunk + i*4 + 1] << 16) |
                   (msg[chunk + i*4 + 2] << 8) |
                   (msg[chunk + i*4 + 3]);
        }

        // Extend the sixteen 32-bit words into eighty 32-bit words
        for (int i = 16; i < 80; i++) {
            uint32_t temp = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
            w[i] = (temp << 1) | (temp >> 31);
        }

        // Initialize hash value for this chunk
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        // Main loop
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result so far
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // Produce the final hash value as a 160-bit number (40 hex digits)
    stringstream ss;
    ss << hex << setfill('0')
       << setw(8) << h0
       << setw(8) << h1
       << setw(8) << h2
       << setw(8) << h3
       << setw(8) << h4;

    return ss.str();
}



// PRE: a path to a file of strings of hashed passwords
// POST: file of hashed passwords is loaded
int PasswordCracker::loadPasswords(const string& path) {
    ifstream file(path);
    if (!file.is_open()) {
        cerr << "Error opening password file: " << path << endl;
        return 0;
    }

    string line;
    while (getline(file, line)) {
        istringstream iss(line);
        string uid, hash;
        if (iss >> uid >> hash) {
            hashes[hash] = uid;
        }
    }
    file.close();

    cout << "Loaded " << hashes.size() << " password hashes" << endl;
    return hashes.size();
}



// PRE: a path to a file of strings that may be used in passwords needing to be crack
// POST: file of words that may be used in passwords is loaded
int PasswordCracker::loadDictionary(const string& path) {
    ifstream file(path);
    if (!file.is_open()) {
        cerr << "Error opening dictionary file: " << path << endl;
        return 0;
    }

    string word;
    while (getline(file, word)) {
        // Trim whitespace and convert to lowercase
        word.erase(0, word.find_first_not_of(" \t\r\n"));
        word.erase(word.find_last_not_of(" \t\r\n") + 1);
        transform(word.begin(), word.end(), word.begin(), ::tolower);

        if (!word.empty()) {
            words.push_back(word);
        }
    }
    file.close();

    cout << "Loaded " << words.size() << " dictionary words" << endl;
    return words.size();
}



// PRE: none
// POST: pre compute numbers to aid password cracking functions
void PasswordCracker::precomputeNumbers() {
    // Pre-compute strings for numbers 0-999
    precomputedNumbers.reserve(1000);
    for (int i = 0; i < 1000; i++) {
        precomputedNumbers.push_back(to_string(i));
    }
}



// PRE: a guesses hash value
// POST: if matching any hashes, true, else false
bool PasswordCracker::tryCrack(const string& guess) {
    string hash = sha1(guess);

    auto it = hashes.find(hash);
    if (it != hashes.end() && cracked.find(hash) == cracked.end()) {
        cracked[hash] = guess;

        // Print found password with visual separation
        cout << "\n\n\n\n\n";
        cout << "*** FOUND PASSWORD: \"" << guess << "\" (User ID: " << it->second << ") ***";
        cout << "\n\n\n\n\n" << endl;

        return true;
    }
    return false;
}



// PRE: none
// POST: guess numbers from 0-999999 (including padding)
void PasswordCracker::crackNumbers() {
    cout << "Cracking numeric passwords..." << endl;

    // Try straight numbers 0-9999
    for (int i = 0; i < 10000; i++) {
        tryCrack(to_string(i));

        if (i % 100 == 0) {
            cout << "  Progress: " << i << "/1000000" << endl;
        }
    }

    // Try zero-padded numbers
    for (int i = 0; i < 1000; i++) {
        ostringstream ss;

        // 4-digit padded
        ss << setw(4) << setfill('0') << i;
        tryCrack(ss.str());

        // 6-digit padded
        ss.str("");
        ss << setw(6) << setfill('0') << i;
        tryCrack(ss.str());

        // 8-digit padded
        ss.str("");
        ss << setw(8) << setfill('0') << i;
        tryCrack(ss.str());
    }

    /*
    // Try dates (YYYYMMDD and MMDDYYYY formats)
    cout << "  Trying date formats..." << endl;
    for (int year = 1950; year <= 2025; year++) {
        for (int month = 1; month <= 12; month++) {
            for (int day = 1; day <= 31; day++) {
                ostringstream ss;

                // YYYYMMDD
                ss << year << setw(2) << setfill('0') << month
                   << setw(2) << setfill('0') << day;
                tryCrack(ss.str());

                // MMDDYYYY
                ss.str("");
                ss << setw(2) << setfill('0') << month
                   << setw(2) << setfill('0') << day << year;
                tryCrack(ss.str());
            }

        }
    }
    */

    printProgress();
}



// PRE: none
// POST: guess every word in dictionary
void PasswordCracker::crackWords() {
    cout << "Cracking dictionary words..." << endl;

    for (size_t i = 0; i < words.size(); i++) {
        tryCrack(words[i]);

        if (i % 10 == 0 && i > 0) {
            cout << "  Progress: " << i << "/" << words.size() << endl;
        }
    }

    printProgress();
}



// PRE: none
// POST: guess every word plus numbers
void PasswordCracker::crackWordPlusNumbers() {
    cout << "Cracking words + numbers..." << endl;

    for (size_t i = 0; i < words.size(); i++) {
        const string& word = words[i];

        // Try word + number (0-999)
        for (int j = 0; j < 1000; j++) {
            tryCrack(word + precomputedNumbers[j]);
            tryCrack(precomputedNumbers[j] + word);
        }

        // Try word + zero-padded numbers
        for (int j = 0; j < 100; j++) {
            ostringstream ss;

            // 2-digit padded
            ss << word << setw(2) << setfill('0') << j;
            tryCrack(ss.str());

            // 3-digit padded
            ss.str("");
            ss << word << setw(3) << setfill('0') << j;
            tryCrack(ss.str());
        }

        if (i % 10 == 0 && i > 0) {
            cout << "  Progress: " << i << "/" << words.size() << endl;
        }
    }

    printProgress();
}



// PRE: none
// POST: guess every two word combination in dictionary
void PasswordCracker::crackTwoWords() {
    cout << "Cracking two-word combinations..." << endl;

    size_t total = words.size() * words.size();
    size_t count = 0;

    for (const auto& w1 : words) {
        for (const auto& w2 : words) {
            tryCrack(w1 + w2);
            count++;

            if (count % 100 == 0) {
                cout << "  Progress: " << count << "/" << total << endl;
            }
        }
    }

    printProgress();
}



// PRE: none
// POST: guess every two word combination with numbers in dictionary
void PasswordCracker::crackTwoWordsNumbers() {
    cout << "Cracking two words + numbers..." << endl;

    size_t total = words.size() * words.size();
    size_t count = 0;

    for (const auto& w1 : words) {
        for (const auto& w2 : words) {
            string combo = w1 + w2;

            for (int i = 0; i < 100; i++) {
                tryCrack(combo + precomputedNumbers[i]);
            }

            count++;
            if (count % 1000 == 0) {
                cout << "  Progress: " << count << "/" << total
                          << " (" << fixed << setprecision(1)
                          << (100.0 * count / total) << "%)" << endl;
            }
        }
    }

    printProgress();
}



// PRE: none
// POST: guess every three word combination in dictionary
void PasswordCracker::crackThreeWords() {
    cout << "Cracking three-word combinations (short words only)..." << endl;

    // Only use words with 6 or fewer characters
    vector<string> shortWords;
    for (const auto& w : words) {
        if (w.length() <= 7) {
            shortWords.push_back(w);
        }
    }

    cout << "  Using " << shortWords.size() << " short words" << endl;

    size_t count = 0;
    size_t total = shortWords.size() * shortWords.size() * shortWords.size();

    for (const auto& w1 : shortWords) {
        for (const auto& w2 : shortWords) {
            for (const auto& w3 : shortWords) {
                tryCrack(w1 + w2 + w3);
                count++;

                if (count % 10000 == 0) {
                    cout << "  Progress: " << count << "/" << total << endl;
                }
            }
        }
    }

    printProgress();
}



// PRE: none
// POST: tries to crack hashed passwords using all password cracking functions
void PasswordCracker::crackAll() {
    cout << "Starting password cracking..." << endl;
    cout << "Total hashes to crack: " << hashes.size() << endl << endl;

    crackNumbers();
    crackWords();
    crackWordPlusNumbers();
    crackTwoWords();
    crackTwoWordsNumbers();
    crackThreeWords();

    cout << "\n=== FINAL RESULTS ===" << endl;
    printProgress();
}



// PRE: none
// POST: calculates percentage of current cracking function
double PasswordCracker::getCrackPercentage() const {
    if (hashes.empty()) return 0.0;
    return (static_cast<double>(cracked.size()) / hashes.size()) * 100.0;
}



// PRE: none
// POST: calculate and print the progress of current cracking function
void PasswordCracker::printProgress() const {
    cout << "Cracked: " << cracked.size() << "/" << hashes.size()
              << " (" << fixed << setprecision(2)
              << getCrackPercentage() << "%)" << endl;
}



// PRE: path to output file
// POST: print results of password cracking to output file
void PasswordCracker::saveResults(const string& path) const {
    ofstream file(path);
    if (!file.is_open()) {
        cerr << "Error opening output file: " << path << endl;
        return;
    }

    file << "User ID,Password Hash,Cracked Password\n";

    for (const auto& pair : cracked) {
        const string& hash = pair.first;
        const string& password = pair.second;
        const string& uid = hashes.at(hash);

        file << uid << "," << hash << "," << password << "\n";
    }

    file.close();
    cout << "Results saved to " << path << endl;
}