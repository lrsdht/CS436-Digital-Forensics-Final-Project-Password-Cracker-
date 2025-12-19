#include "attacks.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <filesystem>

using namespace std;

static string p(const string& rel) {
#ifdef PROJECT_ROOT
    return (std::filesystem::path(PROJECT_ROOT) / rel).string();
#endif
}


int main() {
    cout << "loading stuff..." << endl;

    PasswordCracker cracker;

    // load the password hashes
    if (cracker.loadPasswords("passwords.txt") == 0) {
        cerr << "Failed to load passwords" << endl;
        return 1;
    }

    // load the dictionary
    if (cracker.loadDictionary("dictionary.txt") == 0) {
        cerr << "Failed to load dictionary" << endl;
        return 1;
    }

    int total = cracker.getTotalHashes();
    cout << "got " << total << " passwords to crack\n" << endl;

    // start timer
    auto start = chrono::high_resolution_clock::now();

    // run cracking strategies one by one
    cout << "trying plain numbers..." << endl;
    cracker.crackNumbers();
    cout << "cracked so far: " << cracker.getCrackedCount() << "/" << total << endl;

    cout << "trying dictionary words..." << endl;
    cracker.crackWords();
    cout << "cracked so far: " << cracker.getCrackedCount() << "/" << total << endl;

    cout << "trying words + numbers..." << endl;
    cracker.crackWordPlusNumbers();
    cout << "cracked so far: " << cracker.getCrackedCount() << "/" << total << endl;

    cout << "trying two word combos..." << endl;
    cracker.crackTwoWords();
    cout << "cracked so far: " << cracker.getCrackedCount() << "/" << total << endl;

    cout << "trying two words + numbers..." << endl;
    cracker.crackTwoWordsNumbers();
    cout << "cracked so far: " << cracker.getCrackedCount() << "/" << total << endl;

    cout << "trying three word combos (this takes a while)..." << endl;
    cracker.crackThreeWords();
    cout << "cracked so far: " << cracker.getCrackedCount() << "/" << total << endl;

    // calculate elapsed time
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = end - start;

    // print final results
    cout << "\ndone in " << fixed << setprecision(1)
              << elapsed.count() << " seconds" << endl;
    cout << "cracked " << cracker.getCrackedCount() << "/" << total
              << " (" << fixed << setprecision(1)
              << cracker.getCrackPercentage() << "%)" << endl;

    // save results
    cracker.saveResults("results/cracked.txt");
    cout << "saved to results/cracked.txt" << endl;

    return 0;
}
