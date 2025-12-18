#ifndef ATTACKS_H
#define ATTACKS_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

class PasswordCracker {
public:
    // constructor
    PasswordCracker();



    // load password hashes from file
    // returns number of hashes loaded
    int loadPasswords(const string& path);



    // load dictionary words from file
    // returns number of words loaded
    int loadDictionary(const string& path);



    // execute all cracking strategies
    void crackAll();



    // individual cracking strategies
    void crackNumbers();
    void crackWords();
    void crackWordPlusNumbers();
    void crackTwoWords();
    void crackTwoWordsNumbers();
    void crackThreeWords();



    // get results
    int getTotalHashes() const { return hashes.size(); }
    int getCrackedCount() const { return cracked.size(); }
    double getCrackPercentage() const;



    // save results to file
    void saveResults(const string& path) const;



    // print progress
    void printProgress() const;



private:
    // compute SHA-1 hash of a string
    string sha1(const string& input) const;



    // try to crack a password guess
    // returns true if successful
    bool tryCrack(const string& guess);



    // hash -> User ID mapping
    unordered_map<string, string> hashes;



    // cracked hash -> password mapping
    unordered_map<string, string> cracked;



    // dictionary words
    vector<string> words;



    // pre-compute common number strings for reuse
    vector<string> precomputedNumbers;
    void precomputeNumbers();
};

#endif // ATTACKS_H