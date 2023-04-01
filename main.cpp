#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <unordered_map>

#define AES_KEY_SIZE 256
#define RSA_KEY_SIZE 2048

using namespace std;

// User class to represent a user with a username and password
class User {
    public: User(string username, string password) {
        this -> username = username;
        this -> password = password;
    }
    string getUsername() {
        return username;
    }
    string getPassword() {
        return password;
    }
    private: string username;
    string password;
};

// ACL class to represent an access control list for a file
class ACL {
    public: ACL() {}
    void addUser(User user) {
        users.push_back(user);
    }
    bool isUserAuthorized(User user) {
        for (auto it = users.begin(); it != users.end(); it++) {
            if (it -> getUsername() == user.getUsername() && it -> getPassword() == user.getPassword()) {
                return true;
            }
        }
        return false;
    }
    private: vector < User > users;
};

// Content server class to represent a content server with files and ACLs
class ContentServer {
    public: ContentServer() {}
    void addFile(string filename, string password) {
        // Generate a unique file key for the file
        unsigned char fileKey[AES_KEY_SIZE / 8];
        RAND_bytes(fileKey, AES_KEY_SIZE / 8);

        // Store the file key in a map with the filename as the key
        fileKeys[filename] = string((char * ) fileKey, AES_KEY_SIZE / 8);

        // Store the password in a map with the filename as the key
        filePasswords[filename] = password;

        // Create an ACL for the file
        ACL acl;
        acl.addUser(User("admin", "admin")); // Add the admin user to the ACL by default
        fileACLs[filename] = acl;
    }
    bool isFileAvailable(string filename) {
        return fileKeys.find(filename) != fileKeys.end();
    }
    string getFilePassword(string filename) {
        return filePasswords[filename];
    }
    bool isUserAuthorized(User user, string filename) {
        return fileACLs[filename].isUserAuthorized(user);
    }
    string getFileKey(string filename) {
        return fileKeys[filename];
    }
    private: unordered_map < string,
    string > fileKeys; // Map of filename to file key
    unordered_map < string,
    string > filePasswords; // Map of filename to password
    unordered_map < string,
    ACL > fileACLs; // Map of filename to ACL
};

// Authentication server class to represent an authentication server with user accounts and passwords
class AuthenticationServer {
    public: AuthenticationServer() {}
    void addUser(User user) {
        users[user.getUsername()] = user.getPassword();
    }
    bool authenticateUser(User user) {
        auto it = users.find(user.getUsername());
        return it != users.end() && it -> second == user.getPassword();
    }
    private: unordered_map < string,
    string > users; // Map of username to password
};

// Function to encrypt a file with AES-CBC using a given file key
void encryptFile(string filename, unsigned char * fileKey) {
    // Open the input file and read the plaintext
    ifstream file(filename.c_str(), ios::binary);
    if (!file.is_open()) {
        cout << "Error opening file " << filename << endl;
        return;
    }

    file.seekg(0, ios::end);
    int fileSize = file.tellg();
    file.seekg(0, ios::beg);
    char * plaintext = new char[fileSize];
    file.read(plaintext, fileSize);
    file.close();

    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // Set up the encryption context
    AES_KEY aesKey;
    AES_set_encrypt_key(fileKey, AES_KEY_SIZE, & aesKey);
    int numBlocks = (fileSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    unsigned char * ciphertext = new unsigned char[numBlocks * AES_BLOCK_SIZE];
    AES_cbc_encrypt((unsigned char * ) plaintext, ciphertext, fileSize, & aesKey, iv, AES_ENCRYPT);

    // Write the IV and ciphertext to the output file
    ofstream outfile((filename + ".enc").c_str(), ios::binary);
    outfile.write((char * ) iv, AES_BLOCK_SIZE);
    outfile.write((char * ) ciphertext, numBlocks * AES_BLOCK_SIZE);
    outfile.close();

    delete[] plaintext;
    delete[] ciphertext;
}

// Function to decrypt a file with AES-CBC using a given file key
void decryptFile(string filename, unsigned char * fileKey) {
    // Open the input file and read the IV and ciphertext
    ifstream file((filename + ".enc").c_str(), ios::binary);
    if (!file.is_open()) {
        cout << "Error opening file " << filename << ".enc" << endl;
        return;
    }
    unsigned char iv[AES_BLOCK_SIZE];
    file.read((char * ) iv, AES_BLOCK_SIZE);
    file.seekg(0, ios::end);
    int fileSize = file.tellg() - AES_BLOCK_SIZE;
    file.seekg(AES_BLOCK_SIZE, ios::beg);
    unsigned char * ciphertext = new unsigned char[fileSize];
    file.read((char * ) ciphertext, fileSize);
    file.close();
    // Set up the decryption context
    AES_KEY aesKey;
    AES_set_decrypt_key(fileKey, AES_KEY_SIZE, & aesKey);
    int numBlocks = (fileSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    unsigned char * plaintext = new unsigned char[numBlocks * AES_BLOCK_SIZE];
    AES_cbc_encrypt(ciphertext, plaintext, numBlocks * AES_BLOCK_SIZE, & aesKey, iv, AES_DECRYPT);

    // Write the plaintext to the output file
    ofstream outfile(filename.c_str(), ios::binary);
    outfile.write((char * ) plaintext, fileSize);
    outfile.close();

    delete[] plaintext;
    delete[] ciphertext;
}

int main() {
    // Set up the content server with some files and ACLs
    ContentServer contentServer;
    contentServer.addFile("file1.txt", "password1");
    contentServer.addFile("file2.pdf", "password2");
    contentServer.addFile("file3.jpg", "password3");
    // Set up the authentication server with some user accounts
    AuthenticationServer authenticationServer;
    authenticationServer.addUser(User("user1", "password1"));
    authenticationServer.addUser(User("user2", "password2"));
    authenticationServer.addUser(User("user3", "password3"));

    // Display the list of available files to the client
    cout << "Available files:" << endl;
    if (contentServer.isFileAvailable("file1.txt")) {
        cout << "file1.txt" << endl;
    }
    if (contentServer.isFileAvailable("file2.pdf")) {
        cout << "file2.pdf" << endl;
    }
    if (contentServer.isFileAvailable("file3.jpg")) {

        cout << "file3.jpg" << endl;
    }

    // Prompt the user for their username and password
    string username, password;
    cout << "Enter your username: ";
    cin >> username;
    cout << "Enter your password: ";
    cin >> password;

    // Authenticate the user and get their file key if successful
    unsigned char fileKey[AES_KEY_SIZE];
    if (authenticationServer.authenticate(username, password, contentServer, fileKey)) {
        // Prompt the user for the file they want to download
        string filename;
        cout << "Enter the name of the file you want to download: ";
        cin >> filename;

        // Check if the file is available and get the file key from the content server
        if (contentServer.isFileAvailable(filename)) {
            unsigned char serverFileKey[AES_KEY_SIZE];
            contentServer.getFileKey(filename, serverFileKey);

            // Check that the client and server file keys match
            if (memcmp(fileKey, serverFileKey, AES_KEY_SIZE) == 0) {
                // Decrypt the file using the file key
                decryptFile(filename, fileKey);
                cout << "File downloaded successfully." << endl;
            } else {
                cout << "Error: File key mismatch." << endl;
            }
        } else {
            cout << "Error: File not available." << endl;
        }
    } else {
        cout << "Error: Authentication failed." << endl;
    }

    return 0;
}
