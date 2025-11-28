
#include <hilog/log.h>
#include <string>
#include "napi/native_api.h"
#include <cstdio>     // For FILE, popen, pclose (though we are replacing it, keep for reference)
#include <array>      // For std::array
#include <iostream>   // For standard output, though hilog is preferred for HarmonyOS
#include <errno.h>    // For errno
#include <unistd.h>   // For fork, pipe, dup2, close, execle, _exit
#include <sys/wait.h>
#include <sstream>  
#include <vector>
#include <pty.h>      // For openpty
#include <poll.h>      // poll()
#include <fcntl.h>     // fcntl()
#include <filesystem>

namespace fs = std::__fs::filesystem;

/**
 * Parameter count.
 */
const int PARAMETER_COUNT = 1;

/**
 * Shell variables such as current working dir
 */
struct ShellState {
    std::string cwd = "/";
    std::string toyboxPath = "/system/bin/toybox";
};

static ShellState shellState; // Estado global entre llamadas

/**
 * Log print domain.
 */
const unsigned int LOG_PRINT_DOMAIN = 0xFF00;
std::string xorEncryptDecrypt(const std::string& data, const std::string& key) {
    std::string output = data;
    if (key.empty()) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Encryption key cannot be empty.");
        return data; // Return original data if key is empty
    }

    for (size_t i = 0; i < data.length(); ++i) {
        output[i] = data[i] ^ key[i % key.length()]; // XOR each byte with repeating key byte
    }
    return output;
}

// Native function to handle encryption via XOR cipher
static napi_value encrypt(napi_env env, napi_callback_info info) {
    if ((nullptr == env) || (nullptr == info)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Encrypt: env or info is null");
        return nullptr;
    }

    // Expected number of parameters: 1 (input string)
    size_t argc = 1;
    napi_value args[1] = { nullptr };

    // Get the arguments passed from JavaScript
    if (napi_ok != napi_get_cb_info(env, info, &argc, args, nullptr, nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Encrypt: napi_get_cb_info failed");
        return nullptr;
    }

    // Check if the correct number of arguments is provided
    if (argc < 1) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Encrypt: Not enough arguments. Expected 1.");
        napi_throw_type_error(env, nullptr, "Expected 1 argument: inputString");
        return nullptr;
    }

    // Convert input string argument using a mutable buffer
    size_t inputLen;
    if (napi_ok != napi_get_value_string_utf8(env, args[0], nullptr, 0, &inputLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Encrypt: Failed to get input string length");
        return nullptr;
    }
    std::vector<char> inputBuf(inputLen + 1); // +1 for null terminator
    if (napi_ok != napi_get_value_string_utf8(env, args[0], inputBuf.data(), inputBuf.size(), &inputLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Encrypt: Failed to get input string value");
        return nullptr;
    }
    std::string inputStr(inputBuf.data(), inputLen); // Construct string from buffer

    // Hardcoded encryption key
    const std::string encryptionKey = "w4d4f4k"; // This key is now hardcoded

    // Perform the XOR operation
    std::string resultStr = xorEncryptDecrypt(inputStr, encryptionKey);

    // Create a N-API string from the result
    napi_value napiResult;
    if (napi_ok != napi_create_string_utf8(env, resultStr.c_str(), resultStr.length(), &napiResult)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Encrypt: napi_create_string_utf8 failed");
        return nullptr;
    }

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "Encrypt: Operation completed successfully.");
    return napiResult;
}

// Native function to handle decryption via XOR cipher (same logic as encrypt)
static napi_value decrypt(napi_env env, napi_callback_info info) {
    if ((nullptr == env) || (nullptr == info)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Decrypt: env or info is null");
        return nullptr;
    }

    // Expected number of parameters: 1 (encrypted string)
    size_t argc = 1;
    napi_value args[1] = { nullptr };

    // Get the arguments passed from JavaScript
    if (napi_ok != napi_get_cb_info(env, info, &argc, args, nullptr, nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Decrypt: napi_get_cb_info failed");
        return nullptr;
    }

    // Check if the correct number of arguments is provided
    if (argc < 1) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Decrypt: Not enough arguments. Expected 1.");
        napi_throw_type_error(env, nullptr, "Expected 1 argument: encryptedString");
        return nullptr;
    }

    // Convert encrypted string argument using a mutable buffer
    size_t encryptedLen;
    if (napi_ok != napi_get_value_string_utf8(env, args[0], nullptr, 0, &encryptedLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Decrypt: Failed to get encrypted string length");
        return nullptr;
    }
    std::vector<char> encryptedBuf(encryptedLen + 1); // +1 for null terminator
    if (napi_ok != napi_get_value_string_utf8(env, args[0], encryptedBuf.data(), encryptedBuf.size(), &encryptedLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Decrypt: Failed to get encrypted string value");
        return nullptr;
    }
    std::string encryptedStr(encryptedBuf.data(), encryptedLen); // Construct string from buffer

    // Hardcoded encryption key (same key for decryption)
    const std::string encryptionKey = "w4d4f4k";

    // Perform the XOR operation (decrypts with the same function)
    std::string resultStr = xorEncryptDecrypt(encryptedStr, encryptionKey);

    // Create a N-API string from the result
    napi_value napiResult;
    if (napi_ok != napi_create_string_utf8(env, resultStr.c_str(), resultStr.length(), &napiResult)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "Decrypt: napi_create_string_utf8 failed");
        return nullptr;
    }

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "Decrypt: Operation completed successfully.");
    return napiResult;
}

static napi_value TriggerOverflow(napi_env env, napi_callback_info info) {
    if ((nullptr == env) || (nullptr == info)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "TriggerOverflow: env or info is null");
        return nullptr;
    }

    size_t argc = 1;
    napi_value args[1] = { nullptr };

    if (napi_ok != napi_get_cb_info(env, info, &argc, args, nullptr, nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "TriggerOverflow: napi_get_cb_info failed");
        return nullptr;
    }

    if (argc < 1) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "TriggerOverflow: Not enough arguments. Expected 1.");
        napi_throw_type_error(env, nullptr, "Expected 1 argument: inputString");
        return nullptr;
    }

    // Get input string length
    size_t inputLen;
    if (napi_ok != napi_get_value_string_utf8(env, args[0], nullptr, 0, &inputLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "TriggerOverflow: Failed to get input string length");
        return nullptr;
    }

    // Create a mutable buffer to get the input string value
    std::vector<char> inputBuf(inputLen + 1); // +1 for null terminator
    if (napi_ok != napi_get_value_string_utf8(env, args[0], inputBuf.data(), inputBuf.size(), &inputLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "TriggerOverflow: Failed to get input string value");
        return nullptr;
    }
    const char* inputCStr = inputBuf.data(); // Get C-style string pointer

    // --- VULNERABLE SECTION START ---
    // Declare a small fixed-size buffer on the stack
    char fixedBuffer[20]; // This buffer can hold 19 characters + null terminator

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "Input string length: %zu", inputLen);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "Fixed buffer size: %zu", sizeof(fixedBuffer));

    // Use strcpy - THIS IS THE VULNERABLE CALL!
    // strcpy does not check the destination buffer size, leading to overflow if inputCStr is too long.
    // A safe alternative would be strncpy (with careful handling of null termination) or snprintf.
    // For production, use C++ strings or secure string handling libraries.
    strcpy(fixedBuffer, inputCStr);

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "Copied content (if not crashed): %s", fixedBuffer);
    // --- VULNERABLE SECTION END ---

    // Return a success message (this line might not be reached if overflow crashes the app)
    std::string successMsg = "String copied to buffer. Input length: " + std::to_string(inputLen);
    napi_value napiResult;
    if (napi_ok != napi_create_string_utf8(env, successMsg.c_str(), successMsg.length(), &napiResult)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "TriggerOverflow: napi_create_string_utf8 failed");
        return nullptr;
    }

    return napiResult;
}

std::vector<std::string> splitString(const std::string& str) {
    std::vector<std::string> tokens;
    std::string token;
    bool inQuotes = false;
    char quoteChar = '\0';

    for (size_t i = 0; i < str.size(); ++i) {
        char c = str[i];

        if (inQuotes) {
            if (c == quoteChar) {
                inQuotes = false; // Fin de la cita
            } else {
                token += c;
            }
        } else {
            if (c == '"' || c == '\'') {
                inQuotes = true;
                quoteChar = c;
                // No agregamos la comilla al token
            } else if (std::isspace(c)) {
                if (!token.empty()) {
                    tokens.push_back(token);
                    token.clear();
                }
                // Ignore consecutive spaces
            } else {
                token += c;
            }
        }
    }

    if (!token.empty()) {
        tokens.push_back(token);
    }

    return tokens;
}

std::string getBasename(const std::string& path) {
    size_t last_slash_pos = path.find_last_of('/');
    if (std::string::npos == last_slash_pos) {
        return path; // No slash, so path itself is the basename
    }
    return path.substr(last_slash_pos + 1);
}

static napi_value ExecuteCommand(napi_env env, napi_callback_info info) {
    if ((nullptr == env) || (nullptr == info)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: env or info is null");
        return nullptr;
    }

    size_t argc = 2; // Now expecting two arguments
    napi_value args[2] = { nullptr };

    if (napi_ok != napi_get_cb_info(env, info, &argc, args, nullptr, nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: napi_get_cb_info failed");
        return nullptr;
    }

    if (argc < 2) { // Ensure both arguments are provided
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: Not enough arguments. Expected 2 (binaryPath, commandArguments).");
        napi_throw_type_error(env, nullptr, "Expected 2 arguments: binaryPath, commandArguments");
        return nullptr;
    }

    // Get binary path string (first argument)
    size_t binaryPathLen;
    if (napi_ok != napi_get_value_string_utf8(env, args[0], nullptr, 0, &binaryPathLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: Failed to get binary path length");
        return nullptr;
    }
    std::vector<char> binaryPathBuf(binaryPathLen + 1);
    if (napi_ok != napi_get_value_string_utf8(env, args[0], binaryPathBuf.data(), binaryPathBuf.size(), &binaryPathLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: Failed to get binary path value");
        return nullptr;
    }
    std::string binaryPath(binaryPathBuf.data(), binaryPathLen);

    // Get command arguments string (second argument)
    size_t commandArgsLen;
    if (napi_ok != napi_get_value_string_utf8(env, args[1], nullptr, 0, &commandArgsLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: Failed to get command arguments length");
        return nullptr;
    }
    std::vector<char> commandArgsBuf(commandArgsLen + 1);
    if (napi_ok != napi_get_value_string_utf8(env, args[1], commandArgsBuf.data(), commandArgsBuf.size(), &commandArgsLen)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: Failed to get command arguments value");
        return nullptr;
    }
    std::string commandArguments(commandArgsBuf.data(), commandArgsLen);

    // --- REAL EXECUTION ATTEMPT START ---
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "Attempting execution of binary '%s' with arguments: '%s'", binaryPath.c_str(), commandArguments.c_str());

    std::vector<std::string> tokens = splitString(commandArguments);
    std::vector<char*> c_argv_pointers; // This will hold char* for execv

    // Get the basename of the executable path to use as argv[0]
    std::string binaryBasename = getBasename(binaryPath);
    c_argv_pointers.push_back(const_cast<char*>(binaryBasename.c_str())); // argv[0]

    // Add parsed tokens as arguments
    for (const std::string& token : tokens) {
        c_argv_pointers.push_back(const_cast<char*>(token.c_str()));
    }
    c_argv_pointers.push_back(nullptr); // Null-terminate the argument list for execv

    int pipefd[2]; // pipefd[0] is read end, pipefd[1] is write end
    if (pipe(pipefd) == -1) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: pipe failed! errno: %d", errno);
        napi_throw_error(env, nullptr, ("Failed to create pipe. errno: " + std::to_string(errno)).c_str());
        return nullptr;
    }

    pid_t pid = fork();
    if (pid == -1) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG, "ExecuteCommand: fork failed! errno: %d", errno);
        close(pipefd[0]);
        close(pipefd[1]);
        napi_throw_error(env, nullptr, ("Failed to fork process. errno: " + std::to_string(errno)).c_str());
        return nullptr;
    }
    
    if (pid == 0) {
    // --- CHILD PROCESS ---
    close(pipefd[0]); // Close unused read end

    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]); // Close original write end

    execv(binaryPath.c_str(), c_argv_pointers.data());

    // If execv fails
    _exit(EXIT_FAILURE);
        
    } else {
        // --- PARENT PROCESS ---
        close(pipefd[1]); // Close unused write end
    
        // Set pipe to non-blocking
        int flags = fcntl(pipefd[0], F_GETFL, 0);
        fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    
        std::string result_output;
        std::array<char, 512> buffer;
    
        struct pollfd pfd;
        pfd.fd = pipefd[0];
        pfd.events = POLLIN;
    
        while (true) {
            int poll_result = poll(&pfd, 1, 3000); // 3 sec timeout
    
            if (poll_result > 0 && (pfd.revents & POLLIN)) {
                ssize_t bytes_read = read(pipefd[0], buffer.data(), buffer.size() - 1);
                if (bytes_read > 0) {
                    buffer[bytes_read] = '\0';
                    result_output += buffer.data();
                }
            } else if (poll_result == 0) {
                // Timeout reached (optional: log or break)
                break;
            } else {
                // Error or end-of-stream
                break;
            }
        }

        close(pipefd[0]);
    
        int status;
        waitpid(pid, &status, 0);
    
        napi_value napiResult;
        if (napi_ok != napi_create_string_utf8(env, result_output.c_str(), result_output.length(), &napiResult)) {
            return nullptr;
        }
    
        return napiResult;
    }
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

bool startsWith(const std::string& str, const std::string& prefix) {
    return str.rfind(prefix, 0) == 0;
}

std::string ExecuteCommandInternal(const std::string& binaryPath, const std::string& commandArgs) {
    // Simula cómo tu NAPI envuelve esto, pero directamente
    std::vector<std::string> tokens = splitString(commandArgs);
    std::vector<char*> c_argv_pointers;

    std::string binaryBasename = getBasename(binaryPath);
    c_argv_pointers.push_back(const_cast<char*>(binaryBasename.c_str()));
    for (const std::string& token : tokens) {
        c_argv_pointers.push_back(const_cast<char*>(token.c_str()));
    }
    c_argv_pointers.push_back(nullptr);

    int pipefd[2];
    if (pipe(pipefd) == -1) return "Error: pipe() failed\n";

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]); close(pipefd[1]);
        return "Error: fork() failed\n";
    }

    if (pid == 0) {
        chdir(shellState.cwd.c_str());
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execv(binaryPath.c_str(), c_argv_pointers.data());
        _exit(EXIT_FAILURE);
    }

    close(pipefd[1]);
    std::string output;
    char buffer[512];
    ssize_t bytesRead;
    while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    close(pipefd[0]);
    int status;
    waitpid(pid, &status, 0);
    return output;
}

std::string processShellInput(const std::string& inputLine) {
    std::string input = trim(inputLine);
    if (input.empty()) return "";

    if (startsWith(input, "cd ")) {
        std::string path = trim(input.substr(3));
        
        std::string newPath = "";
        fs::path next;
        
        if (path == "..") {
            size_t slashPos = shellState.cwd.find_last_of('/');
            if (slashPos != std::string::npos && slashPos > 0) {
                newPath = shellState.cwd.substr(0, slashPos);
            } else {
                newPath = "/";
            }
        } else if (path[0] == '/') {
            newPath = path;
        } else {
            newPath = shellState.cwd + "/" + path;
            fs::path current(shellState.cwd);
            next = current / path;
            newPath = next.lexically_normal().string();
        }
        
        try{
            if (fs::exists(newPath) && fs::is_directory(newPath)) {
            shellState.cwd = newPath;
            } else {
                return "cd: no such file or directory: " + path + "\n";
            }
        } catch (const fs::filesystem_error& e) {
            return "cd: Can't open' " + path + " (Probably insuficient permission)" + "\n";
        }
        
        
        return "Changed directory to: " + shellState.cwd + "\n";
    }

    if (input == "pwd") {
        return shellState.cwd + "\n";
    }

    // Comando toybox normal
    return ExecuteCommandInternal(shellState.toyboxPath, input);
}

static napi_value ProcessShellCommand(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "Expected 1 argument: inputCommand");
        return nullptr;
    }

    size_t strLen;
    napi_get_value_string_utf8(env, args[0], nullptr, 0, &strLen);
    std::vector<char> buffer(strLen + 1);
    napi_get_value_string_utf8(env, args[0], buffer.data(), buffer.size(), &strLen);
    std::string input(buffer.data(), strLen);

    std::string output = processShellInput(input);

    napi_value result;
    napi_create_string_utf8(env, output.c_str(), output.length(), &result);
    return result;
}


EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
   // if ((nullptr == env) || (nullptr == exports)) {
   //     OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Init", "env or exports is null");
   //     return exports;
   // }

    napi_property_descriptor desc[] = {
        {"encrypt", nullptr, encrypt, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"decrypt", nullptr, decrypt, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"triggerOverflow", nullptr, TriggerOverflow, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"executeCommand", nullptr, ExecuteCommand, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"processShellCommand", nullptr, ProcessShellCommand, nullptr, nullptr, nullptr, napi_default, nullptr},
        
    };
    if (napi_ok != napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Init", "napi_define_properties failed");
        return nullptr;
    }
    return exports;
}

EXTERN_C_END

static napi_module cryptoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void)
{
    napi_module_register(&cryptoModule);
}