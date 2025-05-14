## Builder Application Overview 🛠️

This C# application acts as a **file binder** a tool that allows multiple files to be embedded, encrypted, and executed from a single output executable. It supports encryption, in-memory execution, and post-execution cleanup, making it suitable for use cases where stealth and efficiency are required.

### Key Features ✨

1. **File Embedding** 📂: The application allows users to embed multiple files into the compiled executable. It requests the file paths and checks if the files exist before proceeding.

2. **Encryption Choices 🔐**: 
   - **XOR Encryption**: A basic encryption method that uses a randomly generated key to XOR each byte of the file with the key.
   - **AES Encryption**: A more secure encryption method using a randomly generated AES key and IV (Initialization Vector) for encrypting files.

3. **File Visibility Options 👀**:
   - Users can choose whether the dropped files should be hidden or visible in the target system. If hidden, the files will be marked as hidden, making them less detectable.

4. **Drop Path Configuration 🗂️**: 
   - The user can specify where the embedded files should be dropped, including system folders such as `%TEMP%`, `%APPDATA%`, and `%USERPROFILE%`, or opt for in-memory execution (where no files are written to disk).

5. **Stub Creation ⚡**: 
   - The application compiles a "stub" executable in C# that will handle the decryption and execution of the embedded files. The stub uses either XOR or AES to decrypt the files and executes them either from disk or directly in memory, based on the user’s choice.
   
6. **Obfuscation 🕵️‍♂️**: 
   - The encryption keys (AES or XOR) are obfuscated in the generated stub code to make it harder to analyze the encryption keys. The keys are reconstructed at runtime using C# code.

7. **File Cleanup 🧹**: 
   - After execution, the stub deletes the temporary files it created to clean up the system, ensuring that no unnecessary files are left behind.

### How It Works 🔧

1. The user is prompted to enter the number of files they wish to embed.
2. The application prompts for the paths of these files and verifies their existence.
3. Next, the user is asked to choose an encryption method (XOR or AES).
4. Then, the application generates an encryption key (AES or XOR) and optionally obfuscates it in the stub code.
5. The user is given the option to choose where the files should be dropped and whether they should be hidden.
6. The stub is then compiled using the `CSharpCodeProvider` class from `Microsoft.CSharp`. The encryption process is applied to the files and the stub is created with the appropriate references to the system libraries (`System.dll`, `System.Core.dll`, `System.Security.dll`).
7. The temporary files created during the process are deleted once the stub is compiled successfully.

### Code Breakdown 🖥️

1. **Encryption 🔑**: 
   - AES encryption uses the `System.Security.Cryptography.Aes` class, which is capable of securely encrypting data with a 256-bit key and IV.
   - XOR encryption is done using a randomly generated 32-byte key, where each byte of the file is XORed with the corresponding byte of the key.

2. **Obfuscation 🛡️**: 
   - The `ObfuscateString` method is used to obfuscate the encryption keys, which are later de-obfuscated at runtime. This helps protect the keys from static analysis.

3. **Stub Execution 🏃‍♂️**:
   - The generated stub can either drop files to a folder or execute them directly in memory. The stub decrypts the files using the appropriate method and runs them via a `Process` object or by loading assemblies into memory.

4. **File Cleanup 🧹**: 
   - Once the execution completes, the stub cleans up by deleting any temporary files it created during the process.

### Example Usage 🎮

1. **Embed Files**: The user specifies multiple files (e.g., `.exe`, `.dll`, `.txt` files) to be embedded into the executable.
2. **Choose Encryption**: The user selects either XOR or AES for file encryption.
3. **Choose Drop Location**: The user decides where to drop the files (e.g., `%TEMP%` or in-memory).
4. **Compile**: After the user configures the options, the application compiles the stub and generates the final executable.

### Conclusion 🎉

This C# builder application is a versatile **file binder**, enabling the packaging of multiple encrypted files into a single executable with flexible drop options and in-memory execution. The combination of AES or XOR encryption with obfuscation ensures that the embedded files are protected during execution, while the cleanup process ensures minimal trace left behind on the system.

![1248e477010d1e91550e1b17907f7924](https://github.com/user-attachments/assets/c47f412b-783a-48c9-84a6-37fe26a822a2)

