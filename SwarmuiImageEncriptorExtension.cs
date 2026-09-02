using FreneticUtilities.FreneticExtensions;
using FreneticUtilities.FreneticToolkit;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.Processing;
using SwarmUI.Accounts;
using SwarmUI.Core;
using SwarmUI.Media;
using SwarmUI.Text2Image;
using SwarmUI.Utils;
using SwarmUI.WebAPI;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Image = SwarmUI.Utils.Image;
using ISImage = SixLabors.ImageSharp.Image;

namespace SwarmuiImageEncriptorExtension;

/// <summary>Extension for SwarmUI (Swarmui-Image-Encriptor) that allows generated images to be encrypted with AES-256-GCM on disk instantly when generated, while remaining seamlessly viewable in the UI with a secret code.</summary>
public class SwarmuiImageEncriptorExtension : Extension
{
    /// <summary>Magic header identifier for SwarmUI encrypted files (8 bytes ASCII 'SWARMENC').</summary>
    public static readonly byte[] MagicHeader = "SWARMENC"u8.ToArray();

    /// <summary>Format version byte.</summary>
    public const byte FormatVersion = 0x01;

    /// <summary>Total header prefix length before ciphertext: 8 (magic) + 1 (version) + 16 (salt) + 12 (nonce) + 16 (tag) = 53 bytes.</summary>
    public const int HeaderSize = 53;

    /// <summary>Parameter group for Image Encryption settings in the generation UI.</summary>
    public static T2IParamGroup EncryptionGroup;

    /// <summary>Registered Text2Image parameter for the user's encryption secret code.</summary>
    public static T2IRegisteredParam<string> EncryptionCodeParam;

    /// <summary>Permission to use the Image Encryptor feature.</summary>
    public static PermInfo PermUseImageEncryptor = Permissions.Register(new("imageencryptor_use", "[Image Encryptor] Use Image Encryption", "Allows the user to encrypt and decrypt output images.", PermissionDefault.USER, Permissions.GroupUser));

    /// <summary>Tracks active encryption settings per session ID (Enabled flag, Secret Code).</summary>
    public static readonly ConcurrentDictionary<string, (bool Enabled, string Code)> SessionSettings = new();

    /// <summary>Path to the JSON file where settings are saved persistently.</summary>
    public static string SettingsFilePath => Utilities.CombinePathWithAbsolute(Environment.CurrentDirectory, Program.DataDir, "image_encryptor_settings.json");

    /// <summary>Global fallback state when session ID is not isolated, enabled by default.</summary>
    public static volatile bool GlobalEnabled = true;

    /// <summary>Global fallback encryption code, defaulted to '1234'.</summary>
    public static volatile string GlobalCode = "1234";

    /// <summary>File system watcher monitoring the output directory for newly created images.</summary>
    public static FileSystemWatcher OutputWatcher;

    /// <summary>Tracks timestamps of recently encrypted files to avoid recursion in file change events.</summary>
    public static readonly ConcurrentDictionary<string, long> RecentlyEncryptedFiles = new();

    /// <summary>Called when the extension is prepared, registering script and stylesheet assets.</summary>
    public override void OnPreInit()
    {
        ScriptFiles.Add("Assets/image_encriptor.js");
        StyleSheetFiles.Add("Assets/image_encriptor.css");
    }

    /// <summary>Called when the extension initializes, registering API routes, parameters, generation hooks, settings, and file watcher.</summary>
    public override void OnInit()
    {
        Logs.Init("Swarmui-Image-Encriptor Extension loaded.");

        LoadSettingsFromDisk();

        EncryptionGroup = new("Image Encryption", Toggles: false, Open: false, IsAdvanced: true, Description: "Options for encrypting generated output images with AES-256-GCM.");

        EncryptionCodeParam = T2IParamTypes.Register<string>(new(
            "Image Encryption Code",
            "Secret passcode or PIN used to encrypt generated output images on disk with AES-256-GCM. When set and enabled, encryption activates automatically.",
            "1234",
            Group: EncryptionGroup,
            Toggleable: true,
            ViewType: ParamViewType.NORMAL,
            IsAdvanced: true
        ));

        API.RegisterAPICall(ImageEncryptor_SetState, false, PermUseImageEncryptor);
        API.RegisterAPICall(ImageEncryptor_GetState, false, PermUseImageEncryptor);
        API.RegisterAPICall(ImageEncryptor_SetSessionCode, false, PermUseImageEncryptor);
        API.RegisterAPICall(ImageEncryptor_DecryptImage, false, PermUseImageEncryptor);
        API.RegisterAPICall(ImageEncryptor_VerifyCode, false, PermUseImageEncryptor);
        API.RegisterAPICall(ImageEncryptor_EncryptRaw, false, PermUseImageEncryptor);

        T2IEngine.PostGenerateEvent += OnPostGenerate;
        T2IEngine.PostBatchEvent += OnPostBatch;

        StartWatcher();
    }

    /// <summary>Called just before the web server launches, when WebServer.WebApp is built and ready for middleware registration.</summary>
    public override void OnPreLaunch()
    {
        RegisterHttpMiddleware();
    }

    /// <summary>Loads persistent encryption settings from disk, or initializes defaults if not present.</summary>
    public static void LoadSettingsFromDisk()
    {
        try
        {
            string path = SettingsFilePath;
            if (File.Exists(path))
            {
                string jsonText = File.ReadAllText(path);
                JObject jObj = JObject.Parse(jsonText);
                GlobalEnabled = jObj.Value<bool?>("enabled") ?? true;
                GlobalCode = jObj.Value<string>("code") ?? "1234";
                Logs.Init($"[Swarmui-Image-Encriptor] Loaded settings from disk: Enabled={GlobalEnabled}, HasCode={!string.IsNullOrWhiteSpace(GlobalCode)}");
            }
            else
            {
                GlobalEnabled = true;
                GlobalCode = "1234";
                SaveSettingsToDisk();
            }
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Failed to load settings from disk: {ex.ReadableString()}");
            GlobalEnabled = true;
            GlobalCode = "1234";
        }
    }

    /// <summary>Saves current encryption settings to disk for permanent persistence across restarts.</summary>
    public static void SaveSettingsToDisk()
    {
        try
        {
            string path = SettingsFilePath;
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            JObject jObj = new()
            {
                ["enabled"] = GlobalEnabled,
                ["code"] = GlobalCode
            };
            File.WriteAllText(path, jObj.ToString());
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Failed to save settings to disk: {ex.ReadableString()}");
        }
    }

    /// <summary>Registers the ASP.NET Core HTTP middleware that intercepts ViewOutput calls to seamlessly decrypt images on-the-fly for the web UI.</summary>
    public static void RegisterHttpMiddleware()
    {
        try
        {
            WebServer.WebApp.Use(async (HttpContext context, Func<Task> next) =>
            {
                string rawPath = context.Request.Path.Value;
                if (rawPath is null || (!rawPath.StartsWith("/View/") && !rawPath.StartsWith("/Output/")))
                {
                    await next();
                    return;
                }

                bool isExact = rawPath.StartsWith("/View/");
                string subPath = isExact ? rawPath.After("/View/") : rawPath.After("/Output/");
                subPath = Uri.UnescapeDataString(subPath).Replace('\\', '/');

                User user = WebServer.GetUserFor(context);
                if (user is null)
                {
                    await next();
                    return;
                }

                string root = WebServer.GetUserOutputRoot("");
                if (Program.ServerSettings.Paths.AppendUserNameToOutputPath)
                {
                    if (isExact)
                    {
                        (string forUser, string newPath) = subPath.BeforeAndAfter('/');
                        if (forUser != user.UserID && !user.HasPermission(Permissions.ViewOthersOutputs))
                        {
                            await context.YieldJsonOutput(null, 400, Utilities.ErrorObj("unauthorized - you may not view other users' outputs", "unauthorized"));
                            return;
                        }
                        root = WebServer.GetUserOutputRoot(forUser);
                        subPath = newPath;
                    }
                    else
                    {
                        root = WebServer.GetUserOutputRoot(user);
                    }
                }

                (string realFilePath, string consoleError, string userError) = WebServer.CheckFilePath(root, subPath);
                if (consoleError is not null || string.IsNullOrWhiteSpace(realFilePath))
                {
                    await next();
                    return;
                }

                realFilePath = UserImageHistoryHelper.GetRealPathFor(user, realFilePath, root: root);
                if (!File.Exists(realFilePath))
                {
                    await next();
                    return;
                }

                byte[] fileBytes;
                try
                {
                    fileBytes = await File.ReadAllBytesAsync(realFilePath);
                }
                catch
                {
                    await next();
                    return;
                }

                if (!IsEncrypted(fileBytes))
                {
                    await next();
                    return;
                }

                // File is encrypted on disk. Retrieve encryption code.
                (bool isEnabled, string code) = GetActiveEncryptionState();
                if (string.IsNullOrWhiteSpace(code))
                {
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\": \"Image is encrypted on disk. Please enter your secret code in the Encryptor tab.\"}");
                    return;
                }

                byte[] decryptedBytes;
                try
                {
                    decryptedBytes = DecryptBytes(fileBytes, code.Trim());
                }
                catch (CryptographicException)
                {
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\": \"Decryption failed: Incorrect code or corrupted encrypted image.\"}");
                    return;
                }

                // If thumbnail preview was requested, generate lightweight thumbnail JPEG
                if (context.Request.Query.TryGetValue("preview", out StringValues previewToken) && $"{previewToken}" == "true")
                {
                    try
                    {
                        using ISImage isImg = ISImage.Load(decryptedBytes);
                        int maxDim = 256;
                        if (isImg.Width > maxDim || isImg.Height > maxDim)
                        {
                            int newW = isImg.Width;
                            int newH = isImg.Height;
                            if (newW > newH)
                            {
                                newH = (int)((double)newH * maxDim / newW);
                                newW = maxDim;
                            }
                            else
                            {
                                newW = (int)((double)newW * maxDim / newH);
                                newH = maxDim;
                            }
                            isImg.Mutate(x => x.Resize(newW, newH));
                        }

                        using MemoryStream ms = new();
                        isImg.SaveAsJpeg(ms);
                        byte[] previewBytes = ms.ToArray();

                        context.Response.ContentType = "image/jpeg";
                        context.Response.Headers.CacheControl = "private, max-age=60";
                        context.Response.StatusCode = 200;
                        await context.Response.Body.WriteAsync(previewBytes);
                        return;
                    }
                    catch (Exception ex)
                    {
                        Logs.Debug($"[Swarmui-Image-Encriptor] Failed to generate thumbnail preview: {ex.Message}");
                    }
                }

                // Determine content type of full decrypted image
                string contentType = "image/png";
                if (decryptedBytes.Length >= 3 && decryptedBytes[0] == 0xFF && decryptedBytes[1] == 0xD8 && decryptedBytes[2] == 0xFF)
                {
                    contentType = "image/jpeg";
                }
                else if (decryptedBytes.Length >= 12 && decryptedBytes[0] == 'R' && decryptedBytes[1] == 'I' && decryptedBytes[2] == 'F' && decryptedBytes[3] == 'F' && decryptedBytes[8] == 'W' && decryptedBytes[9] == 'E' && decryptedBytes[10] == 'B' && decryptedBytes[11] == 'P')
                {
                    contentType = "image/webp";
                }

                context.Response.ContentType = contentType;
                context.Response.Headers.CacheControl = $"private, max-age={Program.ServerSettings.Network.OutputCacheSeconds}";
                context.Response.StatusCode = 200;
                context.Response.ContentLength = decryptedBytes.Length;
                await context.Response.Body.WriteAsync(decryptedBytes, Program.GlobalProgramCancel);
            });
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Failed to register HTTP middleware: {ex.ReadableString()}");
        }
    }

    /// <summary>Starts or restarts the FileSystemWatcher monitoring the output directory.</summary>
    public static void StartWatcher()
    {
        try
        {
            string outputPath = Utilities.CombinePathWithAbsolute(Environment.CurrentDirectory, Program.ServerSettings.Paths.OutputPath);
            if (!Directory.Exists(outputPath))
            {
                Directory.CreateDirectory(outputPath);
            }

            OutputWatcher?.Dispose();
            OutputWatcher = new FileSystemWatcher(outputPath)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };

            OutputWatcher.Created += OnOutputFileEvent;
            OutputWatcher.Changed += OnOutputFileEvent;
            Logs.Init($"[Swarmui-Image-Encriptor] Active file watcher on output directory: '{outputPath}'");
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Failed to start output file watcher: {ex.ReadableString()}");
        }
    }

    /// <summary>Handles file watcher events when new files are saved in the output directory.</summary>
    private static void OnOutputFileEvent(object sender, FileSystemEventArgs e)
    {
        string ext = Path.GetExtension(e.FullPath).ToLowerFast();
        if (ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".webp")
        {
            return;
        }
        if (e.FullPath.Contains(".swarmpreview") || e.FullPath.Contains("swarm_metadata"))
        {
            return;
        }

        Utilities.RunCheckedTask(async () =>
        {
            await ProcessFileForEncryption(e.FullPath);
        });
    }

    /// <summary>Processes a file to encrypt it on disk if encryption is enabled and an encryption key is available.</summary>
    public static async Task ProcessFileForEncryption(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath) || !File.Exists(fullPath))
        {
            return;
        }

        string normPath = Path.GetFullPath(fullPath).Replace('\\', '/');

        // Prevent recursion on file write
        if (RecentlyEncryptedFiles.TryGetValue(normPath, out long lastTime) && Environment.TickCount64 - lastTime < 6000)
        {
            return;
        }

        (bool isEnabled, string code) = GetActiveEncryptionState();
        if (!isEnabled || string.IsNullOrWhiteSpace(code))
        {
            return;
        }

        // Wait briefly for file write locks to release
        byte[] fileBytes = null;
        for (int retry = 0; retry < 12; retry++)
        {
            try
            {
                fileBytes = await File.ReadAllBytesAsync(fullPath);
                break;
            }
            catch (IOException)
            {
                await Task.Delay(60);
            }
            catch (Exception)
            {
                await Task.Delay(60);
            }
        }

        if (fileBytes is null || fileBytes.Length < 8)
        {
            return;
        }

        if (IsEncrypted(fileBytes))
        {
            return;
        }

        try
        {
            // Extract metadata from the unencrypted image before encrypting, so .swarm.json can be preserved
            string metaJson = null;
            try
            {
                string ext = Path.GetExtension(fullPath).TrimStart('.').ToLowerFast();
                metaJson = new Image(fileBytes, MediaType.GetByExtension(ext)).GetMetadata();
            }
            catch
            {
                // Metadata extraction fallback
            }

            byte[] encrypted = EncryptBytes(fileBytes, code.Trim());
            RecentlyEncryptedFiles[normPath] = Environment.TickCount64;
            await File.WriteAllBytesAsync(fullPath, encrypted);
            Logs.Info($"[Swarmui-Image-Encriptor] Successfully encrypted output file on disk: '{fullPath}'");

            // Ensure .swarm.json metadata file is written with valid JSON so OutputMetadataTracker can read history without decoding the encrypted PNG
            string jsonPath = Path.ChangeExtension(fullPath, ".swarm.json");
            if (!string.IsNullOrWhiteSpace(metaJson) && !File.Exists(jsonPath))
            {
                await File.WriteAllTextAsync(jsonPath, metaJson);
            }
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Error encrypting file '{fullPath}': {ex.ReadableString()}");
        }
    }

    /// <summary>Returns the current active encryption state (Enabled flag and Secret Code).</summary>
    public static (bool Enabled, string Code) GetActiveEncryptionState(Session session = null)
    {
        if (session is not null && SessionSettings.TryGetValue(session.ID, out (bool Enabled, string Code) sessData))
        {
            if (sessData.Enabled && !string.IsNullOrWhiteSpace(sessData.Code))
            {
                return (sessData.Enabled, sessData.Code);
            }
            return (sessData.Enabled, sessData.Code);
        }

        return (GlobalEnabled, GlobalCode);
    }

    /// <summary>Handles post-generation event to hook encryption parameters before saving to disk.</summary>
    public static void OnPostGenerate(T2IEngine.PostGenerationEventParams postParams)
    {
        try
        {
            string code = null;
            bool enabled = false;

            if (postParams.UserInput.TryGet(EncryptionCodeParam, out string userCode) && !string.IsNullOrWhiteSpace(userCode))
            {
                code = userCode.Trim();
                enabled = true;
            }
            else if (postParams.UserInput.SourceSession is not null && SessionSettings.TryGetValue(postParams.UserInput.SourceSession.ID, out (bool Enabled, string Code) sessData))
            {
                enabled = sessData.Enabled;
                code = sessData.Code;
            }
            else
            {
                enabled = GlobalEnabled;
                code = GlobalCode;
            }

            if (enabled && !string.IsNullOrWhiteSpace(code))
            {
                postParams.UserInput.ExtraMeta["encrypted_with"] = "AES-256-GCM";
            }
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Error during post-generation hook: {ex.ReadableString()}");
        }
    }

    /// <summary>Handles post-batch event to verify all output images in the batch are encrypted.</summary>
    public static void OnPostBatch(T2IEngine.PostBatchEventParams batchParams)
    {
        try
        {
            (bool isEnabled, string code) = GetActiveEncryptionState(batchParams.UserInput.SourceSession);
            if (!isEnabled || string.IsNullOrWhiteSpace(code))
            {
                return;
            }

            Utilities.RunCheckedTask(async () =>
            {
                await Task.Delay(250);
                string userDir = batchParams.UserInput.SourceSession is not null ? UserImageHistoryHelper.GetRealPathFor(batchParams.UserInput.SourceSession.User, batchParams.UserInput.SourceSession.User.OutputDirectory) : null;
                userDir ??= Utilities.CombinePathWithAbsolute(Environment.CurrentDirectory, Program.ServerSettings.Paths.OutputPath);

                if (Directory.Exists(userDir))
                {
                    DateTime threshold = DateTime.UtcNow.AddMinutes(-2);
                    foreach (string file in Directory.EnumerateFiles(userDir, "*.*", SearchOption.AllDirectories))
                    {
                        string ext = Path.GetExtension(file).ToLowerFast();
                        if (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".webp")
                        {
                            if (File.GetLastWriteTimeUtc(file) >= threshold)
                            {
                                await ProcessFileForEncryption(file);
                            }
                        }
                    }
                }
            });
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Error during post-batch sweep: {ex.ReadableString()}");
        }
    }

    /// <summary>Checks whether a byte buffer starts with the SwarmEnc header.</summary>
    public static bool IsEncrypted(byte[] data)
    {
        if (data is null || data.Length < HeaderSize)
        {
            return false;
        }
        for (int i = 0; i < MagicHeader.Length; i++)
        {
            if (data[i] != MagicHeader[i])
            {
                return false;
            }
        }
        return data[8] == FormatVersion;
    }

    /// <summary>Encrypts plaintext bytes with AES-256-GCM using a key derived from the specified passphrase.</summary>
    public static byte[] EncryptBytes(byte[] plaintext, string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));
        }

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, 100_000, HashAlgorithmName.SHA256, 32);
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[plaintext.Length];

        using (AesGcm aes = new(key, 16))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        byte[] result = new byte[HeaderSize + ciphertext.Length];
        Array.Copy(MagicHeader, 0, result, 0, 8);
        result[8] = FormatVersion;
        Array.Copy(salt, 0, result, 9, 16);
        Array.Copy(nonce, 0, result, 25, 12);
        Array.Copy(tag, 0, result, 37, 16);
        Array.Copy(ciphertext, 0, result, 53, ciphertext.Length);

        return result;
    }

    /// <summary>Decrypts encrypted bytes with AES-256-GCM using a key derived from the specified passphrase.</summary>
    public static byte[] DecryptBytes(byte[] encryptedData, string passphrase)
    {
        if (encryptedData is null || encryptedData.Length < HeaderSize || !IsEncrypted(encryptedData))
        {
            throw new InvalidOperationException("Supplied data is not a valid SwarmEnc encrypted payload.");
        }
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));
        }

        byte[] salt = new byte[16];
        Array.Copy(encryptedData, 9, salt, 0, 16);
        byte[] nonce = new byte[12];
        Array.Copy(encryptedData, 25, nonce, 0, 12);
        byte[] tag = new byte[16];
        Array.Copy(encryptedData, 37, tag, 0, 16);

        int cipherLen = encryptedData.Length - HeaderSize;
        byte[] ciphertext = new byte[cipherLen];
        Array.Copy(encryptedData, 53, ciphertext, 0, cipherLen);

        byte[] key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, 100_000, HashAlgorithmName.SHA256, 32);
        byte[] plaintext = new byte[cipherLen];

        using (AesGcm aes = new(key, 16))
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        return plaintext;
    }

    /// <summary>API endpoint to update the full encryption state (Enabled switch and Secret Code), and saves to disk.</summary>
    public static Task<JObject> ImageEncryptor_SetState(Session session, bool enabled, string code)
    {
        string cleanCode = (code ?? "").Trim();
        SessionSettings[session.ID] = (enabled, cleanCode);
        GlobalEnabled = enabled;
        GlobalCode = cleanCode;
        SaveSettingsToDisk();

        Logs.Info($"[Swarmui-Image-Encriptor] Encryption state updated for session '{session.ID}': Enabled={enabled}, HasCode={!string.IsNullOrWhiteSpace(cleanCode)}");

        return Task.FromResult(new JObject()
        {
            ["success"] = true,
            ["enabled"] = enabled,
            ["has_code"] = !string.IsNullOrWhiteSpace(cleanCode),
            ["code"] = cleanCode
        });
    }

    /// <summary>API endpoint to retrieve the current encryption state.</summary>
    public static Task<JObject> ImageEncryptor_GetState(Session session)
    {
        (bool isEnabled, string code) = GetActiveEncryptionState(session);
        return Task.FromResult(new JObject()
        {
            ["success"] = true,
            ["enabled"] = isEnabled,
            ["has_code"] = !string.IsNullOrWhiteSpace(code),
            ["code"] = code
        });
    }

    /// <summary>API endpoint to store or clear the active encryption code for the current session, and saves to disk.</summary>
    public static Task<JObject> ImageEncryptor_SetSessionCode(Session session, string code)
    {
        string cleanCode = (code ?? "").Trim();
        bool isEnabled = !string.IsNullOrWhiteSpace(cleanCode);

        if (SessionSettings.TryGetValue(session.ID, out (bool Enabled, string Code) current))
        {
            isEnabled = current.Enabled;
        }

        SessionSettings[session.ID] = (isEnabled, cleanCode);
        GlobalCode = cleanCode;
        SaveSettingsToDisk();

        return Task.FromResult(new JObject()
        {
            ["success"] = true,
            ["enabled"] = isEnabled,
            ["active"] = !string.IsNullOrWhiteSpace(cleanCode)
        });
    }

    /// <summary>API endpoint to verify whether a code correctly decrypts an encrypted image.</summary>
    public static async Task<JObject> ImageEncryptor_VerifyCode(Session session, string image_path, string code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return new JObject() { ["valid"] = false, ["error"] = "Code is required" };
        }

        try
        {
            string realPath = UserImageHistoryHelper.GetRealPathFor(session.User, image_path);
            if (!File.Exists(realPath))
            {
                return new JObject() { ["valid"] = false, ["error"] = "File not found" };
            }

            byte[] fileBytes = await File.ReadAllBytesAsync(realPath);
            if (!IsEncrypted(fileBytes))
            {
                return new JObject() { ["valid"] = true, ["is_encrypted"] = false };
            }

            try
            {
                DecryptBytes(fileBytes, code.Trim());
                return new JObject() { ["valid"] = true, ["is_encrypted"] = true };
            }
            catch (CryptographicException)
            {
                return new JObject() { ["valid"] = false, ["is_encrypted"] = true, ["error"] = "Invalid code" };
            }
        }
        catch (Exception ex)
        {
            return new JObject() { ["valid"] = false, ["error"] = ex.Message };
        }
    }

    /// <summary>API endpoint to decrypt an encrypted image file or raw payload and return it as a data URL.</summary>
    public static async Task<JObject> ImageEncryptor_DecryptImage(Session session, string image_path, string encrypted_base64, string code)
    {
        string effectiveCode = code;
        if (string.IsNullOrWhiteSpace(effectiveCode) && SessionSettings.TryGetValue(session.ID, out (bool Enabled, string Code) sessData))
        {
            effectiveCode = sessData.Code;
        }
        if (string.IsNullOrWhiteSpace(effectiveCode))
        {
            effectiveCode = GlobalCode;
        }

        if (string.IsNullOrWhiteSpace(effectiveCode))
        {
            return new JObject() { ["success"] = false, ["error"] = "No encryption code provided or active in session." };
        }

        try
        {
            byte[] encryptedBytes;
            if (!string.IsNullOrWhiteSpace(encrypted_base64))
            {
                string cleanBase64 = encrypted_base64.After(",");
                if (string.IsNullOrEmpty(cleanBase64))
                {
                    cleanBase64 = encrypted_base64;
                }
                encryptedBytes = Convert.FromBase64String(cleanBase64);
            }
            else if (!string.IsNullOrWhiteSpace(image_path))
            {
                string realPath = UserImageHistoryHelper.GetRealPathFor(session.User, image_path);
                if (!File.Exists(realPath))
                {
                    return new JObject() { ["success"] = false, ["error"] = "Image file not found." };
                }
                encryptedBytes = await File.ReadAllBytesAsync(realPath);
            }
            else
            {
                return new JObject() { ["success"] = false, ["error"] = "Must specify either image_path or encrypted_base64." };
            }

            if (!IsEncrypted(encryptedBytes))
            {
                string mime = "image/png";
                if (!string.IsNullOrWhiteSpace(image_path))
                {
                    mime = Utilities.GuessContentType(image_path);
                }
                return new JObject()
                {
                    ["success"] = true,
                    ["is_encrypted"] = false,
                    ["image"] = $"data:{mime};base64,{Convert.ToBase64String(encryptedBytes)}"
                };
            }

            byte[] decryptedBytes;
            try
            {
                decryptedBytes = DecryptBytes(encryptedBytes, effectiveCode.Trim());
            }
            catch (CryptographicException)
            {
                return new JObject() { ["success"] = false, ["error"] = "Decryption failed: Incorrect code or corrupted file." };
            }

            string mimeType = "image/png";
            if (decryptedBytes.Length >= 3 && decryptedBytes[0] == 0xFF && decryptedBytes[1] == 0xD8 && decryptedBytes[2] == 0xFF)
            {
                mimeType = "image/jpeg";
            }
            else if (decryptedBytes.Length >= 12 && decryptedBytes[0] == 'R' && decryptedBytes[1] == 'I' && decryptedBytes[2] == 'F' && decryptedBytes[3] == 'F' && decryptedBytes[8] == 'W' && decryptedBytes[9] == 'E' && decryptedBytes[10] == 'B' && decryptedBytes[11] == 'P')
            {
                mimeType = "image/webp";
            }

            return new JObject()
            {
                ["success"] = true,
                ["is_encrypted"] = true,
                ["image"] = $"data:{mimeType};base64,{Convert.ToBase64String(decryptedBytes)}"
            };
        }
        catch (Exception ex)
        {
            Logs.Error($"[Swarmui-Image-Encriptor] Decrypt request error: {ex.ReadableString()}");
            return new JObject() { ["success"] = false, ["error"] = $"Error decrypting image: {ex.Message}" };
        }
    }

    /// <summary>API endpoint to encrypt a raw image payload directly.</summary>
    public static Task<JObject> ImageEncryptor_EncryptRaw(Session session, string image_base64, string code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return Task.FromResult(new JObject() { ["success"] = false, ["error"] = "Encryption code cannot be empty." });
        }
        if (string.IsNullOrWhiteSpace(image_base64))
        {
            return Task.FromResult(new JObject() { ["success"] = false, ["error"] = "Image payload cannot be empty." });
        }

        try
        {
            string clean = image_base64.After(",");
            if (string.IsNullOrEmpty(clean))
            {
                clean = image_base64;
            }
            byte[] rawBytes = Convert.FromBase64String(clean);
            byte[] encrypted = EncryptBytes(rawBytes, code.Trim());
            return Task.FromResult(new JObject()
            {
                ["success"] = true,
                ["encrypted_base64"] = Convert.ToBase64String(encrypted)
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new JObject() { ["success"] = false, ["error"] = ex.Message });
        }
    }
}
