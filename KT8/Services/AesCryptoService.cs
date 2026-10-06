using KT8.Models;
using KT8.Services;
using System.Security.Cryptography;
using System.Text;

namespace KT8.Services;

public class AesCryptoService : ICryptoService
{
    private const int IvSize = 16;   // размер блока AES

    public CryptoAlgorithm Algorithm => CryptoAlgorithm.Aes;

    // 32 байта = AES-256
    public KeySet GenerateKeys()
        => new(SecretKey: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

    public string Encrypt(string plainText, KeySet keys)
    {
        var key = ParseKey(keys.SecretKey);

        // новый случайный IV на каждое шифрование: один текст даёт разные шифртексты
        var iv = RandomNumberGenerator.GetBytes(IvSize);

        using var aes = Aes.Create();
        aes.Key = key;
        var cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(plainText), iv); // padding PKCS7 по умолчанию

        // Формат результата: IV (16 байт) + шифртекст.
        return Convert.ToBase64String(iv.Concat(cipher).ToArray());
    }

    public string Decrypt(string cipherText, KeySet keys)
    {
        var key = ParseKey(keys.SecretKey);
        var data = Base64Helper.Decode(cipherText, "Шифртекст должен быть в формате Base64.");

        if (data.Length < IvSize + 16)
            throw new CryptoInputException("Шифртекст слишком короткий: это не результат шифрования AES.");

        var iv = data[..IvSize];
        var cipher = data[IvSize..];

        using var aes = Aes.Create();
        aes.Key = key;
        return Encoding.UTF8.GetString(aes.DecryptCbc(cipher, iv));
    }

    private static byte[] ParseKey(string? base64)
    {
        if (string.IsNullOrWhiteSpace(base64))
            throw new CryptoInputException("Укажите ключ AES.");

        var key = Base64Helper.Decode(base64, "Ключ AES должен быть в формате Base64.");

        if (key.Length is not (16 or 24 or 32))
            throw new CryptoInputException(
                $"Длина ключа AES должна быть 16, 24 или 32 байта, сейчас {key.Length}.");

        return key;
    }
}