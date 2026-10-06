using KT8.Models;

namespace KT8.Services;

public record KeySet(string? SecretKey = null, string? PublicKey = null, string? PrivateKey = null);

/// <summary>Ошибка, текст которой безопасно показать пользователю.</summary>
public class CryptoInputException : Exception
{
    public CryptoInputException(string message) : base(message) { }
}

public interface ICryptoService
{
    CryptoAlgorithm Algorithm { get; }
    KeySet GenerateKeys();
    string Encrypt(string plainText, KeySet keys);   // возвращает Base64
    string Decrypt(string cipherText, KeySet keys);  // принимает Base64
}

internal static class Base64Helper
{
    public static byte[] Decode(string value, string errorMessage)
    {
        try { return Convert.FromBase64String(value.Trim()); }
        catch (FormatException) { throw new CryptoInputException(errorMessage); }
    }
}