using KT8.Models;
using KT8.Services;
using System.Security.Cryptography;
using System.Text;

namespace KT8.Services;

public class RsaCryptoService : ICryptoService
{
    private const int KeySizeBits = 2048;
    private static readonly RSAEncryptionPadding Padding = RSAEncryptionPadding.OaepSHA256;

    public CryptoAlgorithm Algorithm => CryptoAlgorithm.Rsa;

    public KeySet GenerateKeys()
    {
        using var rsa = RSA.Create(KeySizeBits);
        return new KeySet(
            PublicKey: Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()),
            PrivateKey: Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()));
    }

    // шифрование открытым ключом
    public string Encrypt(string plainText, KeySet keys)
    {
        if (string.IsNullOrWhiteSpace(keys.PublicKey))
            throw new CryptoInputException("Укажите открытый ключ RSA.");

        var keyBytes = Base64Helper.Decode(keys.PublicKey, "Открытый ключ RSA должен быть в формате Base64.");

        using var rsa = RSA.Create();
        try { rsa.ImportSubjectPublicKeyInfo(keyBytes, out _); }
        catch (CryptographicException)
        {
            throw new CryptoInputException("Некорректный открытый ключ RSA (ожидается X.509 SubjectPublicKeyInfo).");
        }

        var data = Encoding.UTF8.GetBytes(plainText);

        // RSA шифрует только короткие данные: размер ключа - служебные байты OAEP-SHA256
        var maxLength = rsa.KeySize / 8 - 2 * 32 - 2;
        if (data.Length > maxLength)
            throw new CryptoInputException(
                $"RSA-{rsa.KeySize} с OAEP-SHA256 шифрует не более {maxLength} байт за раз, а в тексте {data.Length} байт " +
                "(кириллица занимает 2 байта на символ). Сократите текст или используйте AES.");

        return Convert.ToBase64String(rsa.Encrypt(data, Padding));
    }

    // расшифрование закрытым ключом
    public string Decrypt(string cipherText, KeySet keys)
    {
        if (string.IsNullOrWhiteSpace(keys.PrivateKey))
            throw new CryptoInputException("Для расшифровки укажите закрытый ключ RSA.");

        var keyBytes = Base64Helper.Decode(keys.PrivateKey, "Закрытый ключ RSA должен быть в формате Base64.");
        var data = Base64Helper.Decode(cipherText, "Шифртекст должен быть в формате Base64.");

        using var rsa = RSA.Create();
        try { rsa.ImportPkcs8PrivateKey(keyBytes, out _); }
        catch (CryptographicException)
        {
            throw new CryptoInputException("Некорректный закрытый ключ RSA (ожидается PKCS#8).");
        }

        return Encoding.UTF8.GetString(rsa.Decrypt(data, Padding));
    }
}