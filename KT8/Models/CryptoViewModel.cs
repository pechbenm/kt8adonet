using System.ComponentModel.DataAnnotations;

namespace KT8.Models;

public enum CryptoAlgorithm { Aes, Rsa }

public class CryptoViewModel
{
    [Required(ErrorMessage = "Введите текст.")]
    [Display(Name = "Текст для шифрования или расшифровки")]
    public string Input { get; set; } = string.Empty;

    [EnumDataType(typeof(CryptoAlgorithm))] // отсекает значения вне enum, например Algorithm=7
    public CryptoAlgorithm Algorithm { get; set; } = CryptoAlgorithm.Aes;

    [Display(Name = "Сгенерировать ключ автоматически")]
    public bool GenerateKey { get; set; } = true;

    [Display(Name = "Ключ AES (Base64, 16/24/32 байта)")]
    public string? SecretKey { get; set; }

    [Display(Name = "Открытый ключ RSA")]
    public string? PublicKey { get; set; }

    [Display(Name = "Закрытый ключ RSA")]
    public string? PrivateKey { get; set; }

    //результат операции 
    public string? Output { get; set; }
    public string? OutputTitle { get; set; }
    public bool OutputIsCipherText { get; set; }
    public bool KeysGenerated { get; set; }
}