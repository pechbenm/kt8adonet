using KT8.Models;
using KT8.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace CryptoApp.Controllers;

public class CryptoController : Controller
{
    private readonly Dictionary<CryptoAlgorithm, ICryptoService> _services;

    public CryptoController(IEnumerable<ICryptoService> services)
        => _services = services.ToDictionary(s => s.Algorithm);

    [HttpGet]
    public IActionResult Index() => View(new CryptoViewModel());

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult Encrypt(CryptoViewModel model) => Process(model, encrypt: true);

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult Decrypt(CryptoViewModel model) => Process(model, encrypt: false);

    private IActionResult Process(CryptoViewModel model, bool encrypt)
    {
        if (!ModelState.IsValid)
            return View("Index", model);

        // без этого Tag Helper'ы покажут старые значения из ModelState,
        // а не те, что мы обновим в модели (например, сгенерированные ключи)
        ModelState.Clear();

        var service = _services[model.Algorithm];
        try
        {
            if (encrypt)
            {
                if (model.GenerateKey)
                {
                    var generated = service.GenerateKeys();
                    model.SecretKey = generated.SecretKey;
                    model.PublicKey = generated.PublicKey;
                    model.PrivateKey = generated.PrivateKey;
                    model.GenerateKey = false;   // дальше работа с созданым ключем
                    model.KeysGenerated = true;
                }

                model.Output = service.Encrypt(model.Input, ToKeySet(model));
                model.OutputTitle = "Шифртекст (Base64)";
                model.OutputIsCipherText = true;
            }
            else
            {
                model.Output = service.Decrypt(model.Input, ToKeySet(model));
                model.OutputTitle = "Расшифрованный текст";
            }
        }
        catch (CryptoInputException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
        }
        catch (CryptographicException)
        {
            ModelState.AddModelError(string.Empty, encrypt
                ? "Ошибка шифрования."
                : "Не удалось расшифровать: неверный ключ, не тот алгоритм или повреждённые данные.");
        }

        return View("Index", model);
    }

    private static KeySet ToKeySet(CryptoViewModel m) => new(m.SecretKey, m.PublicKey, m.PrivateKey);
}