using System.Security.Cryptography;
using RedFilter.Core.Settings;

namespace RedFilter.Platform;

public sealed class DpapiSecretProtector : ISecretProtector
{
    public byte[] Protect(byte[] plaintext) =>
        ProtectedData.Protect(plaintext, optionalEntropy: null, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] ciphertext) =>
        ProtectedData.Unprotect(ciphertext, optionalEntropy: null, DataProtectionScope.CurrentUser);
}
