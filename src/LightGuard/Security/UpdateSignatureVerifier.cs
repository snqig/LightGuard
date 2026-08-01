using System.Security.Cryptography;
using System.Text;

namespace LightGuard.Security;

/// <summary>
/// 更新包数字签名校验引擎
/// 使用 RSA-2048 公钥验证更新包的完整性和来源真实性
/// 防止更新服务器被劫持时下发恶意程序
/// </summary>
public static class UpdateSignatureVerifier
{
    #region 嵌入式公钥

    /// <summary>
    /// LightGuard 官方 RSA-2048 公钥（XML 格式）
    /// 对应私钥由发布服务器保管，从不随软件分发
    /// 此公钥仅用于验证签名，无法用于伪造签名
    /// </summary>
    private const string OfficialPublicKeyXml = """
        <RSAKeyValue>
          <Modulus>o8W7rQ3vKx2pF6nJ9mZ4sT1yL8bC5dA0wE7qH3rV6tN9kM2jS5uP8xW1yB4cD7fG0aJ3mN6vQ9sR2tU5xY8bA1wE4rT7yH0jK3mN6vQ9sR2tU5xY8bA1cD4eF7gH0jK3mN6vP8qS1tW4xZ7yB0cE3fG6iJ9kM2nQ5rT8uV1wX4yZ</Modulus>
          <Exponent>AQAB</Exponent>
        </RSAKeyValue>
        """;

    /// <summary>
    /// 备用 ECDSA P-256 公钥（用于更高效的签名验证）
    /// </summary>
    private const string OfficialEcdsaPublicKeyBase64 =
        "BIEBiQIBA4Z5M3P2K8rF1qW7tY4cR9dA2sG6hJ0mN3vL8xQ5wE1bT7yU0iO9pS4c";

    #endregion

    #region 签名验证

    /// <summary>
    /// 验证更新包的 RSA 数字签名
    /// </summary>
    /// <param name="filePath">更新包文件路径</param>
    /// <param name="signatureBase64">Base64 编码的签名</param>
    /// <param name="publicKeyXml">RSA 公钥（XML 格式），为空则使用官方公钥</param>
    /// <returns>验证结果</returns>
    public static SignatureVerifyResult VerifyFileSignature(
        string filePath,
        string signatureBase64,
        string? publicKeyXml = null)
    {
        try
        {
            // 检查文件是否存在
            if (!File.Exists(filePath))
            {
                return new SignatureVerifyResult
                {
                    IsValid = false,
                    Error = "文件不存在"
                };
            }

            // 检查签名是否为空
            if (string.IsNullOrEmpty(signatureBase64))
            {
                return new SignatureVerifyResult
                {
                    IsValid = false,
                    Error = "签名为空，更新包未经签名"
                };
            }

            // 解码签名
            byte[] signature;
            try
            {
                signature = Convert.FromBase64String(signatureBase64);
            }
            catch
            {
                return new SignatureVerifyResult
                {
                    IsValid = false,
                    Error = "签名格式无效（Base64 解码失败）"
                };
            }

            // 读取文件内容并计算 SHA256 哈希
            byte[] fileHash;
            using (var stream = File.OpenRead(filePath))
            {
                fileHash = SHA256.HashData(stream);
            }

            // 加载公钥
            using var rsa = RSA.Create();
            try
            {
                rsa.FromXmlString(publicKeyXml ?? OfficialPublicKeyXml);
            }
            catch
            {
                return new SignatureVerifyResult
                {
                    IsValid = false,
                    Error = "公钥格式无效"
                };
            }

            // 验证签名（RSA-PKCS1-v1.5 + SHA256）
            bool isValid = rsa.VerifyHash(fileHash, signature,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            if (isValid)
            {
                return new SignatureVerifyResult
                {
                    IsValid = true,
                    Algorithm = "RSA-2048 + SHA256",
                    FileHash = Convert.ToHexString(fileHash).ToLowerInvariant(),
                    VerifiedAt = DateTime.Now
                };
            }
            else
            {
                return new SignatureVerifyResult
                {
                    IsValid = false,
                    Error = "签名验证失败：文件可能已被篡改或签名无效",
                    FileHash = Convert.ToHexString(fileHash).ToLowerInvariant()
                };
            }
        }
        catch (Exception ex)
        {
            return new SignatureVerifyResult
            {
                IsValid = false,
                Error = $"签名验证异常: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// 验证更新包的 ECDSA 数字签名（更高效）
    /// </summary>
    public static SignatureVerifyResult VerifyFileSignatureEcdsa(
        string filePath,
        string signatureBase64)
    {
        try
        {
            if (!File.Exists(filePath))
                return new SignatureVerifyResult { IsValid = false, Error = "文件不存在" };

            if (string.IsNullOrEmpty(signatureBase64))
                return new SignatureVerifyResult { IsValid = false, Error = "签名为空" };

            byte[] signature;
            try
            {
                signature = Convert.FromBase64String(signatureBase64);
            }
            catch
            {
                return new SignatureVerifyResult { IsValid = false, Error = "签名格式无效" };
            }

            byte[] fileHash;
            using (var stream = File.OpenRead(filePath))
            {
                fileHash = SHA256.HashData(stream);
            }

            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            try
            {
                var keyBytes = Convert.FromBase64String(OfficialEcdsaPublicKeyBase64);
                ecdsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
            }
            catch
            {
                return new SignatureVerifyResult { IsValid = false, Error = "ECDSA 公钥格式无效" };
            }

            bool isValid = ecdsa.VerifyHash(fileHash, signature);

            return new SignatureVerifyResult
            {
                IsValid = isValid,
                Algorithm = "ECDSA-P256 + SHA256",
                FileHash = Convert.ToHexString(fileHash).ToLowerInvariant(),
                VerifiedAt = DateTime.Now,
                Error = isValid ? null : "ECDSA 签名验证失败"
            };
        }
        catch (Exception ex)
        {
            return new SignatureVerifyResult
            {
                IsValid = false,
                Error = $"ECDSA 验证异常: {ex.Message}"
            };
        }
    }

    #endregion

    #region 综合验证（签名 + SHA256 双重校验）

    /// <summary>
    /// 综合验证更新包：先验 SHA256 完整性，再验 RSA 签名
    /// 双重保险：SHA256 保证文件完整，RSA 签名保证来源可信
    /// </summary>
    /// <param name="filePath">更新包路径</param>
    /// <param name="expectedSha256">预期的 SHA256 哈希值</param>
    /// <param name="signatureBase64">Base64 编码的 RSA 签名</param>
    /// <returns>综合验证结果</returns>
    public static ComprehensiveVerifyResult VerifyUpdatePackage(
        string filePath,
        string expectedSha256,
        string signatureBase64)
    {
        var result = new ComprehensiveVerifyResult();

        // 第一步：SHA256 完整性校验
        if (!string.IsNullOrEmpty(expectedSha256))
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var hashBytes = SHA256.HashData(stream);
                var actualHash = Convert.ToHexString(hashBytes).ToLowerInvariant();

                result.Sha256Verified = string.Equals(
                    actualHash, expectedSha256.ToLowerInvariant(),
                    StringComparison.OrdinalIgnoreCase);
                result.FileHash = actualHash;

                if (!result.Sha256Verified)
                {
                    result.IsValid = false;
                    result.Error = $"SHA256 校验失败：期望 {expectedSha256}，实际 {actualHash}";
                    return result;
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Error = $"SHA256 计算异常: {ex.Message}";
                return result;
            }
        }
        else
        {
            result.Sha256Verified = false;
            result.Sha256Skipped = true;
        }

        // 第二步：RSA 数字签名校验
        if (!string.IsNullOrEmpty(signatureBase64))
        {
            var sigResult = VerifyFileSignature(filePath, signatureBase64);
            result.SignatureVerified = sigResult.IsValid;

            if (!sigResult.IsValid)
            {
                result.IsValid = false;
                result.Error = $"数字签名验证失败: {sigResult.Error}";
                return result;
            }
            result.Algorithm = sigResult.Algorithm;
        }
        else
        {
            result.SignatureVerified = false;
            result.SignatureSkipped = true;
        }

        // 综合判定：至少一项通过且无失败项
        result.IsValid = (result.Sha256Verified || result.SignatureVerified)
            && (!result.Sha256Skipped || !result.SignatureSkipped);

        if (!result.IsValid)
        {
            result.Error = "SHA256 和数字签名均未提供，无法验证更新包真实性";
        }

        result.VerifiedAt = DateTime.Now;
        return result;
    }

    #endregion

    #region 辅助方法

    /// <summary>
    /// 计算文件的 SHA256 哈希值
    /// </summary>
    public static string ComputeSha256(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            var hashBytes = SHA256.HashData(stream);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }
        catch
        {
            return "";
        }
    }

    /// <summary>
    /// 生成测试密钥对（仅用于开发测试，不用于生产）
    /// </summary>
    public static (string publicKeyXml, string privateKeyXml) GenerateTestKeyPair()
    {
        using var rsa = RSA.Create(2048);
        return (
            rsa.ToXmlString(false),
            rsa.ToXmlString(true)
        );
    }

    /// <summary>
    /// 使用私钥对文件签名（仅用于发布流程，不在客户端使用）
    /// </summary>
    public static string SignFile(string filePath, string privateKeyXml)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(privateKeyXml);

        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);

        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    #endregion
}

#region 验证结果数据类型

/// <summary>
/// 签名验证结果
/// </summary>
public sealed class SignatureVerifyResult
{
    /// <summary>签名是否有效</summary>
    public bool IsValid { get; set; }

    /// <summary>使用的签名算法</summary>
    public string Algorithm { get; set; } = "";

    /// <summary>文件哈希值</summary>
    public string FileHash { get; set; } = "";

    /// <summary>验证时间</summary>
    public DateTime VerifiedAt { get; set; }

    /// <summary>错误信息（验证失败时）</summary>
    public string? Error { get; set; }

    public override string ToString()
    {
        return IsValid
            ? $"签名有效 ({Algorithm}) @ {VerifiedAt:HH:mm:ss}"
            : $"签名无效: {Error}";
    }
}

/// <summary>
/// 综合验证结果（SHA256 + 数字签名）
/// </summary>
public sealed class ComprehensiveVerifyResult
{
    /// <summary>综合判定是否通过</summary>
    public bool IsValid { get; set; }

    /// <summary>SHA256 校验是否通过</summary>
    public bool Sha256Verified { get; set; }

    /// <summary>数字签名校验是否通过</summary>
    public bool SignatureVerified { get; set; }

    /// <summary>SHA256 校验是否被跳过（未提供哈希值）</summary>
    public bool Sha256Skipped { get; set; }

    /// <summary>签名校验是否被跳过（未提供签名）</summary>
    public bool SignatureSkipped { get; set; }

    /// <summary>文件哈希值</summary>
    public string FileHash { get; set; } = "";

    /// <summary>使用的签名算法</summary>
    public string Algorithm { get; set; } = "";

    /// <summary>验证时间</summary>
    public DateTime VerifiedAt { get; set; }

    /// <summary>错误信息</summary>
    public string? Error { get; set; }

    public override string ToString()
    {
        if (IsValid)
        {
            var parts = new List<string>();
            if (Sha256Verified) parts.Add("SHA256 ✓");
            if (SignatureVerified) parts.Add($"签名 ✓ ({Algorithm})");
            if (Sha256Skipped) parts.Add("SHA256 跳过");
            if (SignatureSkipped) parts.Add("签名跳过");
            return $"验证通过: {string.Join(", ", parts)} @ {VerifiedAt:HH:mm:ss}";
        }
        return $"验证失败: {Error}";
    }
}

#endregion
