
// Copyright (c) 2026 LumaCoreTech
// SPDX-License-Identifier: MIT
// Project: https://github.com/LumaCoreTech/LumaCore

using System;
using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

namespace LumaCore.Core.Cryptography;

/// <summary>
/// PBKDF2 password hasher using HMAC-SHA512.
/// </summary>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private const string AlgorithmIdentifier = "pbkdf2-sha512";

    private const int SaltSize = 16;
    private const int KeySize = 64;
    private const int SaltAndKeySize = SaltSize + KeySize;

    private const int Base64PayloadLength =
        ((SaltAndKeySize + 2) / 3) * 4;

    private const int MaxPasswordLength = 1024;
    private const int MaxHashStringLength = 256;

    // Compatibility floor for verifying legacy hashes only.
    // Newly generated hashes always use validated options.
    private const int MinSupportedHashIterations = 1;

    private static readonly HashAlgorithmName HashAlgorithm =
        HashAlgorithmName.SHA512;

    private static readonly UTF8Encoding PasswordEncoding =
        new(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

    /// <summary>
    /// Initializes the hasher with validated options.
    /// </summary>
    public Pbkdf2PasswordHasher(PasswordHashingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.ThrowIfInvalid();

        Iterations = options.Iterations;
    }

    /// <summary>
    /// Initializes the hasher through IOptions.
    /// </summary>
    public Pbkdf2PasswordHasher(
        IOptions<PasswordHashingOptions> options)
        : this(GetValue(options))
    {
    }

    /// <summary>
    /// Gets the iterations used for newly generated hashes.
    /// </summary>
    public int Iterations { get; }

    /// <inheritdoc/>
    public string Hash(ReadOnlySpan<char> password)
    {
        ValidatePassword(password);

        Span<byte> salt = stackalloc byte[SaltSize];
        Span<byte> key = stackalloc byte[KeySize];
        Span<byte> saltAndKey = stackalloc byte[SaltAndKeySize];

        byte[]? passwordBuffer = null;

        try
        {
            RandomNumberGenerator.Fill(salt);

            int maxByteCount =
                PasswordEncoding.GetMaxByteCount(password.Length);

            passwordBuffer =
                ArrayPool<byte>.Shared.Rent(maxByteCount);

            int passwordByteCount =
                PasswordEncoding.GetBytes(password, passwordBuffer);

            Rfc2898DeriveBytes.Pbkdf2(
                password: passwordBuffer.AsSpan(0, passwordByteCount),
                salt: salt,
                destination: key,
                iterations: Iterations,
                hashAlgorithm: HashAlgorithm);

            salt.CopyTo(saltAndKey);
            key.CopyTo(saltAndKey[SaltSize..]);

            string base64 = Convert.ToBase64String(saltAndKey);

            return string.Create(
                CultureInfo.InvariantCulture,
                $"${AlgorithmIdentifier}${Iterations}${base64}");
        }
        finally
        {
            if (passwordBuffer is not null)
            {
                CryptographicOperations.ZeroMemory(passwordBuffer);
                ArrayPool<byte>.Shared.Return(passwordBuffer);
            }

            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(saltAndKey);
        }
    }

    /// <inheritdoc/>
    public bool Verify(
        ReadOnlySpan<char> password,
        ReadOnlySpan<char> passwordHash)
    {
        return Verify(password, passwordHash, out _);
    }

    /// <inheritdoc/>
    public bool Verify(
        ReadOnlySpan<char> password,
        ReadOnlySpan<char> passwordHash,
        out bool needsRehash)
    {
        needsRehash = false;

        ValidatePassword(password);

        ParseHash(
            passwordHash,
            out int iterationsFromHash,
            out ReadOnlySpan<char> base64Payload);

        Span<byte> storedSaltAndKey =
            stackalloc byte[SaltAndKeySize];

        Span<byte> derivedKey =
            stackalloc byte[KeySize];

        Span<char> canonicalBase64 =
            stackalloc char[Base64PayloadLength];

        byte[]? passwordBuffer = null;

        try
        {
            if (!Convert.TryFromBase64Chars(
                    base64Payload,
                    storedSaltAndKey,
                    out int decodedByteCount)
                || decodedByteCount != SaltAndKeySize)
            {
                throw new FormatException(
                    $"Password hash payload must decode to exactly {SaltAndKeySize} bytes.");
            }

            // Reject non-canonical Base64 representations.
            if (!Convert.TryToBase64Chars(
                    storedSaltAndKey,
                    canonicalBase64,
                    out int charsWritten)
                || charsWritten != Base64PayloadLength
                || !base64Payload.SequenceEqual(canonicalBase64))
            {
                throw new FormatException(
                    "Password hash payload is not canonical Base64.");
            }

            ReadOnlySpan<byte> storedSalt =
                storedSaltAndKey[..SaltSize];

            ReadOnlySpan<byte> storedKey =
                storedSaltAndKey[SaltSize..];

            int maxByteCount =
                PasswordEncoding.GetMaxByteCount(password.Length);

            passwordBuffer =
                ArrayPool<byte>.Shared.Rent(maxByteCount);

            int passwordByteCount =
                PasswordEncoding.GetBytes(password, passwordBuffer);

            Rfc2898DeriveBytes.Pbkdf2(
                password: passwordBuffer.AsSpan(0, passwordByteCount),
                salt: storedSalt,
                destination: derivedKey,
                iterations: iterationsFromHash,
                hashAlgorithm: HashAlgorithm);

            bool verified =
                CryptographicOperations.FixedTimeEquals(
                    derivedKey,
                    storedKey);

            // Successfully verified legacy hashes can be upgraded.
            needsRehash =
                verified && iterationsFromHash < Iterations;

            return verified;
        }
        finally
        {
            if (passwordBuffer is not null)
            {
                CryptographicOperations.ZeroMemory(passwordBuffer);
                ArrayPool<byte>.Shared.Return(passwordBuffer);
            }

            CryptographicOperations.ZeroMemory(storedSaltAndKey);
            CryptographicOperations.ZeroMemory(derivedKey);
            CryptographicOperations.ZeroMemory(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(
                    canonicalBase64));
        }
    }

    /// <inheritdoc/>
    public bool NeedsRehash(ReadOnlySpan<char> passwordHash)
    {
        ParseHash(
            passwordHash,
            out int iterationsFromHash,
            out _);

        return iterationsFromHash < Iterations;
    }

    private static void ValidatePassword(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty)
        {
            throw new ArgumentException(
                "Password must not be empty.",
                nameof(password));
        }

        if (password.Length > MaxPasswordLength)
        {
            throw new ArgumentException(
                $"Password exceeds the maximum length of {MaxPasswordLength} characters.",
                nameof(password));
        }
    }

    private static void ParseHash(
        ReadOnlySpan<char> passwordHash,
        out int iterations,
        out ReadOnlySpan<char> base64Payload)
    {
        iterations = 0;
        base64Payload = default;

        if (passwordHash.IsEmpty)
        {
            throw new ArgumentException(
                "Password hash must not be empty.",
                nameof(passwordHash));
        }

        if (passwordHash.Length > MaxHashStringLength)
        {
            throw new FormatException(
                "Password hash exceeds the maximum allowed length.");
        }

        if (passwordHash[0] != '$')
        {
            throw new FormatException(
                "Password hash must start with '$'.");
        }

        ReadOnlySpan<char> remainder = passwordHash[1..];

        int firstSeparator = remainder.IndexOf('$');

        if (firstSeparator < 0)
        {
            throw new FormatException(
                "Password hash is missing the iteration separator.");
        }

        ReadOnlySpan<char> algorithm =
            remainder[..firstSeparator];

        remainder = remainder[(firstSeparator + 1)..];

        int secondSeparator = remainder.IndexOf('$');

        if (secondSeparator < 0)
        {
            throw new FormatException(
                "Password hash is missing the payload separator.");
        }

        ReadOnlySpan<char> iterationsField =
            remainder[..secondSeparator];

        base64Payload = remainder[(secondSeparator + 1)..];

        if (!algorithm.Equals(
                AlgorithmIdentifier,
                StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"Password hash algorithm '{algorithm}' is not supported.");
        }

        if (!int.TryParse(
                iterationsField,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out iterations)
            || iterations < MinSupportedHashIterations)
        {
            throw new FormatException(
                "Password hash iteration count is invalid.");
        }

        if (iterations > PasswordHashingOptions.MaxAllowedIterations)
        {
            throw new FormatException(
                $"Password hash iteration count exceeds the maximum of {PasswordHashingOptions.MaxAllowedIterations}.");
        }

        if (base64Payload.Length != Base64PayloadLength)
        {
            throw new FormatException(
                "Password hash payload has an invalid length.");
        }
    }

    private static PasswordHashingOptions GetValue(
        IOptions<PasswordHashingOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return options.Value
            ?? throw new ArgumentNullException(
                nameof(options),
                "Options value is null.");
    }
}
