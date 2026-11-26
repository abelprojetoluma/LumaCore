
// Copyright (c) 2026 LumaCoreTech
// SPDX-License-Identifier: MIT
// Project: https://github.com/LumaCoreTech/LumaCore

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace LumaCore.Core.Cryptography;

/// <summary>
/// Configuration options for <see cref="Pbkdf2PasswordHasher"/>.
/// </summary>
public sealed class PasswordHashingOptions : IValidatableObject
{
    public const string SectionName = "PasswordHashing";

    public const int DefaultIterations = 600_000;

    public const int MinAllowedIterations = 220_000;

    public const int MaxAllowedIterations = 10_000_000;

    /// <summary>
    /// Gets or sets the PBKDF2 iteration count.
    /// </summary>
    public int Iterations { get; set; } = DefaultIterations;

    /// <inheritdoc/>
    public IEnumerable<ValidationResult> Validate(
        ValidationContext validationContext)
    {
        ArgumentNullException.ThrowIfNull(validationContext);

        if (Iterations < MinAllowedIterations)
        {
            yield return new ValidationResult(
                $"{nameof(Iterations)} must be at least " +
                $"{MinAllowedIterations}, but was {Iterations}.",
                new[] { nameof(Iterations) });
        }

        if (Iterations > MaxAllowedIterations)
        {
            yield return new ValidationResult(
                $"{nameof(Iterations)} must not exceed " +
                $"{MaxAllowedIterations}, but was {Iterations}.",
                new[] { nameof(Iterations) });
        }
    }

    /// <summary>
    /// Validates the options and throws when invalid.
    /// </summary>
    public void ThrowIfInvalid()
    {
        Validator.ValidateObject(
            this,
            new ValidationContext(this),
            validateAllProperties: true);
    }
}
