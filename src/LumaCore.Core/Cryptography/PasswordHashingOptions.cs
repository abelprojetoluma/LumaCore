
// Copyright (c) 2026 LumaCoreTech
// SPDX-License-Identifier: MIT
// Project: https://github.com/LumaCoreTech/LumaCore

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace LumaCore.Core.Cryptography;

/// <summary>
/// Configuration options for <see cref="Pbkdf2PasswordHasher"/>.
/// </summary>
/// <remarks>
/// This type is designed to be bound from a configuration section
/// using the IOptions pattern:
///
/// services.Configure&lt;PasswordHashingOptions&gt;(
///     configuration.GetSection(PasswordHashingOptions.SectionName));
///
/// services.AddSingleton&lt;IPasswordHasher, Pbkdf2PasswordHasher&gt;();
///
/// The default of 600,000 iterations provides a work factor above
/// the OWASP recommendation of 220,000 iterations for PBKDF2-HMAC-SHA512.
/// Actual authentication latency must be benchmarked on the target hardware.
///
/// Existing hashes retain their original iteration count and can be
/// upgraded through IPasswordHasher.NeedsRehash.
/// </remarks>
public sealed class PasswordHashingOptions : IValidatableObject
{
    /// <summary>
    /// Default configuration section name.
    /// </summary>
    public const string SectionName = "PasswordHashing";

    /// <summary>
    /// Default number of PBKDF2 iterations.
    /// </summary>
    public const int DefaultIterations = 600_000;

    /// <summary>
    /// Minimum allowed iteration count.
    /// </summary>
    private const int MinAllowedIterations = 100_000;

    /// <summary>
    /// Maximum allowed iteration count.
    /// </summary>
    private const int MaxAllowedIterations = 10_000_000;

    /// <summary>
    /// Gets or sets the PBKDF2 iteration count.
    /// </summary>
    /// <value>
    /// Defaults to 600,000.
    /// Must be between 100,000 and 10,000,000 inclusive.
    /// </value>
    public int Iterations { get; set; } = DefaultIterations;

    /// <summary>
    /// Validates the configured options.
    /// </summary>
    /// <param name="validationContext">
    /// The validation context.
    /// </param>
    /// <returns>
    /// Validation results, or an empty collection if valid.
    /// </returns>
    public IEnumerable<ValidationResult> Validate(
        ValidationContext validationContext)
    {
        if (Iterations < MinAllowedIterations)
        {
            yield return new ValidationResult(
                $"{nameof(Iterations)} must be at least " +
                $"{MinAllowedIterations}, but was {Iterations}.",
                new[] { nameof(Iterations) });
        }
        else if (Iterations > MaxAllowedIterations)
        {
            yield return new ValidationResult(
                $"{nameof(Iterations)} must not exceed " +
                $"{MaxAllowedIterations}, but was {Iterations}.",
                new[] { nameof(Iterations) });
        }
    }

    /// <summary>
    /// Validates the options and throws a ValidationException
    /// when any constraint is violated.
    /// </summary>
    /// <exception cref="ValidationException">
    /// The configured options are invalid.
    /// </exception>
    public void ThrowIfInvalid()
    {
        Validator.ValidateObject(
            this,
            new ValidationContext(this),
            validateAllProperties: true);
    }
}
