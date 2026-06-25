// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if !NET5_0_OR_GREATER
namespace System.Runtime.Versioning;

/// <summary>
/// Polyfill of the platform-compatibility attribute for target frameworks (netstandard2.1)
/// that do not ship it. It carries no behaviour there; the platform-compatibility analyzer
/// runs only on the modern target frameworks where the real type is available.
/// </summary>
[AttributeUsage(
    AttributeTargets.Assembly
    | AttributeTargets.Class
    | AttributeTargets.Constructor
    | AttributeTargets.Enum
    | AttributeTargets.Event
    | AttributeTargets.Field
    | AttributeTargets.Method
    | AttributeTargets.Module
    | AttributeTargets.Property
    | AttributeTargets.Struct,
    AllowMultiple = true,
    Inherited = false)]
internal sealed class SupportedOSPlatformAttribute : Attribute
{
    public SupportedOSPlatformAttribute(string platformName)
    {
        PlatformName = platformName;
    }

    public string PlatformName { get; }
}
#endif
