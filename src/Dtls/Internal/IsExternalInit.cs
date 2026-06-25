// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

#if !NET5_0_OR_GREATER
namespace System.Runtime.CompilerServices;

/// <summary>
/// Polyfill enabling <c>init</c>-only setters on target frameworks (netstandard2.1) that
/// do not ship this type. Recognized by the C# compiler by name only.
/// </summary>
internal static class IsExternalInit
{
}
#endif
