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
