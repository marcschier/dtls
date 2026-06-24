#if NET8_0_OR_GREATER
using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Dtls.Interop.Network;

/// <summary>
/// Minimal Objective-C block ABI shim used to hand C# callbacks to Network.framework. Each block
/// is created as a <em>global</em> block (<c>isa = _NSConcreteGlobalBlock</c>,
/// <c>flags = BLOCK_IS_GLOBAL</c>): the Block runtime treats global blocks as immortal, so
/// <c>_Block_copy</c>/<c>_Block_release</c> are no-ops and Network.framework never copies or frees
/// them. That gives the managed side full, deterministic control of each block's lifetime (freed
/// on connection disposal). A captured context pointer (a <see cref="GCHandle"/> to the owning
/// connection) is appended to the literal; the <c>UnmanagedCallersOnly</c> invoke trampoline
/// recovers it via <see cref="GetContext"/>.
/// </summary>
[SupportedOSPlatform("macos")]
internal static unsafe class NwBlock
{
    private const int BlockIsGlobal = 1 << 28;

    [StructLayout(LayoutKind.Sequential)]
    private struct BlockLiteral
    {
        public IntPtr Isa;
        public int Flags;
        public int Reserved;
        public IntPtr Invoke;
        public IntPtr Descriptor;
        public IntPtr Context;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BlockDescriptor
    {
        public UIntPtr Reserved;
        public UIntPtr Size;
    }

    private static readonly object DescriptorLock = new();
    private static IntPtr _descriptor;

    /// <summary>
    /// Allocates a global block whose <c>invoke</c> is <paramref name="invoke"/> and which carries
    /// <paramref name="context"/> as its single captured value. The block is a global (immortal)
    /// block, so Network.framework never copies or frees it; the literal is intentionally leaked
    /// (Network.framework reads its flags during its own post-terminal release).
    /// </summary>
    /// <param name="invoke">
    /// An <c>UnmanagedCallersOnly</c> function pointer whose first parameter is the block pointer.
    /// </param>
    /// <param name="context">The captured context (typically <c>GCHandle.ToIntPtr</c>).</param>
    public static IntPtr Create(IntPtr invoke, IntPtr context)
    {
        IntPtr block = Marshal.AllocHGlobal(sizeof(BlockLiteral));
        BlockLiteral* literal = (BlockLiteral*)block;
        literal->Isa = NetworkInterop.NSConcreteGlobalBlock;
        literal->Flags = BlockIsGlobal;
        literal->Reserved = 0;
        literal->Invoke = invoke;
        literal->Descriptor = SharedDescriptor();
        literal->Context = context;
        return block;
    }

    /// <summary>
    /// Recovers the captured context from a block created by <see cref="Create"/>.
    /// </summary>
    public static IntPtr GetContext(IntPtr block) => ((BlockLiteral*)block)->Context;

    /// <summary>
    /// Invokes a foreign block of shape <c>void (^)(bool)</c> (for example the verify-completion
    /// block handed to a <c>sec_protocol_options</c> verify block).
    /// </summary>
    public static void InvokeBoolBlock(IntPtr block, bool value)
    {
        BlockLiteral* literal = (BlockLiteral*)block;
        ((delegate* unmanaged[Cdecl]<IntPtr, byte, void>)literal->Invoke)(
            block, value ? (byte)1 : (byte)0);
    }

    private static IntPtr SharedDescriptor()
    {
        if (_descriptor != IntPtr.Zero)
        {
            return _descriptor;
        }

        lock (DescriptorLock)
        {
            if (_descriptor == IntPtr.Zero)
            {
                IntPtr descriptor = Marshal.AllocHGlobal(sizeof(BlockDescriptor));
                BlockDescriptor* d = (BlockDescriptor*)descriptor;
                d->Reserved = UIntPtr.Zero;
                d->Size = (UIntPtr)sizeof(BlockLiteral);
                _descriptor = descriptor;
            }

            return _descriptor;
        }
    }
}
#endif
