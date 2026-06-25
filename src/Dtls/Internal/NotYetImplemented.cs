// Copyright (c) marcschier. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System;

namespace Dtls.Internal;

/// <summary>
/// Produces consistent "under construction" exceptions for the parts of the hybrid stack
/// (the managed DTLS 1.3 engine and the native DTLS 1.0/1.2 backends) that are still being
/// implemented. Centralizing this keeps the messages uniform and easy to find.
/// </summary>
internal static class NotYetImplemented
{
    public static NotImplementedException Feature(string what)
    {
        return new NotImplementedException(
            what + " is under construction. See docs/architecture.md and the "
            + "implementation plan (phases 2-3).");
    }
}
