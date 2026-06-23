using System;

namespace Dtls;

/// <summary>
/// The base exception type for all DTLS protocol and configuration errors raised by this
/// library.
/// </summary>
public class DtlsException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="DtlsException"/> class.</summary>
    public DtlsException()
    {
    }

    /// <summary>Initializes a new instance with a message.</summary>
    /// <param name="message">A description of the error.</param>
    public DtlsException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    /// <param name="message">A description of the error.</param>
    /// <param name="innerException">The underlying cause.</param>
    public DtlsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The exception raised when a DTLS connection is terminated by an alert, either sent or
/// received.
/// </summary>
public sealed class DtlsAlertException : DtlsException
{
    /// <summary>Initializes a new instance with the alert and whether it was fatal.</summary>
    /// <param name="alert">The alert description.</param>
    /// <param name="fatal">Whether the alert is fatal (terminates the connection).</param>
    /// <param name="message">A description of the error.</param>
    public DtlsAlertException(DtlsAlert alert, bool fatal, string message)
        : base(message)
    {
        Alert = alert;
        IsFatal = fatal;
    }

    /// <summary>Initializes a new instance with a generic internal-error alert.</summary>
    public DtlsAlertException()
        : this(DtlsAlert.InternalError, true, "A DTLS alert occurred.")
    {
    }

    /// <summary>Initializes a new instance with a message and internal-error alert.</summary>
    /// <param name="message">A description of the error.</param>
    public DtlsAlertException(string message)
        : this(DtlsAlert.InternalError, true, message)
    {
    }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    /// <param name="message">A description of the error.</param>
    /// <param name="innerException">The underlying cause.</param>
    public DtlsAlertException(string message, Exception innerException)
        : base(message, innerException)
    {
        Alert = DtlsAlert.InternalError;
        IsFatal = true;
    }

    /// <summary>The alert description associated with this error.</summary>
    public DtlsAlert Alert { get; }

    /// <summary>Whether the alert is fatal and terminates the connection.</summary>
    public bool IsFatal { get; }
}
