<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ReportedFault;
use Throwable;

/**
 * What the peer said about a response that then failed its inbound checks. Never thrown on its own: it is
 * chained inside the uniform SecurityFault, between that fault and the cause it already carried.
 *
 * This exists for one path only. A fault reply whose inbound checks pass is handed on to the encoder, whose
 * SoapFaultGuard raises a SoapFaultException carrying the fault in full. A reply whose checks fail never gets
 * that far, because this middleware throws first, and the server's stated reason would otherwise be lost.
 *
 * The inbound path deliberately tells a caller nothing about why it refused a message, which leaves an
 * operator holding a refusal and no idea that the server had answered "invalid credentials" all along. This
 * type closes that gap without opening the other one. It sits in the exception chain, which is where this
 * package already delivers causes destined for a log, so a SecurityFault's own message is unchanged and an
 * application cannot branch on the peer's text: reaching it means walking past the fault the caller was given.
 *
 * The presence of this link tells a reader only that the response was fault-shaped, which the peer that wrote
 * it obviously knows already, and nothing about which check failed or what any key did.
 */
final class PeerReportedFault extends RuntimeException
{
    public static function describing(ReportedFault $fault, ?Throwable $previous = null): self
    {
        return new self(
            // Worded exactly as php-soap/encoding's SoapFaultException words it, so one log search finds a
            // reported fault whichever layer got to report it. Which layer that was is the class name's job.
            sprintf('SOAP Fault: %s (Code: %s)', $fault->reason, $fault->code),
            0,
            $previous,
        );
    }
}
