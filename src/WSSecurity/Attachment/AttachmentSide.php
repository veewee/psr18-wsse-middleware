<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

/**
 * Which of the storage's two collections an AttachmentParts adapter speaks for. The storage keeps the
 * request and the response apart, and so must the adapter: an outbound block must never reach the parts
 * that arrived with a response.
 */
enum AttachmentSide
{
    case Request;
    case Response;
}
