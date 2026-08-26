<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

/**
 * The OASIS WS-Security EncodingType URIs that name how a token body is encoded. Base64Binary is the only
 * encoding the engine emits or accepts; a single source of truth removes the risk of a copy diverging into
 * a silent interop break.
 */
enum WsSecurityEncodingType: string
{
    case Base64Binary = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
}
