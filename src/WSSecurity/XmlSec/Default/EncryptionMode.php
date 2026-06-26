<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

/**
 * Drives the serialization and DOM-replacement strategy on both the encrypt and decrypt sides. Element: the
 * whole target element is replaced by (or recovered from) the xenc:EncryptedData. Content: only the target
 * element's children are replaced; the element itself survives.
 */
enum EncryptionMode: string
{
    case Element = 'http://www.w3.org/2001/04/xmlenc#Element';
    case Content = 'http://www.w3.org/2001/04/xmlenc#Content';
}
