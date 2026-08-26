<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use InvalidArgumentException;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\CustomKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncryptedKeySha1KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityEncodingType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;

/**
 * A secret both sides already hold, named by an identifier they agreed on out of band. Nothing is written to
 * the message: there is no key to convey, only a reference saying which of the agreed keys this message used.
 *
 * Unlike a wrapped session key, this authenticates, and mutually: only the two holders of the secret can
 * produce a MAC that verifies under it. It is not non-repudiable, because either of them could have produced any
 * given message.
 *
 * The identifier is stated once and both used and emitted from that one value. Stating the reference and the
 * name separately would be the same fact written twice, with two places for it to drift and a signature no peer
 * could resolve when it did. A deployment whose peer references a pre-shared key in some other shape can still
 * emit that shape through the signing block's own key-identifier override.
 *
 * Which value type to agree on depends on the peer. A WSS4J or CXF one wants the WSS 1.1 EncryptedKeySHA1 URI,
 * because that is the only custom identifier its emitter writes for a shared secret, even though nothing here
 * is a digest of any cipher bytes: the URI names the shape of the reference rather than how the value was
 * arrived at. Its reader is the tolerant half and takes any type at all.
 */
final class PreSharedSessionKey implements SymmetricKeySource
{
    private readonly SymmetricKey $key;

    /**
     * @param non-empty-string $identifier   the name both sides agreed on, carried verbatim as the
     *        wsse:KeyIdentifier content and matched verbatim against what an inbound reference names
     * @param non-empty-string $valueType    the ValueType URI the agreed reference declares
     * @param non-empty-string $encodingType the encoding the identifier is written in, base64 by default,
     *        which is what a peer expects unless it says otherwise
     *
     * @throws InvalidArgumentException when the secret is empty, or the identifier does not match the encoding
     *         it is written under
     */
    public function __construct(
        #[SensitiveParameter] SessionKey $secret,
        string $identifier,
        string $valueType,
        string $encodingType = WsSecurityEncodingType::Base64Binary->value,
    ) {
        if ($secret->bytes() === '') {
            // An empty secret keys a MAC anyone can reproduce, which authenticates nobody.
            throw new InvalidArgumentException('A pre-shared secret must not be empty.');
        }

        // The identifier is written verbatim under the encoding the reference declares, so the two have to
        // agree. A plain name under a base64 encoding type is a reference that says one thing and carries
        // another, which a strict receiver refuses and a lenient one resolves to something else.
        if ($encodingType === WsSecurityEncodingType::Base64Binary->value
            && base64_encode((string) base64_decode($identifier, true)) !== $identifier
        ) {
            throw new InvalidArgumentException(sprintf(
                'The key identifier "%s" is not base64, which is the encoding this reference declares. '
                .'Encode it, or name the encoding your peer agreed on.',
                $identifier,
            ));
        }

        // A reference declaring the WSS 1.1 session-key type has to carry the matching wsse11:TokenType, which
        // is what the identifier built for that type emits and what a receiver enforcing the Basic Security
        // Profile refuses a reference for lacking. Every other agreed type is written as it stands, since the
        // profile names none of them.
        $reference = $valueType === WsSecurityValueType::EncryptedKeySha1->value
            ? new EncryptedKeySha1KeyIdentifier($identifier)
            : new CustomKeyIdentifier($identifier, $valueType, $encodingType);

        // The key is a value here rather than per-exchange state, which is the one place this source differs
        // from the others: it holds no key it minted, only the one the deployment configured.
        $this->key = new SymmetricKey($secret, $reference, [$identifier]);
    }

    public function resolve(WsseContext $context, KeyRequest $for): SymmetricKey
    {
        // Established rather than materialized: nothing is minted, and registering the same secret twice under
        // the same identifier is a no-op, which is what lets every block in both directions hold this source.
        $context->keys()->establish($this->key->bytes, ...$this->key->wireIdentifiers);

        $for->enforce(
            $this->key,
            'The pre-shared secret',
            'Fix the block\'s algorithm or agree on a secret of that width.',
        );

        return $this->key;
    }
}
