<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Wsa;

use Dom\Element;
use Dom\Node;
use Soap\Xml\Builder\SoapHeaders;
use Soap\Xml\Locator\SoapHeaderLocator;
use Soap\Xml\Manipulator\PrependSoapHeaders;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Assert\assert_element;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;
use function VeeWee\Xml\Dom\Builder\xmlns_attribute;

/**
 * The WS-Addressing header of an outgoing request: the Action/To/MessageID/ReplyTo (and optional
 * From/RelatesTo) properties that tell the service which operation is invoked and where to send the reply.
 * Immutable: each `with*` returns a new value, and `appendTo()` writes the configured properties into the
 * envelope's SOAP Header (adding the header when the request has none).
 */
final class WsaHeader
{
    private ?string $action = null;
    private ?string $to = null;
    private ?string $from = null;
    private ?MessageId $messageId = null;
    private ?string $replyTo = null;
    private ?string $relatesTo = null;

    private function __construct(
        private readonly WsaNamespace $namespace,
    ) {
    }

    public static function create(WsaNamespace $namespace = WsaNamespace::W3c200508): self
    {
        return new self($namespace);
    }

    public function withAction(string $action): self
    {
        $clone = clone $this;
        $clone->action = $action;

        return $clone;
    }

    public function withTo(string $to): self
    {
        $clone = clone $this;
        $clone->to = $to;

        return $clone;
    }

    public function withFrom(string $address): self
    {
        $clone = clone $this;
        $clone->from = $address;

        return $clone;
    }

    public function withMessageId(MessageId $messageId): self
    {
        $clone = clone $this;
        $clone->messageId = $messageId;

        return $clone;
    }

    public function withReplyTo(string $address): self
    {
        $clone = clone $this;
        $clone->replyTo = $address;

        return $clone;
    }

    public function withRelatesTo(string $messageId): self
    {
        $clone = clone $this;
        $clone->relatesTo = $messageId;

        return $clone;
    }

    public function appendTo(Document $document): void
    {
        $header = $document->locate(new SoapHeaderLocator());
        if ($header === null) {
            $header = assert_element($document->build(new SoapHeaders())[0] ?? null);
            $document->manipulate(new PrependSoapHeaders($header));
        }

        // Declare xmlns:wsa once on the header so the elements below reuse it instead of redeclaring per node.
        xmlns_attribute($this->namespace->prefix(), $this->namespace->value)($header);
        children(...$this->buildElements())($header);
    }

    /**
     * @return list<callable(Node): Element>
     */
    private function buildElements(): array
    {
        $ns = $this->namespace->value;
        $prefix = $this->namespace->prefix();

        $elements = [];
        if ($this->action !== null) {
            $elements[] = namespaced_element($ns, $prefix.':Action', value($this->action));
        }
        if ($this->to !== null) {
            $elements[] = namespaced_element($ns, $prefix.':To', value($this->to));
        }
        if ($this->from !== null) {
            $elements[] = namespaced_element($ns, $prefix.':From', children(
                namespaced_element($ns, $prefix.':Address', value($this->from)),
            ));
        }
        if ($this->messageId !== null) {
            $elements[] = namespaced_element($ns, $prefix.':MessageID', value($this->messageId->value()));
        }
        if ($this->replyTo !== null) {
            $elements[] = namespaced_element($ns, $prefix.':ReplyTo', children(
                namespaced_element($ns, $prefix.':Address', value($this->replyTo)),
            ));
        }
        if ($this->relatesTo !== null) {
            $elements[] = namespaced_element($ns, $prefix.':RelatesTo', value($this->relatesTo));
        }

        return $elements;
    }
}
