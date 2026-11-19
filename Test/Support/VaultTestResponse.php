<?php

use Kanboard\Core\Http\Response;

// Captures what a controller sends instead of emitting headers.
class VaultTestResponse extends Response
{
    public array $headers = [];
    public int $status = 200;
    public string $body = '';
    public bool $sent = false;

    public function withHeader($header, $value)
    {
        $this->headers[$header] = $value;
        return parent::withHeader($header, $value);
    }

    public function withStatusCode($statusCode)
    {
        $this->status = (int) $statusCode;
        return parent::withStatusCode($statusCode);
    }

    public function withBody($body)
    {
        $this->body = (string) $body;
        return parent::withBody($body);
    }

    public function send()
    {
        $this->sent = true;
    }

    public function json_(): array
    {
        return json_decode($this->body, true) ?? [];
    }
}
