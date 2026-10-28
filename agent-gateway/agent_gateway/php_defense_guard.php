<?php
/**
 * AgentGate PHP Defense Guard - Runtime Application Firewall & Sanitizer
 * Zero-dependency drop-in for PHP 7.4 through 8.5 (Laravel, WordPress, Vanilla).
 */

namespace AgentGate;

class PhpDefenseGuard {
    private array $blockedPatterns;
    private string $auditLogPath;

    public function __construct(string $auditLogPath = '') {
        $this->auditLogPath = $auditLogPath ?: sys_get_temp_dir() . '/agentgate_php_audit.jsonl';
        $this->blockedPatterns = [
            'SQLI_UNION' => '/\bUNION\b\s+\bSELECT\b/i',
            'SQLI_TAUTOLOGY' => '/\b(OR|AND)\b\s+([0-9]=([0-9]|[''"])|[''"][^''_]*[''"]\s*=\s*[''"][^''_]*[''"])/i',
            'PATH_TRAVERSAL' => '/(\.\.[\/\\\\]){2,}/',
            'PHP_DESERIALIZE' => '/\bO:[0-9]+:"[a-zA-Z0-9_\\\\]+":[0-9]+:{/',
            'RCE_EVAL' => '/\b(eval|system|passthru|shell_exec|exec|assert)\s*\(/i'
        ];
    }

    public function inspectAndEnforce(): void {
        $inputVector = array_merge($_GET, $_POST, $_COOKIE);
        $payload = json_encode($inputVector);

        foreach ($this->blockedPatterns as $ruleCode => $pattern) {
            if (preg_match($pattern, $payload)) {
                $this->logViolation($ruleCode, $payload);
                http_response_code(403);
                header('Content-Type: application/json');
                echo json_encode([
                    "error" => "AgentGate PHP Defense Blocked Request",
                    "rule_code" => $ruleCode,
                    "status" => 403
                ]);
                exit(1);
            }
        }
    }

    private function logViolation(string $ruleCode, string $payload): void {
        $entry = [
            'ts' => microtime(true),
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'rule_code' => $ruleCode,
            'client_ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            'hash' => hash('sha256', $payload)
        ];
        file_put_contents($this->auditLogPath, json_encode($entry) . "\n", FILE_APPEND | LOCK_EX);
    }
}
