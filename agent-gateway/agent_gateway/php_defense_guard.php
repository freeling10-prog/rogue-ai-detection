<?php
/**
 * AgentGate PHP Defense Guard - request input validation for PHP applications.
 * Zero-dependency drop-in for PHP 7.4 or later (Laravel, WordPress, Vanilla).
 *
 * Usage, as early as possible in the request (e.g. a Laravel middleware, a
 * WordPress mu-plugin, or the top of index.php):
 *
 *     require __DIR__ . '/php_defense_guard.php';
 *     (new \AgentGate\PhpDefenseGuard('/var/log/agentgate_php_audit.jsonl'))->inspectAndEnforce();
 *
 * Every key and string value in $_GET, $_POST and $_COOKIE, nested to any
 * depth, is checked as received and once more after rawurldecode(). The
 * first matching rule answers 403 with its rule code and appends a SHA-256
 * hash-chained entry (seq, prev_hash, entry_hash) to the audit log. The log
 * holds a SHA-256 of the offending value, never the value. Python's
 * agent_gateway.audit_chain.verify_chain_file checks the chain, and
 * agent_gateway/php_defense_guard.py applies the same RULES.
 *
 * These are lexical input checks. Keep parameterized queries,
 * unserialize(..., ['allowed_classes' => false]) and disable_functions.
 */

namespace AgentGate;

class PhpDefenseGuard {
    /** Rule code => PCRE pattern. Keep in step with RULES in php_defense_guard.py. */
    public const RULES = [
        'PHP_SQLI_UNION' => '~\bUNION(?:\s|/\*.*?\*/)+(?:ALL(?:\s|/\*.*?\*/)+|DISTINCT(?:\s|/\*.*?\*/)+)?SELECT\b~is',
        'PHP_SQLI_TAUTOLOGY' => '~\b(?:OR|AND)\s+(?:\d+\s*=\s*\d+|([\'"])[^\'"]*\1\s*=\s*[\'"])~is',
        'PHP_PATH_TRAVERSAL' => '~(?:\.\.[/\\\\]){2,}~is',
        'PHP_DESERIALIZE_DENIED' => '~\b[OC]:\d+:"[A-Za-z0-9_\\\\]+":\d+:\{~is',
        'PHP_RCE_EVAL' => '~\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|create_function)\s*\(~is',
    ];
    public const MAX_VALUE_CHARS = 65536;
    private const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    private string $auditLogPath;

    public function __construct(string $auditLogPath = '') {
        $this->auditLogPath = $auditLogPath !== '' ? $auditLogPath : sys_get_temp_dir() . '/agentgate_php_audit.jsonl';
    }

    /** Rule code for one input string, or null. */
    public static function matchValue(string $text): ?string {
        $text = substr($text, 0, self::MAX_VALUE_CHARS);
        $forms = [$text];
        $decoded = rawurldecode($text);
        if ($decoded !== $text) {
            $forms[] = $decoded;
        }
        foreach (self::RULES as $code => $pattern) {
            foreach ($forms as $form) {
                if (preg_match($pattern, $form) === 1) {
                    return $code;
                }
            }
        }
        return null;
    }

    /**
     * Check parameters (keys and string values, nested). Returns
     * ['rule_code' => ..., 'field' => ..., 'value_sha256' => ...] for the first match, or null.
     */
    public static function inspect(array $params, string $prefix = ''): ?array {
        foreach ($params as $key => $value) {
            $key = (string) $key;
            $field = $prefix === '' ? $key : $prefix . '[' . $key . ']';
            $code = self::matchValue($key);
            if ($code !== null) {
                return ['rule_code' => $code, 'field' => $field, 'value_sha256' => hash('sha256', $key)];
            }
            if (is_array($value)) {
                $hit = self::inspect($value, $field);
                if ($hit !== null) {
                    return $hit;
                }
            } elseif (is_string($value) || is_int($value) || is_float($value)) {
                $text = (string) $value;
                $code = self::matchValue($text);
                if ($code !== null) {
                    return ['rule_code' => $code, 'field' => $field, 'value_sha256' => hash('sha256', $text)];
                }
            }
        }
        return null;
    }

    /** Inspect $_GET, $_POST and $_COOKIE; answer 403 and stop on the first match. */
    public function inspectAndEnforce(): void {
        foreach ([$_GET, $_POST, $_COOKIE] as $section) {
            $hit = self::inspect(is_array($section) ? $section : []);
            if ($hit !== null) {
                $this->logViolation($hit);
                if (!headers_sent()) {
                    http_response_code(403);
                    header('Content-Type: application/json');
                }
                echo json_encode([
                    'error' => 'AgentGate PHP Defense Blocked Request',
                    'rule_code' => $hit['rule_code'],
                    'status' => 403,
                ]);
                exit(1);
            }
        }
    }

    /** Canonical JSON, byte-identical to agent_gateway.audit_chain.canonical for these fields. */
    private static function canonical(array $entry): string {
        ksort($entry);
        return json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }

    /** Append one hash-chained entry. Public so the chain can be exercised without a web request. */
    public function logViolation(array $hit): array {
        $fh = fopen($this->auditLogPath, 'c+');
        if ($fh === false) {
            return [];
        }
        flock($fh, LOCK_EX);
        $seq = 0;
        $prev = self::GENESIS;
        $size = fstat($fh)['size'];
        if ($size > 0) {
            $start = max(0, $size - 8192);
            fseek($fh, $start);
            $lines = array_values(array_filter(explode("\n", stream_get_contents($fh)), 'strlen'));
            $last = $lines ? json_decode(end($lines), true) : null;
            if (is_array($last) && isset($last['seq'], $last['entry_hash'])) {
                $seq = (int) $last['seq'] + 1;
                $prev = (string) $last['entry_hash'];
            }
        }
        $entry = [
            'ts' => round(microtime(true), 6),
            'kind' => 'php_defense',
            'uri' => (string) ($_SERVER['REQUEST_URI'] ?? ''),
            'method' => (string) ($_SERVER['REQUEST_METHOD'] ?? ''),
            'client_ip' => (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
            'verdict' => 'DENY',
            'rule_code' => $hit['rule_code'],
            'field' => $hit['field'],
            'value_sha256' => $hit['value_sha256'],
            'seq' => $seq,
            'prev_hash' => $prev,
        ];
        $entry['entry_hash'] = hash('sha256', self::canonical($entry));
        fseek($fh, 0, SEEK_END);
        fwrite($fh, json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION) . "\n");
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);
        return $entry;
    }
}
