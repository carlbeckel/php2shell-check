<?php
/**
 * php2shell_check.php
 * Read-only exposure check for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
 *
 * Report sections, in order:
 *   1. PHP version: patched / update available / no patch available
 *   2. Server API (SAPI) in use and its risk level per the PHP advisory
 *   3. Relevant settings: current value -> recommended value
 *   4. Mitigations this script cannot detect (check these by hand)
 *
 * USAGE
 *   Web (recommended: checks the configuration your web workers actually use)
 *     1. Add your IP address to $CONFIG['allowed_ips'] below.
 *     2. Upload into the docroot of each site / FPM pool you want to check, then open it.
 *          ?format=text   plain-text output
 *     3. DELETE THE FILE when finished. It discloses server configuration.
 *   CLI
 *     php php2shell_check.php
 *     Exit codes without logging: 0 = patched, 1 = vulnerable, 2 = cannot confirm
 *     Exit codes with logging:    0 = report written, 3 = not written (busy or write failed)
 *     The CLI often loads a different php.ini than the web server, so CLI results
 *     describe the CLI only.
 *   OUTPUT MODES (decided only by $CONFIG['log_file']; no URL or CLI parameter changes it)
 *     log_file empty : the full report is shown on screen.
 *     log_file set   : the report goes ONLY to the log file. The screen shows a timestamp
 *                      and a confirmation, never the result or the log location.
 *     Each write REPLACES the previous report, so the file never grows beyond one report.
 *     Web writes are throttled; the CLI is not (it already requires shell access).
 *
 * SAFETY
 *   Changes nothing. The only runtime action is ini_set('memory_limit', <current value>)
 *   to test whether applications can override memory_limit. It sets the value it
 *   already has and affects this request only.
 *
 * LIMITATIONS
 *   The version check trusts PHP_VERSION from the running binary. It cannot detect
 *   custom or modified builds whose version string does not match their source.
 *
 * SOURCES (as of 2026-10-21)
 *   PHP advisory : https://www.php.net/archive/2026.php#2026-10-21-5
 *   Cloudflare   : https://blog.cloudflare.com/php-vulnerabilities-waf-protection/
 *   Checks marked "(Inferred)" are not in the advisory.
 *
 * Uses only PHP 5.3-era syntax so it can run on the old versions it reports on.
 */

// Capture any diagnostic raised before this script started (best-effort).
$p2sStartupError = error_get_last();

// ------------------------------------------------------------------ configuration
$CONFIG = array(
    // Client IPs allowed to view the report over the web. Add your own.
    // Behind a reverse proxy or CDN, PHP sees the proxy's address instead.
    'allowed_ips' => array('127.0.0.1', '::1', '::ffff:127.0.0.1'),

    // Absolute path for the log file. Keep it OUTSIDE the docroot.
    // Set   : every run writes the report here; the screen shows only a confirmation.
    // Empty : the report is shown on screen and nothing is written to disk.
    'log_file' => '',

    // Minimum seconds between web log writes. Requests inside this window get
    // HTTP 429 and write nothing. The CLI is not throttled.
    'log_min_interval' => 60,
);
// --------------------------------------------------------------------------------

define('P2S_ADVISORY', 'https://www.php.net/archive/2026.php#2026-10-21-5');
define('P2S_DELETE_HEAD', 'DELETE THIS SCRIPT WHEN YOU ARE DONE. DO NOT LEAVE IT ON A PRODUCTION SYSTEM.');
define('P2S_DELETE_BODY', 'It discloses PHP version, file paths and server configuration to anyone who can reach it.');

/** Fixed release per supported branch, from the PHP advisory. */
function p2s_fixed_versions()
{
    return array('8.5' => '8.5.12', '8.4' => '8.4.27', '8.3' => '8.3.36', '8.2' => '8.2.35');
}

function p2s_h($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

function p2s_read($path)
{
    if (!@is_readable($path)) {
        return false;
    }
    $c = @file_get_contents($path);
    return ($c === false) ? false : $c;
}

/** Converts php.ini shorthand (128M, 1G) to bytes. Returns -1 for unlimited, null if unset. */
function p2s_to_bytes($v)
{
    $v = trim((string) $v);
    if ($v === '') {
        return null;
    }
    if ($v === '-1') {
        return -1;
    }
    $n = (float) $v;
    switch (strtolower(substr($v, -1))) {
        case 'g':
            $n *= 1024; // fall through
        case 'm':
            $n *= 1024; // fall through
        case 'k':
            $n *= 1024;
    }
    return (int) $n;
}

function p2s_is_on($v)
{
    return in_array(strtolower(trim((string) $v)), array('1', 'on', 'yes', 'true'), true);
}

function p2s_onoff($v)
{
    return p2s_is_on($v) ? 'On (1)' : 'Off (0)';
}

function p2s_row($name, $cve, $current, $recommended, $status, $why)
{
    return array(
        'name' => $name, 'cve' => $cve, 'current' => $current,
        'recommended' => $recommended, 'status' => $status, 'why' => $why,
    );
}

/**
 * Explains when an effective ini value differs from the php.ini master value.
 * Matters because the advisory says ini_set() and .user.ini do not count.
 */
function p2s_override_note($name)
{
    static $all = null;
    if ($all === null) {
        $all = @ini_get_all(null, true);
        if (!is_array($all)) {
            $all = array();
        }
    }
    if (!isset($all[$name])) {
        return '';
    }
    $g = (string) $all[$name]['global_value'];
    $l = (string) $all[$name]['local_value'];
    if ($g === $l) {
        return '';
    }
    return ' Note: the effective value differs from the php.ini master value ("' . $g . '"), so it is'
        . ' set per pool, per directory or at runtime. That is fine from an FPM pool or Apache config;'
        . ' it does not count if it comes from .user.ini or ini_set().';
}

/** true = apps can change it via ini_set(); false = locked (php_admin_value); null = cannot test. */
function p2s_can_override($name)
{
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    if (!function_exists('ini_set') || in_array('ini_set', $disabled, true)) {
        return null;
    }
    $cur = ini_get($name);
    if ($cur === false) {
        return null;
    }
    // Sets the value it already has: no effective change, this request only.
    return @ini_set($name, $cur) !== false;
}

/** Soft RLIMIT_AS / RLIMIT_DATA from /proc/self/limits (Linux). Null if unreadable. */
function p2s_rlimits()
{
    if (stripos(PHP_OS, 'linux') !== 0) {
        return null;
    }
    $txt = p2s_read('/proc/self/limits');
    if ($txt === false) {
        return null;
    }
    $out = array();
    foreach (explode("\n", $txt) as $line) {
        if (preg_match('/^Max (address space|data size)\s+(\S+)/', $line, $m)) {
            $out[$m[1] === 'address space' ? 'RLIMIT_AS' : 'RLIMIT_DATA'] = $m[2];
        }
    }
    return $out ? $out : null;
}

/** Best-effort cgroup memory limit for this process, walking up to parent cgroups. */
function p2s_cgroup_memory()
{
    $cg = p2s_read('/proc/self/cgroup');
    if ($cg === false) {
        return array('state' => 'unreadable');
    }
    $v1 = null;
    $v2 = null;
    foreach (explode("\n", trim($cg)) as $line) {
        $p = explode(':', $line, 3);
        if (count($p) !== 3) {
            continue;
        }
        if ($p[0] === '0' && $p[1] === '') {
            $v2 = $p[2];
        } elseif (in_array('memory', explode(',', $p[1]), true)) {
            $v1 = $p[2];
        }
    }
    if ($v1 !== null) {
        $base = '/sys/fs/cgroup/memory';
        $file = 'memory.limit_in_bytes';
        $path = $v1;
    } elseif ($v2 !== null) {
        $base = '/sys/fs/cgroup';
        $file = 'memory.max';
        $path = $v2;
    } else {
        return array('state' => 'unreadable');
    }

    $readAny = false;
    $path = rtrim($path, '/');
    while (true) {
        $f = $base . $path . '/' . $file;
        $v = p2s_read($f);
        if ($v !== false) {
            $readAny = true;
            $v = trim($v);
            // cgroup v2 uses "max"; v1 uses a huge number for "no limit".
            if ($v !== '' && $v !== 'max' && (float) $v < 1.0e18) {
                return array('state' => 'limited', 'bytes' => (float) $v, 'file' => $f);
            }
        }
        if ($path === '') {
            break;
        }
        $path = dirname($path);
        if ($path === '/' || $path === '.' || $path === '\\') {
            $path = '';
        }
    }
    return array('state' => $readAny ? 'unlimited' : 'unreadable');
}

// ======================================================================== checks

/**
 * Version verdict. Parameters default to the running PHP so the logic can be tested.
 * Returns array(code => PATCHED|VULNERABLE|UNKNOWN, headline, details[]).
 */
function p2s_version_status($major = null, $minor = null, $release = null, $extra = null)
{
    $major = ($major === null) ? PHP_MAJOR_VERSION : $major;
    $minor = ($minor === null) ? PHP_MINOR_VERSION : $minor;
    $release = ($release === null) ? PHP_RELEASE_VERSION : $release;
    $extra = ($extra === null) ? PHP_EXTRA_VERSION : $extra;

    $num = $major . '.' . $minor . '.' . $release;
    $full = $num . $extra;
    $branch = $major . '.' . $minor;
    $isPre = (bool) preg_match('/alpha|beta|rc|dev/i', $extra);
    // Vendor note: shown on VULNERABLE results only. Distributions backport fixes onto
    // OLDER version numbers (e.g. 8.3.6-0ubuntu0.24.04.x), so a build that compares as
    // vulnerable may already be fixed: a possible false alarm. It is deliberately not
    // shown on PATCHED results: PHP_VERSION comes from the upstream source the binary was
    // built from, and that source already contains the fixes, so a suffix there adds no
    // doubt. Showing it on every patched distro build would train operators to ignore it.
    $hasVendor = ($extra !== '' && !$isPre);
    $fixed = p2s_fixed_versions();
    $targets = 'Supported fixed releases: 8.5.12+, 8.4.27+, 8.3.36+, or 8.2.35+ (8.2 is end-of-life on 31 December 2026).';
    $vendorNote = 'Your build has a vendor suffix ("' . $extra . '"). Distributions often backport security'
        . ' fixes without changing the upstream version number, so check your vendor\'s advisory for'
        . ' CVE-2026-109618 and CVE-2026-109619 before acting on this result.';
    $eolNote = 'PHP 8.2 reaches end of life on 31 December 2026. Plan an upgrade to 8.3 or later.';
    $d = array();

    // Supported branches with an official fixed release
    if (isset($fixed[$branch])) {
        $fix = $fixed[$branch];
        $cmp = version_compare($num, $fix);
        if ($cmp > 0 || ($cmp === 0 && !$isPre)) {
            $d[] = "PHP $branch is fixed in $fix and later.";
            if ($branch === '8.2') {
                $d[] = $eolNote;
            }
            return array('code' => 'PATCHED',
                'headline' => "Vulnerability is patched. PHP $full includes the PHP2Shell fixes.",
                'details' => $d);
        }
        if ($cmp === 0) {
            $d[] = 'Pre-release builds are not covered by the advisory and should not run in production.';
            return array('code' => 'UNKNOWN',
                'headline' => "Cannot confirm. PHP $full is a pre-release of the fixed version $fix.",
                'details' => $d);
        }
        if ($hasVendor) {
            $d[] = $vendorNote;
        }
        if ($branch === '8.2') {
            $d[] = $eolNote;
        }
        return array('code' => 'VULNERABLE',
            'headline' => "You are vulnerable. Update PHP $branch to $fix or later.",
            'details' => $d);
    }

    // Newer than any branch named in the advisory (8.6 was in RC testing at disclosure)
    if ($major > 8 || ($major == 8 && $minor >= 6)) {
        $d[] = 'The advisory lists fixed releases for 8.2 to 8.5 only. PHP 8.6 was still in release-candidate testing when the fixes shipped.';
        $d[] = 'Check the NEWS / release notes for this exact build for CVE-2026-109618 and CVE-2026-109619. Do not run pre-releases in production.';
        return array('code' => 'UNKNOWN',
            'headline' => "Cannot confirm. PHP $full is not covered by the advisory.",
            'details' => $d);
    }

    // End-of-life branches that received source-only backports
    if (($major == 7 && $minor == 4) || ($major == 8 && $minor <= 1)) {
        if ($hasVendor) {
            $d[] = $vendorNote;
        }
        $d[] = 'Option A: install a backported package from your distribution or LTS vendor.';
        $d[] = 'Option B: build from the PHP security team\'s minimal source backport: https://github.com/php/php-src/tree/PHP-' . $branch . '-CVE-2026-109618-109619';
        $d[] = 'Option C (preferred): upgrade to a supported branch. ' . $targets;
        return array('code' => 'VULNERABLE',
            'headline' => "You are vulnerable. PHP $branch is end-of-life and has no official patched release (a source backport exists).",
            'details' => $d);
    }

    // 5.4 to 7.3: believed affected, no patch at all
    if (($major == 5 && $minor >= 4) || ($major == 7 && $minor <= 3)) {
        if ($hasVendor) {
            $d[] = $vendorNote;
        }
        $d[] = 'Researchers believe PHP 5.4 and later are affected (not every release was individually tested). No patch exists for this branch.';
        $d[] = 'Upgrade to a supported branch. ' . $targets;
        return array('code' => 'VULNERABLE',
            'headline' => "You are vulnerable. Your version (PHP $branch) does not have a patch.",
            'details' => $d);
    }

    // Older than the reported affected range
    $d[] = 'This version is below the range reported as affected (5.4+), but it has been end-of-life for over a decade and has many other unpatched vulnerabilities.';
    $d[] = 'Upgrade to a supported branch. ' . $targets;
    return array('code' => 'UNKNOWN',
        'headline' => "Not in the reported affected range, but PHP $full is unsupported. Upgrade.",
        'details' => $d);
}

function p2s_sapi_info()
{
    $sapi = php_sapi_name();
    $map = array(
        'apache2handler' => array('Apache mod_php', 'HIGHEST',
            'The advisory rates mod_php highest risk: a demonstrated exploit works with one unauthenticated request, before any application code runs.'),
        'apache' => array('Apache mod_php', 'HIGHEST',
            'The advisory rates mod_php highest risk: a demonstrated exploit works with one unauthenticated request, before any application code runs.'),
        'fpm-fcgi' => array('PHP-FPM', 'AFFECTED',
            'Exploitation was validated against FPM, but the confirmed route needs a suitable operation in the application. More workers lower the per-request success rate but do not remove the vulnerability.'),
        'cgi-fcgi' => array('php-cgi (FastCGI)', 'AFFECTED', 'Listed as at risk in the advisory.'),
        'cgi' => array('php-cgi', 'AFFECTED', 'Listed as at risk in the advisory.'),
        'litespeed' => array('LiteSpeed (LSAPI)', 'AFFECTED', 'Listed as at risk in the advisory.'),
        'frankenphp' => array('FrankenPHP', 'AFFECTED', 'Listed as at risk in the advisory.'),
        'cli' => array('Command line', 'NOT A WEB SAPI',
            'This run shows the CLI configuration, not your web workers. Run the script through the web server to check the settings that matter.'),
        'cli-server' => array('PHP built-in web server', 'NOT LISTED',
            'Not named in the advisory. It is not meant for production; treat it as affected if it serves untrusted traffic.'),
    );
    if (isset($map[$sapi])) {
        return array('sapi' => $sapi, 'label' => $map[$sapi][0], 'risk' => $map[$sapi][1], 'note' => $map[$sapi][2]);
    }
    return array('sapi' => $sapi, 'label' => 'Other', 'risk' => 'ASSUME AFFECTED',
        'note' => 'Not named in the advisory. The advisory covers all PHP installations serving web requests.');
}

function p2s_settings_checks($startupError)
{
    $rows = array();
    $sapi = php_sapi_name();
    $A = 'CVE-2026-109618';
    $B = 'CVE-2026-109619';
    p2s_override_note('memory_limit'); // snapshot ini values before the ini_set() test

    // ---- CVE-2026-109618: out-of-memory corruption ---------------------------------
    $ml = (string) ini_get('memory_limit');
    $mlBytes = p2s_to_bytes($ml);
    $over = p2s_can_override('memory_limit');
    $mlNote = p2s_override_note('memory_limit');
    if ($mlBytes === -1) {
        if ($over === true) {
            $rows[] = p2s_row('memory_limit', $A, $ml, '-1, set with php_admin_value (FPM pool or Apache config)', 'REVIEW',
                'Unlimited, but applications can change it with ini_set(), which would bring back a finite limit.' . $mlNote);
        } else {
            $why = ($over === false)
                ? 'Unlimited and locked against ini_set() overrides.'
                : 'Unlimited. ini_set() is disabled, so PHP code cannot override it.';
            $rows[] = p2s_row('memory_limit', $A, $ml, '-1 (no change)', 'OK',
                $why . ' Also check that no pool, directory or application setting puts a finite limit back, and keep a container/cgroup memory limit in place.' . $mlNote);
        }
    } else {
        $rows[] = p2s_row('memory_limit', $A, $ml, '-1, set with php_admin_value (FPM pool or Apache config) so applications cannot override it', 'CHANGE',
            'A finite limit leaves the controllable out-of-memory path open. Partial mitigation only: an underlying allocation failure can still reach the vulnerable code. '
            . 'Trade-off: with no PHP limit, a runaway script can use all memory available to the worker, so put a container/cgroup memory limit in place first and test before production.' . $mlNote);
    }

    $uploads = p2s_is_on(ini_get('file_uploads'));
    $rows[] = p2s_row('file_uploads', $A, p2s_onoff(ini_get('file_uploads')),
        $uploads ? 'Off (0), if the application does not accept uploads' : 'Off (no change)',
        $uploads ? 'REVIEW' : 'OK',
        'Restricting unnecessary uploads reduces exposure (Cloudflare). It also sets the post_max_size target below: 8M without uploads, 32M with.');

    $target = $uploads ? '32M' : '8M';
    $pm = (string) ini_get('post_max_size');
    $pmBytes = p2s_to_bytes($pm);
    $pmDisplay = ($pmBytes === 0) ? $pm . ' (no limit)' : $pm;
    $pmOk = ($pmBytes !== null && $pmBytes > 0 && $pmBytes <= p2s_to_bytes($target));
    $rows[] = p2s_row('post_max_size', $A, $pmDisplay, $pmOk ? $pm . ' (no change)' : $target . ' or lower',
        $pmOk ? 'OK' : 'CHANGE',
        'Advisory: 8M if the application does not need uploads, 32M if it does. Also enforce request limits at the web server or proxy.'
        . p2s_override_note('post_max_size'));

    if ($uploads) {
        $um = (string) ini_get('upload_max_filesize');
        $umBytes = p2s_to_bytes($um);
        $umOk = ($umBytes !== null && $pmBytes !== null && $pmBytes > 0 && $umBytes < $pmBytes);
        $rows[] = p2s_row('upload_max_filesize', $A, $um,
            $umOk ? $um . ' (no change)' : 'Lower than post_max_size',
            $umOk ? 'OK' : 'CHANGE',
            'Advisory: keep upload_max_filesize below post_max_size.' . p2s_override_note('upload_max_filesize'));
    } else {
        $rows[] = p2s_row('upload_max_filesize', $A, (string) ini_get('upload_max_filesize'), 'n/a', 'N/A',
            'Not relevant while file_uploads is Off.');
    }

    // ---- CVE-2026-109619: stale global state ------------------------------------
    if (extension_loaded('session')) {
        $up = ini_get('session.upload_progress.enabled');
        $on = p2s_is_on($up);
        $rows[] = p2s_row('session.upload_progress.enabled', $B, p2s_onoff($up),
            $on ? '0 in php.ini, the FPM pool or server config (not ini_set() or .user.ini), then restart every worker' : '0 (no change)',
            $on ? 'CHANGE' : 'OK',
            'Blocks the confirmed session paths, not other variants.' . p2s_override_note('session.upload_progress.enabled'));
    } else {
        $rows[] = p2s_row('session.upload_progress.enabled', $B, 'session extension not loaded', 'n/a', 'N/A',
            'The confirmed session paths need the session extension.');
    }

    $feb = ini_get('fatal_error_backtraces');
    if ($feb === false) {
        $rows[] = p2s_row('fatal_error_backtraces', $B, 'not present', 'n/a', 'N/A', 'This setting exists in PHP 8.5 and later only.');
    } else {
        $on = p2s_is_on($feb);
        $rows[] = p2s_row('fatal_error_backtraces', $B, p2s_onoff($feb),
            $on ? '0 in php.ini, the FPM pool or server config, then restart every worker' : '0 (no change)',
            $on ? 'CHANGE' : 'OK',
            'Blocks the confirmed fatal-error backtrace path only.' . p2s_override_note('fatal_error_backtraces'));
    }

    if (is_array($startupError)) {
        $msg = $startupError['message'] . ' (' . basename((string) $startupError['file']) . ':' . $startupError['line'] . ')';
        $rows[] = p2s_row('Pre-request diagnostics', $B, $msg, 'Fix or remove the setting that triggers it', 'REVIEW',
            'A diagnostic was raised before this script ran. Advisory: remove invalid or deprecated settings applied per request that emit diagnostics before initialization. Hiding diagnostics does not help.');
    } else {
        $rows[] = p2s_row('Pre-request diagnostics', $B, 'None seen', 'n/a', 'OK',
            'Best-effort: only the most recent diagnostic is visible, so this cannot rule out every case.');
    }

    $rows[] = p2s_row('max_execution_time', $B, (string) ini_get('max_execution_time'), 'No specific value', 'INFO',
        'The advisory asks you to fix attacker-reachable execution timeouts in application code. Changing this value is not a mitigation by itself.');

    if (in_array($sapi, array('cgi-fcgi', 'fpm-fcgi', 'cgi'), true)) {
        $uif = (string) ini_get('user_ini.filename');
        $rows[] = p2s_row('user_ini.filename', $B, $uif === '' ? '(disabled)' : $uif, 'No change needed', 'INFO',
            'Mitigation settings placed in .user.ini files do not count. Put them in php.ini or the FPM pool config.');
    }

    // ---- Both / defence in depth ------------------------------------------------
    $mi = (int) ini_get('max_input_vars');
    $rows[] = p2s_row('max_input_vars', 'Both', (string) $mi, $mi > 1000 ? '1000 (default) unless the app needs more' : $mi . ' (no change)',
        $mi > 1000 ? 'REVIEW' : 'OK',
        '(Inferred, not in the advisory.) PHP\'s own counterpart to the input-field-count limit the advisory asks you to enforce at the proxy.');

    $mn = (int) ini_get('max_input_nesting_level');
    $rows[] = p2s_row('max_input_nesting_level', 'Both', (string) $mn, $mn > 64 ? '64 (default) unless the app needs more' : $mn . ' (no change)',
        $mn > 64 ? 'REVIEW' : 'OK',
        '(Inferred, not in the advisory.) PHP\'s own counterpart to the nesting-depth limit the advisory asks you to enforce at the proxy.');

    $oc = ini_get('opcache.enable');
    if ($oc !== false) {
        $rows[] = p2s_row('opcache.enable', 'Both', p2s_onoff($oc), 'No published guidance', 'INFO',
            'Imperva reports OPcache class caching is one of the components involved. No OPcache setting has been published as a mitigation.');
    }

    $rl = p2s_rlimits();
    if ($rl === null) {
        $rows[] = p2s_row('RLIMIT_AS / RLIMIT_DATA', $A, 'Could not read', 'unlimited', 'N/A',
            'Could not read /proc/self/limits (non-Linux, open_basedir or restricted /proc). Check by hand.');
    } else {
        $as = isset($rl['RLIMIT_AS']) ? $rl['RLIMIT_AS'] : '?';
        $da = isset($rl['RLIMIT_DATA']) ? $rl['RLIMIT_DATA'] : '?';
        $ok = ($as === 'unlimited' && $da === 'unlimited');
        $rows[] = p2s_row('RLIMIT_AS / RLIMIT_DATA', $A, 'AS=' . $as . ', DATA=' . $da,
            $ok ? 'unlimited (no change)' : 'unlimited; use a container/cgroup memory limit instead',
            $ok ? 'OK' : 'CHANGE',
            'Advisory: do not use RLIMIT_AS or RLIMIT_DATA as a memory cap, because they can cause the vulnerable allocation failure.');
    }

    $cg = p2s_cgroup_memory();
    if ($cg['state'] === 'limited') {
        $rows[] = p2s_row('Container / cgroup memory limit', $A, round($cg['bytes'] / 1048576) . 'M (' . $cg['file'] . ')', 'Keep', 'OK',
            'Advisory: use a container or cgroup limit as the availability boundary, preferably one that kills only the affected worker.');
    } elseif ($cg['state'] === 'unlimited') {
        $rows[] = p2s_row('Container / cgroup memory limit', $A, 'None found', 'Set one, preferably killing only the affected worker',
            $mlBytes === -1 ? 'CHANGE' : 'REVIEW',
            ($mlBytes === -1 ? 'memory_limit is -1, so nothing else caps worker memory. ' : '')
            . 'Advisory: use a container or cgroup limit as the availability boundary. Best-effort detection.');
    } else {
        $rows[] = p2s_row('Container / cgroup memory limit', $A, 'Could not read', 'Set one, preferably killing only the affected worker', 'N/A',
            'Could not read cgroup information (non-Linux, open_basedir or restricted /proc). Check by hand.');
    }

    return $rows;
}

function p2s_manual_items()
{
    return array(
        'Vendor backports: distributions may patch without changing the version number. Check your vendor advisory if the version check says vulnerable.',
        'Every PHP install on the host: other FPM pools, virtual hosts, containers, and CLI vs web. Run this script in each context.',
        'Worker restarts: after updating PHP or changing settings, restart or reload every worker (FPM reload, Apache restart).',
        'Where settings are applied: php.ini, the FPM pool and Apache config count. ini_set() and .user.ini do not.',
        'Web server / proxy limits: decoded request size, input field count, multipart part count, header count and nesting depth. They must also cover requests without a usable Content-Length (e.g. chunked).',
        'Container / cgroup kill policy: prefer one that kills only the affected worker.',
        'WAF: Cloudflare managed rules protect Free plans by default. Paid plans should confirm the Managed Ruleset is deployed in block mode. A WAF does not replace patching.',
        'Application code: fix attacker-reachable fatal errors and execution timeouts, including in callbacks, upload or import processing, and cleanup.',
        'Per-request settings: remove invalid or deprecated settings that emit diagnostics before initialization.',
        'Does NOT help: hiding errors with error_reporting, display_errors or the @ operator.',
        'Package source: rpms.remirepo.net had no update on release day. Use distribution packages or build from source.',
        'Signs of compromise: if you see evidence of exploitation, treat it as an incident and escalate to your security team. Patching alone does not remove an attacker who already got in.',
    );
}

function p2s_build_report($startupError)
{
    $ini = php_ini_loaded_file();
    $scanned = php_ini_scanned_files();
    return array(
        'generated' => gmdate('Y-m-d H:i:s') . ' UTC',
        'host' => function_exists('php_uname') ? @php_uname('n') : '(unknown)',
        'version' => p2s_version_status(),
        'sapi' => p2s_sapi_info(),
        'ini_file' => $ini ? $ini : '(none)',
        'ini_scanned' => $scanned ? preg_replace('/\s*,\s*/', ', ', trim($scanned)) : '(none)',
        'settings' => p2s_settings_checks($startupError),
        'manual' => p2s_manual_items(),
    );
}

function p2s_exit_code($report)
{
    $map = array('PATCHED' => 0, 'VULNERABLE' => 1, 'UNKNOWN' => 2);
    return $map[$report['version']['code']];
}

function p2s_settings_intro($report)
{
    return ($report['version']['code'] === 'PATCHED')
        ? 'PHP is patched. These settings are only stop-gaps for unpatched systems; shown for reference.'
        : 'Stop-gaps only. They reduce specific attack paths but do not make an unpatched system safe. Patching is the only complete fix.';
}

function p2s_counts($rows)
{
    $c = array('CHANGE' => 0, 'REVIEW' => 0, 'OK' => 0, 'INFO' => 0, 'N/A' => 0);
    foreach ($rows as $r) {
        $c[$r['status']]++;
    }
    return $c;
}

// ===================================================================== rendering

function p2s_wrap($text, $first, $next, $width = 100)
{
    return $first . wordwrap($text, $width - strlen($next), "\n" . $next, false);
}

/** "Label : value" with the value wrapped under itself. */
function p2s_field($indent, $label, $value, $width = 100)
{
    $prefix = $indent . str_pad($label, 12) . ': ';
    $hang = str_repeat(' ', strlen($prefix));
    return $prefix . wordwrap($value, $width - strlen($prefix), "\n" . $hang, false);
}

function p2s_render_text($r)
{
    $L = array();
    $hr = str_repeat('=', 78);
    $L[] = $hr;
    $L[] = 'PHP2Shell exposure check (CVE-2026-109618, CVE-2026-109619)';
    $L[] = 'Generated: ' . $r['generated'] . '   Host: ' . $r['host'];
    $L[] = 'Advisory : ' . P2S_ADVISORY;
    $L[] = $hr;
    $L[] = p2s_text_banner();
    if ($r['sapi']['sapi'] === 'cli') {
        $L[] = p2s_wrap('NOTE: run from the CLI. Settings below describe the CLI configuration, not your web workers.', '', '      ');
    }
    $L[] = '';
    $L[] = '1. PHP VERSION';
    $L[] = p2s_wrap('[' . $r['version']['code'] . '] ' . $r['version']['headline'], '   ', '   ');
    $L[] = '   Running: PHP ' . PHP_VERSION;
    foreach ($r['version']['details'] as $d) {
        $L[] = p2s_wrap('- ' . $d, '   ', '     ');
    }
    $L[] = '';
    $L[] = '2. SERVER API';
    $L[] = '   ' . $r['sapi']['sapi'] . ' (' . $r['sapi']['label'] . ')   Risk: ' . $r['sapi']['risk'];
    $L[] = p2s_wrap($r['sapi']['note'], '   ', '   ');
    $L[] = p2s_wrap('Loaded php.ini: ' . $r['ini_file'], '   ', '     ');
    $L[] = p2s_wrap('Additional .ini files: ' . $r['ini_scanned'], '   ', '     ');
    $L[] = '';
    $c = p2s_counts($r['settings']);
    $L[] = '3. RELEVANT SETTINGS   (' . $c['CHANGE'] . ' to change, ' . $c['REVIEW'] . ' to review, ' . $c['OK'] . ' OK)';
    $L[] = p2s_wrap(p2s_settings_intro($r), '   ', '   ');
    foreach ($r['settings'] as $s) {
        $L[] = '';
        $L[] = '   ' . str_pad('[' . $s['status'] . ']', 9) . $s['name'] . ($s['cve'] !== '' ? '   (' . $s['cve'] . ')' : '');
        $pad = '            ';
        $L[] = p2s_field($pad, 'Current', $s['current']);
        $L[] = p2s_field($pad, 'Recommended', $s['recommended']);
        $L[] = p2s_field($pad, 'Why', $s['why']);
    }
    $L[] = '';
    $L[] = '4. CHECK MANUALLY (not detectable by this script)';
    foreach ($r['manual'] as $m) {
        $L[] = p2s_wrap('- ' . $m, '   ', '     ');
    }
    $L[] = '';
    $L[] = p2s_text_banner();
    $L[] = '';
    return implode("\n", $L);
}

function p2s_text_banner()
{
    $bar = str_repeat('!', 78);
    return $bar . "\n" . p2s_wrap('!!! ' . P2S_DELETE_HEAD, '', '!!! ', 78) . "\n"
        . p2s_wrap('!!! ' . P2S_DELETE_BODY, '', '!!! ', 78) . "\n" . $bar;
}

function p2s_linkify($escaped)
{
    return preg_replace('~(https?://[^\s<]*[^\s<.,;)])~', '<a href="$1" rel="noopener noreferrer">$1</a>', $escaped);
}

function p2s_render_html($r)
{
    $h = array();
    $h[] = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">';
    $h[] = '<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow">';
    $h[] = '<title>PHP2Shell exposure check</title><style>';
    $h[] = ':root{--bg:#fff;--fg:#1b1b1b;--muted:#5f5f5f;--line:#ddd;--card:#f5f5f5;--red:#b3261e;--amber:#8a5a00;--green:#1e7b34;--blue:#1d4f91;--grey:#6b6b6b}';
    $h[] = '@media (prefers-color-scheme:dark){:root{--bg:#151515;--fg:#ececec;--muted:#a8a8a8;--line:#333;--card:#1f1f1f;--red:#ff8a80;--amber:#ffcc66;--green:#7dd88f;--blue:#8ab4f8;--grey:#9a9a9a;color-scheme:dark}}';
    $h[] = 'body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:1150px;margin:0 auto;padding:24px}';
    $h[] = 'h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}';
    $h[] = '.meta,.muted{color:var(--muted);font-size:.9rem}a{color:var(--blue)}';
    $h[] = '.verdict{border-left:6px solid;padding:12px 16px;background:var(--card);border-radius:6px;font-size:1.1rem;font-weight:600}';
    $h[] = '.v-PATCHED{border-color:var(--green)}.v-VULNERABLE{border-color:var(--red)}.v-UNKNOWN{border-color:var(--amber)}';
    $h[] = '.warn{border:1px solid var(--amber);color:var(--amber);padding:8px 12px;border-radius:6px;margin:12px 0}';
    $h[] = '.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid var(--line)}';
    $h[] = 'th{color:var(--muted);font-weight:600}code{font-family:ui-monospace,Consolas,monospace;font-size:.9em}';
    $h[] = '.s{font-weight:700;white-space:nowrap}.s-CHANGE{color:var(--red)}.s-REVIEW{color:var(--amber)}.s-OK{color:var(--green)}.s-INFO{color:var(--blue)}.s-N\\/A{color:var(--grey)}';
    $h[] = '.danger{color:var(--red);font-weight:700;border:3px solid var(--red);border-radius:6px;padding:12px 16px;margin:16px 0;font-size:1.15rem}';
    $h[] = '.danger span{display:block;font-size:.95rem;margin-top:4px}';
    $h[] = 'li{margin:4px 0}</style></head><body>';
    $banner = '<div class="danger" role="alert">' . p2s_h(P2S_DELETE_HEAD) . '<span>' . p2s_h(P2S_DELETE_BODY) . '</span></div>';
    $h[] = $banner;

    $h[] = '<h1>PHP2Shell exposure check</h1>';
    $h[] = '<div class="meta">CVE-2026-109618, CVE-2026-109619 &middot; Generated ' . p2s_h($r['generated'])
        . ' &middot; Host ' . p2s_h($r['host']) . ' &middot; <a href="' . p2s_h(P2S_ADVISORY) . '" rel="noopener noreferrer">PHP advisory</a></div>';
    if ($r['sapi']['sapi'] === 'cli') {
        $h[] = '<div class="warn">Run from the CLI: settings describe the CLI configuration, not your web workers.</div>';
    }

    $v = $r['version'];
    $h[] = '<h2>1. PHP version</h2>';
    $h[] = '<div class="verdict v-' . p2s_h($v['code']) . '">' . p2s_h($v['headline']) . '</div>';
    $h[] = '<p class="muted">Running PHP <code>' . p2s_h(PHP_VERSION) . '</code></p>';
    if ($v['details']) {
        $h[] = '<ul>';
        foreach ($v['details'] as $d) {
            $h[] = '<li>' . p2s_linkify(p2s_h($d)) . '</li>';
        }
        $h[] = '</ul>';
    }

    $s = $r['sapi'];
    $h[] = '<h2>2. Server API</h2>';
    $h[] = '<p><code>' . p2s_h($s['sapi']) . '</code> (' . p2s_h($s['label']) . ') &middot; Risk: <strong>' . p2s_h($s['risk']) . '</strong><br>' . p2s_h($s['note']) . '</p>';
    $h[] = '<p class="muted">Loaded php.ini: <code>' . p2s_h($r['ini_file']) . '</code><br>Additional .ini files: <code>' . p2s_h($r['ini_scanned']) . '</code></p>';

    $c = p2s_counts($r['settings']);
    $h[] = '<h2>3. Relevant settings</h2>';
    $h[] = '<p>' . $c['CHANGE'] . ' to change, ' . $c['REVIEW'] . ' to review, ' . $c['OK'] . ' OK. <span class="muted">' . p2s_h(p2s_settings_intro($r)) . '</span></p>';
    $h[] = '<div class="wrap"><table><thead><tr><th>Status</th><th>Setting</th><th>Current</th><th>Recommended</th><th>Why</th></tr></thead><tbody>';
    foreach ($r['settings'] as $row) {
        $h[] = '<tr><td class="s s-' . p2s_h($row['status']) . '">' . p2s_h($row['status']) . '</td>'
            . '<td><code>' . p2s_h($row['name']) . '</code><br><span class="muted">' . p2s_h($row['cve']) . '</span></td>'
            . '<td><code>' . p2s_h($row['current']) . '</code></td>'
            . '<td>' . p2s_h($row['recommended']) . '</td>'
            . '<td>' . p2s_h($row['why']) . '</td></tr>';
    }
    $h[] = '</tbody></table></div>';

    $h[] = '<h2>4. Check manually (not detectable by this script)</h2><ul>';
    foreach ($r['manual'] as $m) {
        $h[] = '<li>' . p2s_h($m) . '</li>';
    }
    $h[] = '</ul>';
    $h[] = $banner;
    $h[] = '</body></html>';
    return implode("\n", $h);
}

// ======================================================================= logging

/**
 * Replaces the log file with $text. The throttle check and the write happen under one
 * exclusive lock, so concurrent requests cannot both pass the check.
 * Returns array('status' => ok|throttled|busy|error, 'retry' => seconds).
 */
function p2s_write_log($file, $text, $minInterval)
{
    $fh = @fopen($file, 'c'); // create if missing; do not truncate before locking
    if ($fh === false) {
        return array('status' => 'error', 'retry' => 0);
    }
    if (!flock($fh, LOCK_EX | LOCK_NB)) { // another request is writing: skip, don't queue
        fclose($fh);
        return array('status' => 'busy', 'retry' => 5);
    }
    $st = fstat($fh);
    if ($minInterval > 0 && $st['size'] > 0) { // size 0 = new or empty file, never throttled
        $age = time() - $st['mtime'];
        if ($age >= 0 && $age < $minInterval) {
            flock($fh, LOCK_UN);
            fclose($fh);
            return array('status' => 'throttled', 'retry' => $minInterval - $age);
        }
    }
    $ok = ftruncate($fh, 0) && rewind($fh) && fwrite($fh, $text) === strlen($text);
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return array('status' => $ok ? 'ok' : 'error', 'retry' => 0);
}

function p2s_http_status($code, $text)
{
    if (function_exists('http_response_code')) {
        http_response_code($code);
    } else {
        header('HTTP/1.1 ' . $code . ' ' . $text);
    }
}

/**
 * Screen output when logging is enabled. Deliberately shows no verdict, no settings
 * and no log location: only a timestamp and whether the run completed.
 */
function p2s_render_notice($generated, $headline, $detail, $ok, $format)
{
    if ($format === 'text') {
        return $generated . "\n" . $headline . "\n" . $detail . "\n" . p2s_text_banner() . "\n";
    }
    return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow">'
        . '<title>PHP2Shell check</title><style>'
        . ':root{--bg:#fff;--fg:#1b1b1b;--muted:#5f5f5f;--red:#b3261e;--green:#1e7b34;--amber:#8a5a00}'
        . '@media (prefers-color-scheme:dark){:root{--bg:#151515;--fg:#ececec;--muted:#a8a8a8;--red:#ff8a80;--green:#7dd88f;--amber:#ffcc66;color-scheme:dark}}'
        . 'body{background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:760px;margin:0 auto;padding:32px 24px}'
        . '.t{color:var(--muted);font-size:.9rem}.h{font-size:1.3rem;font-weight:600;margin:6px 0;color:var(--' . ($ok ? 'green' : 'amber') . ')}'
        . '.danger{color:var(--red);font-weight:700;border:3px solid var(--red);border-radius:6px;padding:12px 16px;margin:24px 0 0;font-size:1.1rem}'
        . '.danger span{display:block;font-size:.95rem;margin-top:4px}</style></head><body>'
        . '<div class="t">' . p2s_h($generated) . '</div>'
        . '<div class="h">' . p2s_h($headline) . '</div>'
        . '<div>' . p2s_h($detail) . '</div>'
        . '<div class="danger" role="alert">' . p2s_h(P2S_DELETE_HEAD) . '<span>' . p2s_h(P2S_DELETE_BODY) . '</span></div>'
        . '</body></html>';
}

// ========================================================================== main

$isCli = (PHP_SAPI === 'cli');
$format = $isCli ? 'text' : 'html';

if ($isCli) {
    $args = isset($_SERVER['argv']) ? array_slice($_SERVER['argv'], 1) : array();
    foreach ($args as $arg) {
        if ($arg === '--help' || $arg === '-h') {
            echo 'Usage: php ' . basename(__FILE__) . "\n";
            echo "  Output goes to the screen, or ONLY to \$CONFIG['log_file'] if that is set in this file.\n";
            exit(0);
        }
        // No other options: output mode and log path come only from $CONFIG.
        fwrite(STDERR, "Unknown option: $arg (try --help)\n");
        exit(2);
    }
} else {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
    if (!in_array($ip, $CONFIG['allowed_ips'], true)) {
        p2s_http_status(403, 'Forbidden');
        header('Content-Type: text/plain; charset=UTF-8');
        echo "Forbidden. Add your IP address to \$CONFIG['allowed_ips'] in this file.\n";
        echo 'Your address as seen by PHP: ' . $ip . "\n";
        exit;
    }
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex, nofollow');
    if (isset($_GET['format']) && $_GET['format'] === 'text') {
        $format = 'text';
    }
    header('Content-Type: ' . ($format === 'text' ? 'text/plain' : 'text/html') . '; charset=UTF-8');
}

$report = p2s_build_report($p2sStartupError);
$logFile = isset($CONFIG['log_file']) ? (string) $CONFIG['log_file'] : '';

// ---- Logging enabled: the report goes only to the log file -----------------------
if ($logFile !== '') {
    // Web writes are throttled; the CLI already requires shell access, so it is not.
    $interval = isset($CONFIG['log_min_interval']) ? (int) $CONFIG['log_min_interval'] : 60;
    $interval = $isCli ? 0 : max(0, $interval);
    $res = p2s_write_log($logFile, p2s_render_text($report) . "\n", $interval);

    // The screen never shows the verdict or the log location.
    if ($res['status'] === 'ok') {
        $ok = true;
        $headline = 'php2shell check successfully run.';
        $detail = 'Check the log for results.';
    } else {
        $ok = false;
        $headline = ($res['status'] === 'error')
            ? 'php2shell check could not save its results.'
            : 'php2shell check did not run.';
        if ($res['status'] === 'throttled') {
            $detail = 'It ran less than ' . $interval . ' seconds ago. Try again in ' . $res['retry'] . ' seconds.';
        } elseif ($res['status'] === 'busy') {
            $detail = 'Another run is in progress. Try again shortly.';
        } else {
            $detail = 'The results could not be saved. Ask the administrator to check the log file settings.';
        }
        if (!$isCli) {
            if ($res['status'] === 'error') {
                p2s_http_status(500, 'Internal Server Error');
            } else {
                p2s_http_status(429, 'Too Many Requests');
                header('Retry-After: ' . $res['retry']);
            }
        }
    }
    echo p2s_render_notice($report['generated'], $headline, $detail, $ok, $format);
    if ($isCli) {
        exit($ok ? 0 : 3); // exit code says only whether the report was written
    }
    exit;
}

// ---- Logging disabled: full report on screen -------------------------------------
echo ($format === 'text') ? p2s_render_text($report) : p2s_render_html($report);

if ($isCli) {
    exit(p2s_exit_code($report));
}
