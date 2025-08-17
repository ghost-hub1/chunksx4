 <?php
// =======================
// 🔐 TOKEN-AUTH GATEWAY (Disk-safe, Reassembly-Safe)
// =======================

$logFile     = "debug_log.txt";
$tokenDB     = "tokens.json";
$payloadFile = "payload_core.b64";
$cacheDir    = __DIR__ . "/cache_site";
$decryptedZip = "decrypted_payload.zip";

// Logging helper
function logEntry($msg) {
    global $logFile;
    file_put_contents($logFile, "[" . date("Y-m-d H:i:s") . "] $msg\n", FILE_APPEND);
}

// Recursive delete
function recursiveDelete($dir) {
    foreach (glob($dir . '/*') as $f) is_dir($f) ? recursiveDelete($f) : unlink($f);
    rmdir($dir);
}

// =========================
// 🔑 STEP 1: Validate Token
// =========================

$token = $_GET['t'] ?? $_COOKIE['stealth_access'] ?? null;
if (!$token || !file_exists($tokenDB)) {
    logEntry("❌ No token or token DB missing.");
    exit("Invalid request.");
}

$db = json_decode(file_get_contents($tokenDB), true);
if (!isset($db[$token])) {
    logEntry("❌ Invalid token: $token");
    exit("Unauthorized");
}

$record = $db[$token];
if (($record['status'] ?? '') !== 'active') {
    logEntry("❌ Token $token is revoked/inactive.");
    exit("Access denied");
}

if (isset($record['expires']) && strtotime($record['expires']) < time()) {
    logEntry("❌ Token expired: $token");
    exit("Expired token");
}

// =========================
// 🔄 STEP 2: Reassemble .b64
// =========================

if (file_exists($payloadFile)) {
    logEntry("⚠️ Skipping reassembly — $payloadFile already exists.");
} else {
    $chunkFiles = glob("payload_part*.b64");
    natsort($chunkFiles);

    if (!$chunkFiles) {
        logEntry("❌ No payload_part*.b64 chunks found.");
        exit("Missing chunks.");
    }

    $out = fopen($payloadFile, "wb");
    foreach ($chunkFiles as $chunk) {
        $data = file_get_contents($chunk);
        if ($data === false) {
            logEntry("❌ Failed to read chunk: $chunk");
            fclose($out);
            exit("Chunk read failed.");
        }
        fwrite($out, $data);
        logEntry("📥 Added chunk: $chunk");
    }
    fclose($out);
    logEntry("✅ Reassembled to: $payloadFile");
}

// =========================
// 🔐 STEP 3: Decrypt Payload
// =========================

$key = base64_decode($record['key']);
$iv  = base64_decode($record['iv']);
logEntry("🧬 Token resolved to key/iv (lengths: " . strlen($key) . ", " . strlen($iv) . ")");

$raw = base64_decode(file_get_contents($payloadFile));
if (!$raw) {
    logEntry("❌ base64_decode failed.");
    exit("Invalid base64 payload.");
}

$decrypted = openssl_decrypt($raw, "aes-256-cbc", $key, OPENSSL_RAW_DATA, $iv);
if (!$decrypted) {
    logEntry("❌ openssl_decrypt returned false");
    exit("Decryption failed");
}

file_put_contents($decryptedZip, $decrypted);
logEntry("📦 Decrypted to: $decryptedZip");
logEntry("🧪 Attempting to unzip from: $decryptedZip");

// =============================
// 📦 STEP 4: Extract to cache_site
// =============================

if (is_dir($cacheDir)) recursiveDelete($cacheDir);
mkdir($cacheDir);
file_put_contents("$cacheDir/.timestamp", time());

$zip = new ZipArchive();
if ($zip->open($decryptedZip) === TRUE) {
    $zip->extractTo($cacheDir);
    $zip->close();
    logEntry("✅ Cache rebuilt at: $cacheDir");
} else {
    logEntry("❌ Failed to unzip: $decryptedZip");
    exit("Extraction failed");
}

// =============================
// 🍪 Set Cookie and Redirect
// =============================

setcookie("stealth_access", "valid", time() + 21600, "/"); // 6 hrs
header("Location: navigate.php");
exit;
?>