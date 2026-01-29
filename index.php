<?php
/**
 * Secure Burn-After-Reading
 * By Prince 2025.12
 * https://github.com/Andeasw/BurnRead
 */

header("X-Frame-Options: SAMEORIGIN");
header("X-Content-Type-Options: nosniff");
header("X-Robots-Tag: noindex, noarchive, nofollow");
header("Referrer-Policy: strict-origin-when-cross-origin");

session_start();
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

$selfUrl = basename($_SERVER['PHP_SELF']);

// --- HKDF Key Derivation ---
function derive_server_key(string $envKey): string {
    return hash_hkdf(
        'sha256',
        $envKey,
        32,
        'burnread-master-key-context',
        'burnread-static-salt-v2'
    );
}

// --- Garbage Collection ---
function gc_cleanup() {
    global $env;
    if (mt_rand(1, 100) !== 1) return;

    $cleanup_files = function($dir) {
        if (!is_dir($dir)) return;
        $now = time();
        foreach (glob($dir . '/*.{json,dat}', GLOB_BRACE) as $f) {
            if ($now - filemtime($f) > 2592000) @unlink($f); 
        }
    };
    $cleanup_files('burnread_data');
    $cleanup_files('burnread_uploads');

    $logDir = __DIR__ . '/burnread_logs';
    if (is_dir($logDir)) {
        $maxDays = intval($env['LOG_MAX_DAYS'] ?? 365);
        $now = time();
        foreach (glob($logDir . '/*.log') as $f) {
            if ($now - filemtime($f) > $maxDays * 86400) @unlink($f);
        }
    }
}

// --- Init Directories & Security ---
function secure_path($path) {
    if (!is_dir($path)) mkdir($path, 0755, true);
    if (!file_exists($path . '/index.php')) file_put_contents($path . '/index.php', '<?php header("HTTP/1.0 404 Not Found"); exit;');
    if (!file_exists($path . '/.htaccess')) file_put_contents($path . '/.htaccess', "Deny from all");
}
secure_path('burnread_data');
secure_path('burnread_uploads');
secure_path('burnread_logs');

// Robust .htaccess Check
$rootHtaccess = __DIR__ . '/.htaccess';
$htContent = file_exists($rootHtaccess) ? file_get_contents($rootHtaccess) : '';
if (strpos($htContent, 'BurnRead-Protection') === false) {
    $rules = "\n# BurnRead-Protection\n<FilesMatch \"^(\\.burnread\\.env|.*\\.log)$\">\nRequire all denied\n</FilesMatch>\n";
    file_put_contents($rootHtaccess, $rules, FILE_APPEND | LOCK_EX);
}

// --- Environment ---
$envPath = __DIR__ . '/.burnread.env';
if (!file_exists($envPath)) {
    $proto = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? "https" : "http";
    $port = $_SERVER['SERVER_PORT'];
    $dispPort = (($proto === 'http' && $port == 80) || ($proto === 'https' && $port == 443)) ? '' : ":$port";
    $autoDomain = $proto . "://" . $_SERVER['SERVER_NAME'] . $dispPort;
    $autoKey = bin2hex(random_bytes(32));
    
    $defEnv = implode("\n", [
        "ENCRYPTION_KEY=\"$autoKey\"",
        "ENABLE_LOGGING=\"false\"",
        "LOG_MAX_DAYS=\"365\"",
        "LOG_MAX_SIZE=\"30\"", 
        "SITE_NAME=\"BurnRead\"",
        "SITE_ICON=\"https://cdn-icons-png.flaticon.com/512/2913/2913520.png\"",
        "SITE_DOMAIN=\"$autoDomain\"",
        "SITE_BACKGROUND=\"https://t.alcy.cc/moez\"",
        "DEFAULT_LANG=\"cn\"",
        "DEFAULT_THEME=\"light\"",
        "TIMEZONE=\"Asia/Shanghai\"",
        "MAX_READ_LIMIT=\"10\"",
        "MAX_EXPIRY_DAYS=\"30\"",
        "MAX_DELAY_DAYS=\"30\"",
        "UPLOAD_MAX_MB=\"5\"",
        "UPLOAD_TYPES=\"png,jpg,gif,webp,ico,zip,rar,7z,pdf,txt,doc,docx,xls,xlsx\""
    ]);
    file_put_contents($envPath, $defEnv);
    chmod($envPath, 0600);
}
if (basename($_SERVER['PHP_SELF']) === '.burnread.env') { header("HTTP/1.0 403 Forbidden"); die("Access Denied"); }

function loadEnv($path) {
    if (!file_exists($path)) return [];
    $env = [];
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (strpos($line, '=') !== false) {
            list($k, $v) = explode('=', $line, 2);
            $env[trim($k)] = trim(trim($v), "\"'");
        }
    }
    return $env;
}

$env = loadEnv($envPath);
if (empty($env['ENCRYPTION_KEY'])) die("Config Error: Missing Key");
date_default_timezone_set($env['TIMEZONE'] ?? 'Asia/Shanghai');
gc_cleanup();

$serverKey = derive_server_key($env['ENCRYPTION_KEY']);
$domain = rtrim($env['SITE_DOMAIN'] ?? '', '/');
$maxReads = intval($env['MAX_READ_LIMIT'] ?? 10);
$maxExp = intval($env['MAX_EXPIRY_DAYS'] ?? 30);
$maxDelay = intval($env['MAX_DELAY_DAYS'] ?? 30);
$uploadMaxMB = intval($env['UPLOAD_MAX_MB'] ?? 5);
$allowedExts = explode(',', $env['UPLOAD_TYPES'] ?? 'png,jpg,zip,txt');

// --- Helpers ---
function app_log($action, $info = '') {
    global $env;
    if (($env['ENABLE_LOGGING'] ?? 'false') !== 'true') return;
    
    $logDir = __DIR__ . '/burnread_logs';
    $logFile = $logDir . '/' . date('Y-m-d') . '.log';
    $maxSize = intval($env['LOG_MAX_SIZE'] ?? 30) * 1048576;
    if (file_exists($logFile) && filesize($logFile) > $maxSize) return;

    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $entry = sprintf("[%s] IP:%s | ACT:%s | %s | UA:%s\n", date('Y-m-d H:i:s'), $_SERVER['REMOTE_ADDR'], $action, $info, $ua);
    file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}

function encrypt_data($plaintext, $key) {
    global $serverKey;
    $derivedKey = hash_hkdf('sha256', $key, 32, 'aes-gcm', $serverKey);
    $iv = random_bytes(12); 
    $tag = "";
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $derivedKey, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ciphertext === false) return false;
    return base64_encode($iv . $tag . $ciphertext);
}

function decrypt_data($payload, $key) {
    global $serverKey;
    $decoded = base64_decode($payload, true);
    if ($decoded === false || strlen($decoded) < 28) return false;
    
    $iv = substr($decoded, 0, 12);
    $tag = substr($decoded, 12, 16);
    $ciphertext = substr($decoded, 28);
    $derivedKey = hash_hkdf('sha256', $key, 32, 'aes-gcm', $serverKey);
    
    return openssl_decrypt($ciphertext, 'aes-256-gcm', $derivedKey, OPENSSL_RAW_DATA, $iv, $tag);
}

function derive_key($pass, $salt) { 
    return hash_pbkdf2('sha256', $pass, $salt, 100000, 32, true); 
}

$langInput = $_GET['lang'] ?? $_COOKIE['site_lang'] ?? $env['DEFAULT_LANG'] ?? 'cn';
$langCode = in_array($langInput, ['cn', 'en']) ? $langInput : 'cn';
setcookie('site_lang', $langCode, time() + 86400 * 30, "/");

$i18n = [
    'cn' => [
        'app_title' => $env['SITE_NAME'], 'subtitle' => '私密传递 · 安全无痕',
        'desc' => '创建机密信息', 'nickname' => '您的代号 (可选)', 'note' => '简报摘要 (标题)',
        'pass_set' => '设定访问密码 (可选)', 'pass_req' => '请输入访问密码', 'reads' => '销毁次数',
        'expiry' => '有效期限', 'delay' => '延迟显示', 'gen_btn' => '生成机密链接',
        'copy' => '复制链接', 'copied' => '已复制', 'back' => '返回首页', 'edit' => '撰写', 'preview' => '预览',
        'placeholder' => '在此输入绝密情报... (支持 Markdown)', 'ready' => '机密链接已生成',
        'ready_desc' => '此链接被访问 %s 次后将彻底销毁', 'msg_404' => '信息不可用',
        'msg_404_desc' => '链接已失效、被删除或验证失败。',
        'msg_view' => '查看内容', 'unlock' => '验证并解锁', 'left' => '剩余次数: %s',
        'destroyed' => '已销毁', 'day' => '天', 'hour' => '时', 'min' => '分',
        'err_empty' => '内容不能为空', 'err_pass' => '密码错误或信息已失效', 'err_csrf' => '会话过期，请刷新',
        'sec_info' => '基础信息', 'sec_safe' => '安全控制',
        'upload_label' => '加密附件', 'upload_hint' => '最大 %sMB, 允许: %s',
        'download' => '下载附件', 'err_upload' => '文件类型不合规或伪装文件', 'max_limit' => '上限: %s次', 
        'max_time' => '最长: '.$maxExp.'天', 'max_delay' => '最长: '.$maxDelay.'天',
        'file_ready' => '包含加密附件', 'select_file' => '选择文件...',
        'gen_pass' => '随机密码', 'toggle_pass' => '显隐',
        'tip_max' => '拉满', 'tip_min' => '最小', 'tip_reset' => '归零',
        'wait_msg' => '锁定中', 'wait_desc' => '距离开放还有',
        'err_len' => '内容超出长度限制', 'err_sys' => '系统错误'
    ],
    'en' => [
        'app_title' => $env['SITE_NAME'], 'subtitle' => 'Secure & Private',
        'desc' => 'Create Secure Message', 'nickname' => 'Codename (Optional)', 'note' => 'Subject',
        'pass_set' => 'Password (Optional)', 'pass_req' => 'Password Required', 'reads' => 'Burn Limit',
        'expiry' => 'Auto-Destroy', 'delay' => 'Delay Start', 'gen_btn' => 'Generate Link',
        'copy' => 'Copy Link', 'copied' => 'Copied', 'back' => 'Back', 'edit' => 'Edit', 'preview' => 'Preview',
        'placeholder' => 'Top secret content here... (Markdown)', 'ready' => 'Link Generated',
        'ready_desc' => 'Self-destructs after %s visits', 'msg_404' => 'Unavailable',
        'msg_404_desc' => 'Link expired, deleted, or invalid.',
        'msg_view' => 'View Message', 'unlock' => 'Unlock', 'left' => '%s left',
        'destroyed' => 'Destroyed', 'day' => 'd', 'hour' => 'h', 'min' => 'm',
        'err_empty' => 'Content cannot be empty', 'err_pass' => 'Invalid Password/State', 'err_csrf' => 'Session expired',
        'sec_info' => 'Info', 'sec_safe' => 'Security',
        'upload_label' => 'Attachment', 'upload_hint' => 'Max %sMB, types: %s',
        'download' => 'Download', 'err_upload' => 'Invalid file type or mismatch', 'max_limit' => 'Max: %s', 
        'max_time' => 'Max: '.$maxExp.'d', 'max_delay' => 'Max: '.$maxDelay.'d',
        'file_ready' => 'File Attached', 'select_file' => 'Select File...',
        'gen_pass' => 'Random', 'toggle_pass' => 'Show',
        'tip_max' => 'Max', 'tip_min' => 'Min', 'tip_reset' => 'Reset',
        'wait_msg' => 'Locked', 'wait_desc' => 'Available in',
        'err_len' => 'Input too long', 'err_sys' => 'System Error'
    ]
];
$L = $i18n[$langCode];

$mimeMap = [
    'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif', 'webp' => 'image/webp', 'ico' => 'image/x-icon',
    'txt' => 'text/plain', 'pdf' => 'application/pdf', 'zip' => 'application/zip', 'rar' => 'application/x-rar-compressed', '7z' => 'application/x-7z-compressed',
    'doc' => 'application/msword', 'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls' => 'application/vnd.ms-excel', 'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt' => 'application/vnd.ms-powerpoint', 'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
];

$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
$reqFile = $_GET['file'] ?? '';
$isFile = !empty($reqFile) && isset($_GET['code']);
$viewState = 'create';
$name = ''; $note = ''; $msg = ''; $fileName = '';
$waitSecs = 0;

// --- CREATE ---
if ($isPost && !$isFile) {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) die($L['err_csrf']);
    if (strlen($_POST['message']??'') > 200000 || strlen($_POST['name']??'') > 64 || strlen($_POST['note']??'') > 128) die($L['err_len']);
    
    $content = $_POST['message'] ?? '';
    if (empty($content)) die($L['err_empty']);
    $masterKey = random_bytes(32); 
    $salt = random_bytes(16); 
    $verifyCode = bin2hex(random_bytes(32)); 
    
    $encPaths = null; $encName = null;
    if (!empty($_FILES['file']['name'])) {
        $f = $_FILES['file'];
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $f['tmp_name']);
        finfo_close($finfo);
        
        $isValid = false;
        if (isset($mimeMap[$ext])) {
            if (in_array($ext, ['zip','docx','xlsx','pptx','rar','7z'])) {
                if (strpos($mime, 'zip') !== false || strpos($mime, 'compressed') !== false || strpos($mime, 'octet-stream') !== false || strpos($mime, 'office') !== false) {
                    $isValid = true;
                }
            } elseif ($mimeMap[$ext] === $mime) {
                $isValid = true;
            }
        }
        
        if ($f['size'] > $uploadMaxMB*1048576 || !in_array($ext, $allowedExts) || !$isValid) die($L['err_upload']);
        
        $encFileName = 'burnread_uploads/'.bin2hex(random_bytes(32)).'.dat';
        file_put_contents($encFileName, encrypt_data(file_get_contents($f['tmp_name']), $masterKey));
        $encPaths = $encFileName; 
        $encName = encrypt_data($f['name'], $masterKey);
    }
    
    $userPass = $_POST['pass'] ?? '';
    $wrappingKey = (!empty($userPass)) ? derive_key($userPass, $salt) : derive_key($verifyCode, $salt);
    
    $now = time();
    
    $rawExp = (intval($_POST['ed']??0)*86400) + (intval($_POST['eh']??0)*3600) + (intval($_POST['em']??0)*60);
    $expS = min(max($rawExp, 60), $maxExp*86400);

    $delayS = min((intval($_POST['dd']??0)*86400) + (intval($_POST['dh']??0)*3600) + (intval($_POST['dm']??0)*60), $maxDelay*86400);
    
    $fileId = bin2hex(random_bytes(32)); 
    $fname = 'burnread_data/' . $fileId . '.json';
    $data = [
        'file_id' => $fileId,
        'msg' => encrypt_data($content, $masterKey),
        'name' => encrypt_data($_POST['name']??'', $masterKey),
        'note' => encrypt_data($_POST['note']??'', $masterKey),
        'file_path' => $encPaths, 'file_name' => $encName,
        'salt' => base64_encode($salt),
        'master_key_enc' => encrypt_data($masterKey, $wrappingKey),
        'pass_hash' => (!empty($userPass)) ? password_hash($userPass, PASSWORD_ARGON2ID) : null,
        'code_hash' => hash('sha256', $verifyCode),
        'time' => $now, 'avail' => $now + $delayS, 'exp' => $expS, 
        'reads' => min(max(intval($_POST['limit']??1), 1), $maxReads),
        'fails' => 0 
    ];
    
    if (file_put_contents($fname, json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE))) {
        app_log('CREATE', "FileID: $fileId");
        $viewState = 'success';
        $limit = $data['reads'];
        $link = $domain . rtrim(dirname($_SERVER['PHP_SELF']), '/\\') . "/$selfUrl?file=" . urlencode($fileId . '.json') . "&code=" . urlencode($verifyCode);
    } else {
        die($L['err_sys']);
    }
}

// --- READ / DOWNLOAD ---
if ($isFile) {
    ignore_user_abort(true);
    
    if (!preg_match('/^[a-f0-9]{64}\.json$/', $reqFile) || !preg_match('/^[a-f0-9]{64}$/', $_GET['code'])) {
        header("HTTP/1.0 400 Bad Request"); die("Invalid Request");
    }
    
    $file = "burnread_data/" . $reqFile;
    
    if (!file_exists($file)) {
        $viewState = 'error';
        app_log('404', "File: $reqFile");
    } else {
        $fp = fopen($file, 'r+');
        if ($fp && flock($fp, LOCK_EX)) {
            $raw = stream_get_contents($fp);
            $data = json_decode($raw, true);
            $now = time();
            $shouldBurn = false;
            
            if (!is_array($data) || !isset($data['master_key_enc']) || ($now - $data['time'] > $data['exp'])) {
                $shouldBurn = true; $viewState = 'error'; app_log('EXPIRED', "FileID: $reqFile");
            }
            elseif (isset($data['fails']) && $data['fails'] >= 5) {
                 $shouldBurn = true; $viewState = 'error'; app_log('BRUTE_FORCE_LOCK', "FileID: $reqFile");
            }
            elseif ($data['reads'] <= 0 && !isset($_GET['download'])) {
                $shouldBurn = true; $viewState = 'error'; app_log('BURNED_ENTRY', "FileID: $reqFile");
            }
            elseif (isset($data['file_id']) && $data['file_id'] !== str_replace('.json', '', $reqFile)) {
                $shouldBurn = true; $viewState = 'error';
            }
            elseif ($now < $data['avail']) {
                $viewState = 'wait';
                $waitSecs = $data['avail'] - $now;
            }
            else {
                $passReq = !empty($data['pass_hash']);
                $confirm = isset($_GET['confirm']) || isset($_GET['download']);
                $isDownload = isset($_GET['download']);
                
                if ($confirm) {
                    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
                         die($L['err_csrf']);
                    }

                    $userPass = $_POST['pass'] ?? ''; 
                    $authValid = $passReq ? password_verify($userPass, $data['pass_hash']) : hash_equals($data['code_hash'], hash('sha256', $_GET['code']));
                    
                    if (!$authValid) {
                        $data['fails'] = ($data['fails'] ?? 0) + 1;
                        if ($data['fails'] >= 5) {
                            $shouldBurn = true;
                            app_log('BRUTE_FORCE_BURN', "FileID: $reqFile - Max attempts reached");
                        } else {
                            ftruncate($fp, 0); rewind($fp);
                            fwrite($fp, json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
                            usleep(300000); 
                        }
                        
                        $err = $passReq ? $L['err_pass'] : $L['msg_404'];
                        if (!$passReq) $viewState = 'error';
                        app_log('AUTH_FAIL', "FileID: $reqFile");
                    } else {
                        $salt = base64_decode($data['salt'], true);
                        $mk = decrypt_data($data['master_key_enc'], derive_key($passReq ? $userPass : $_GET['code'], $salt));
                        
                        if ($mk === false) {
                            $shouldBurn = true; $viewState = 'error'; $err = $L['msg_404'];
                            app_log('DECRYPT_FAIL', "FileID: $reqFile - Key Invalid");
                        } else {
                            $msg = decrypt_data($data['msg'], $mk);
                            $name = decrypt_data($data['name'], $mk);
                            $note = decrypt_data($data['note'], $mk);
                            
                            if (!empty($data['file_path']) && file_exists($data['file_path'])) {
                                if ($isDownload) {
                                    $rawFile = file_get_contents($data['file_path']);
                                    $decFile = decrypt_data($rawFile, $mk);
                                    if ($decFile !== false) {
                                        $fileName = str_replace(['/','\\',':'], '', decrypt_data($data['file_name'], $mk));
                                        if (ob_get_level()) ob_end_clean();
                                        header('Content-Type: application/octet-stream');
                                        header('Content-Disposition: attachment; filename*=UTF-8\'\''.rawurlencode($fileName));
                                        header('Content-Length: ' . strlen($decFile));
                                        echo $decFile;
                                        $viewState = 'downloaded';
                                        app_log('DOWNLOAD', "FileID: $reqFile");
                                    }
                                } else {
                                    $fileReady = true;
                                    $fileName = str_replace(['/','\\',':'], '', decrypt_data($data['file_name'], $mk));
                                }
                            }
                            
                            if ($viewState !== 'downloaded') {
                                $viewState = 'view';
                                app_log('VIEW', "FileID: $reqFile");
                            }
                        }
                    }
                    
                    if (($viewState === 'view' || $viewState === 'downloaded') && !$shouldBurn) {
                        $data['reads']--;
                        if ($data['reads'] <= 0) {
                            $hasFile = !empty($data['file_path']) && file_exists($data['file_path']);
                            if ($viewState === 'view' && $hasFile) {
                                ftruncate($fp, 0); rewind($fp);
                                fwrite($fp, json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
                            } else {
                                $shouldBurn = true;
                            }
                        } else {
                            ftruncate($fp, 0); rewind($fp);
                            fwrite($fp, json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
                        }
                    }
                } else {
                    $viewState = 'password';
                    app_log('VISIT_GATE', "FileID: $reqFile");
                }
            }
            
            if ($shouldBurn) {
                if (isset($data['file_path']) && file_exists($data['file_path'])) unlink($data['file_path']);
                ftruncate($fp, 0); 
            }
            
            flock($fp, LOCK_UN);
            fclose($fp);
            
            if ($shouldBurn) {
                unlink($file);
                if ($viewState !== 'error' && $viewState !== 'downloaded') app_log('BURN', "FileID: $reqFile");
            }
            if ($viewState === 'downloaded') exit;
        } else {
            die($L['err_sys']);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?php echo $langCode; ?>" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $L['app_title']; ?></title>
    <link rel="icon" href="<?php echo $env['SITE_ICON']; ?>">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = { darkMode: 'class' }</script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"/>
    <style>
        body { font-family: 'Inter', sans-serif; background: url('<?php echo $env['SITE_BACKGROUND']; ?>') no-repeat center center fixed; background-size: cover; color: #1f2937; transition: color 0.3s; }
        .glass { 
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.40), rgba(240, 253, 244, 0.60));
            backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); 
            border: 1px solid rgba(255, 255, 255, 0.5); 
            box-shadow: 0 10px 40px rgba(20, 83, 45, 0.1), 0 4px 10px rgba(0,0,0,0.05); 
        }
        .dark .glass { 
            background: linear-gradient(135deg, rgba(20, 30, 25, 0.70), rgba(6, 78, 59, 0.40));
            border: 1px solid rgba(255, 255, 255, 0.08); color: #ecfccb; 
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
        }
        .glass-input { 
            color: #1f2937; background: rgba(255, 255, 255, 0.4); 
            border: 1px solid rgba(200, 200, 200, 0.4); transition: all 0.2s; 
        }
        .glass-input:focus { 
            background: rgba(255, 255, 255, 0.8); border-color: #84cc16; 
            box-shadow: 0 0 0 3px rgba(132, 204, 22, 0.2); 
        }
        .dark .glass-input { 
            color: #f3f4f6; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); 
        }
        .dark .glass-input:focus { 
            background: rgba(20, 30, 20, 0.7); border-color: #4ade80; 
            box-shadow: 0 0 0 3px rgba(74, 222, 128, 0.2);
        }
        .fire-icon {
            display: inline-block; font-size: 2.2rem;
            background: linear-gradient(to top, #f59e0b 20%, #ef4444 80%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            filter: drop-shadow(0 0 4px rgba(245, 158, 11, 0.5));
            animation: burn 1.8s infinite alternate ease-in-out; transform-origin: center bottom;
        }
        @keyframes burn { 0% { transform: scale(1) rotate(-2deg); filter: drop-shadow(0 0 2px rgba(245, 158, 11, 0.3)); } 100% { transform: scale(1.15) rotate(2deg); filter: drop-shadow(0 0 10px rgba(239, 68, 68, 0.7)) brightness(1.2); } }
        .ctrl-btn { @apply w-8 h-8 flex items-center justify-center rounded-full transition-all hover:bg-black/5 dark:hover:bg-white/10 active:scale-95 text-gray-500 dark:text-gray-400; }
        .pass-btn { @apply w-7 h-7 flex items-center justify-center rounded-md text-gray-400 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-900/30 transition-all cursor-pointer active:scale-95; }
        .btn-act { @apply w-7 h-7 flex items-center justify-center rounded bg-gray-200/40 text-gray-500 hover:bg-gray-300/50 hover:text-gray-700 dark:bg-black/20 dark:text-gray-400 dark:hover:bg-white/10 dark:hover:text-gray-200 transition-colors cursor-pointer; }
        ::-webkit-scrollbar { width: 4px; height: 4px; } ::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.2); border-radius: 2px; }
        .markdown-body blockquote { border-left: 3px solid #84cc16; padding-left: 0.8rem; color: #64748b; }
        .markdown-body pre { background: rgba(0,0,0,0.05); padding: 0.8rem; border-radius: 0.5rem; overflow-x: auto; }
        .dark .markdown-body pre { background: rgba(0,0,0,0.4); }
        .urgent-pulse { font-size: 3.5rem; color: #ef4444; font-weight: 800; animation: ping-text 1s cubic-bezier(0, 0, 0.2, 1) infinite; }
        @keyframes ping-text { 50% { transform: scale(1.1); opacity: 0.8; } }
    </style>
</head>
<body class="min-h-screen flex flex-col text-gray-800 dark:text-gray-100">

<div class="flex-grow flex items-center justify-center p-4">
    <div class="w-full max-w-6xl">
    <?php 
    function renderTools($L, $langCode) {
        $nextLang = $langCode==='cn'?'en':'cn';
        return "<div class='flex items-center gap-3 ml-2 pl-2'>
            <button type='button' onclick='toggleTheme()' class='ctrl-btn' title='Toggle Theme'><i class='fas fa-sun text-[16px] dark:hidden'></i><i class='fas fa-moon text-[16px] hidden dark:block'></i></button>
            <a href='?lang=$nextLang' class='ctrl-btn no-underline' title='Switch Language'><i class='fas fa-language text-[18px]'></i></a>
        </div>";
    }
    ?>

    <?php if ($viewState === 'success'): ?>
        <div class="glass rounded-2xl p-8 max-w-xl mx-auto text-center animate-fade-in border-0 overflow-hidden relative">
            <div class="absolute -top-10 -right-10 w-32 h-32 bg-lime-400/20 rounded-full blur-2xl"></div>
            <div class="relative z-10">
                <div class="w-16 h-16 mx-auto mb-4 flex items-center justify-center bg-white/50 dark:bg-lime-900/30 rounded-full shadow-sm"><i class="fas fa-check text-3xl text-emerald-500"></i></div>
                <h2 class="text-2xl font-bold mb-1 text-emerald-900 dark:text-lime-100"><?php echo $L['ready']; ?></h2>
                <p class="text-emerald-800/70 dark:text-lime-200/70 text-xs mb-6"><?php echo sprintf($L['ready_desc'], $limit); ?></p>
                <div class="bg-white/40 dark:bg-black/30 border border-lime-200/50 dark:border-lime-800/30 rounded-xl p-3 mb-6 font-mono text-xs text-emerald-800 dark:text-lime-300 break-all select-all shadow-inner relative group"><?php echo $link; ?></div>
                <div class="flex gap-3 justify-center">
                    <button onclick="copyLink('<?php echo $link; ?>')" class="bg-gradient-to-r from-emerald-500 to-lime-500 hover:from-emerald-400 hover:to-lime-400 text-white px-6 py-2.5 rounded-lg text-xs font-bold shadow-lg shadow-emerald-500/20 active:scale-95 transition-all w-full flex items-center justify-center gap-2"><i class="fas fa-copy"></i> <?php echo $L['copy']; ?></button>
                    <a href="<?php echo $selfUrl; ?>" class="px-6 py-2.5 rounded-lg text-xs font-bold text-emerald-800 bg-lime-100/50 hover:bg-lime-100 transition-colors w-1/3 text-center"><?php echo $L['back']; ?></a>
                </div>
            </div>
        </div>

    <?php elseif ($viewState === 'error'): ?>
        <div class="glass rounded-2xl p-10 max-w-md mx-auto text-center animate-fade-in relative overflow-hidden">
            <div class="relative z-10">
                <div class="mb-6 inline-flex items-center justify-center w-20 h-20 rounded-full bg-red-50/50 dark:bg-red-900/20"><i class="fas fa-link-slash text-4xl text-red-400/80"></i></div>
                <h2 class="text-2xl font-bold mb-2"><?php echo $L['msg_404']; ?></h2>
                <p class="text-xs text-gray-500 dark:text-gray-400 mb-8 leading-relaxed"><?php echo $L['msg_404_desc']; ?></p>
                <a href="<?php echo $selfUrl; ?>" class="inline-flex items-center gap-2 glass px-8 py-3 rounded-full text-emerald-600 dark:text-lime-400 text-sm font-bold hover:bg-white/60 dark:hover:bg-black/20 transition-all hover:scale-105 shadow-sm"><i class="fas fa-house"></i> <?php echo $L['back']; ?></a>
            </div>
        </div>

    <?php elseif ($viewState === 'wait'): ?>
        <div class="glass rounded-2xl p-10 max-w-md mx-auto text-center animate-fade-in relative overflow-hidden">
            <div class="relative z-10">
                <div class="mb-6 animate-pulse"><i class="fas fa-hourglass-half text-6xl text-yellow-500"></i></div>
                <h2 class="text-2xl font-bold mb-2"><?php echo $L['wait_msg']; ?></h2>
                <p class="text-xs text-gray-500 dark:text-gray-400 mb-8 leading-relaxed">
                    <?php echo $L['wait_desc']; ?> <span id="cd-timer" class="font-bold">...</span>
                </p>
                <a href="<?php echo $selfUrl; ?>" class="inline-flex items-center gap-2 glass px-8 py-3 rounded-full text-gray-600 text-sm font-bold hover:bg-white/60 transition-all hover:scale-105 shadow-sm"><?php echo $L['back']; ?></a>
            </div>
        </div>
        <script>
            let sec = <?php echo $waitSecs; ?>;
            function upT() {
                sec--;
                const el = document.getElementById('cd-timer');
                if (sec <= 0) { location.reload(); return; }
                if (sec > 60) {
                    let d = Math.floor(sec/86400), h = Math.floor((sec%86400)/3600), m = Math.floor((sec%3600)/60);
                    el.innerHTML = `${d}d ${h}h ${m}m`;
                } else {
                    el.innerHTML = sec + 's';
                    if (sec <= 10) { el.className = 'urgent-pulse block mt-2'; }
                }
            }
            setInterval(upT, 1000); upT();
        </script>

    <?php elseif ($viewState === 'view'): ?>
        <div class="glass rounded-2xl w-full max-w-4xl h-[600px] flex flex-col relative overflow-hidden mx-auto">
            <div class="px-6 py-4 flex justify-between items-center z-10">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400 to-lime-400 text-white flex items-center justify-center shadow-lg shadow-emerald-500/10"><i class="fas fa-user-secret"></i></div>
                    <div><div class="font-bold text-sm"><?php echo $name ?: 'Anonymous'; ?></div><?php if($note): ?><div class="text-[10px] text-gray-600 dark:text-gray-400"><?php echo htmlspecialchars($note); ?></div><?php endif; ?></div>
                </div>
                <div class="flex items-center gap-2">
                    <div class="px-2 py-1 rounded text-[10px] font-bold border border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-lime-300"><?php echo sprintf($L['left'], max(0, $data['reads'])); ?></div>
                    <?php echo renderTools($L, $langCode); ?>
                </div>
            </div>
            <div class="flex-1 overflow-y-auto p-6 relative">
                <?php if(isset($fileReady)): ?>
                <div class="mb-6 p-3 rounded-xl bg-gradient-to-r from-emerald-50/50 to-lime-50/50 dark:from-emerald-900/20 dark:to-lime-900/20 border border-emerald-100/50 dark:border-lime-800/30 flex items-center justify-between shadow-sm animate-pulse">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-full bg-emerald-100 dark:bg-emerald-800 flex items-center justify-center text-emerald-600 dark:text-emerald-300 text-sm"><i class="fas fa-file-arrow-down"></i></div>
                        <div><div class="font-bold text-xs text-emerald-900 dark:text-lime-200"><?php echo $L['file_ready']; ?></div><div class="text-[10px] text-emerald-600 dark:text-lime-400 max-w-[150px] truncate"><?php echo htmlspecialchars($fileName); ?></div></div>
                    </div>
                    <form method="post" action="<?php echo $selfUrl; ?>?file=<?php echo urlencode($reqFile); ?>&code=<?php echo urlencode($_GET['code']); ?>&download=1" target="_blank">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <?php if($passReq): ?><input type="hidden" name="pass" value="<?php echo htmlspecialchars($userPass); ?>"><?php endif; ?>
                        <button type="submit" class="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white text-[10px] font-bold rounded-lg shadow-lg shadow-emerald-500/20 transition-all flex items-center gap-1 cursor-pointer"><i class="fas fa-download"></i> <?php echo $L['download']; ?></button>
                    </form>
                </div>
                <?php endif; ?>
                <div class="markdown-body text-sm leading-relaxed" id="content-view"></div>
                <textarea id="raw-content" class="hidden"><?php echo htmlspecialchars($msg); ?></textarea>
            </div>
        </div>
        <script>document.getElementById('content-view').innerHTML = DOMPurify.sanitize(marked.parse(document.getElementById('raw-content').value), {FORBID_TAGS: ['img']});</script>

    <?php elseif ($viewState === 'password'): ?>
        <div class="glass rounded-2xl p-10 max-w-md mx-auto text-center relative">
            <div class="absolute top-4 right-4"><?php echo renderTools($L, $langCode); ?></div>
            <div class="mb-4 inline-block"><i class="fas <?php echo $passReq?'fa-lock':'fa-shield-halved'; ?> text-5xl bg-clip-text text-transparent bg-gradient-to-br from-emerald-500 to-lime-500 pb-1"></i></div>
            <h2 class="text-xl font-bold mb-1"><?php echo $passReq ? $L['pass_req'] : $L['msg_view']; ?></h2>
            <p class="text-xs text-gray-500 mb-6"><?php echo sprintf($L['left'], $data['reads']); ?></p>
            <?php if(isset($err)) echo "<div class='text-red-500 text-[10px] mb-4 bg-red-50/50 dark:bg-red-900/30 py-1.5 rounded font-medium'>$err</div>"; ?>
            <form method="post" action="<?php echo $selfUrl; ?>?file=<?php echo urlencode($reqFile); ?>&code=<?php echo urlencode($_GET['code']); ?>&confirm=1">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <?php if($passReq): ?>
                    <input type="password" name="pass" class="glass-input w-full px-4 py-2.5 rounded-xl mb-4 text-center outline-none text-base tracking-widest" placeholder="••••••" required autofocus>
                <?php endif; ?>
                <button class="w-full bg-gradient-to-r from-emerald-500 to-lime-500 hover:from-emerald-600 hover:to-lime-600 text-white py-2.5 rounded-xl font-bold shadow-lg shadow-emerald-500/25 transition-all"><?php echo $passReq ? $L['unlock'] : $L['msg_view']; ?></button>
            </form>
        </div>

    <?php else: ?>
        <form method="post" enctype="multipart/form-data" class="grid grid-cols-1 lg:grid-cols-12 gap-4 w-full h-auto lg:h-[600px]">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            
            <div class="lg:col-span-4 flex flex-col h-full">
                <div class="glass rounded-2xl p-5 h-full flex flex-col shadow-lg">
                    <div class="flex items-center gap-3 mb-4 shrink-0">
                        <i class="fas fa-fire fire-icon"></i>
                        <div><h1 class="font-bold text-lg leading-tight"><?php echo $L['app_title']; ?></h1><p class="text-[10px] text-gray-500"><?php echo $L['subtitle']; ?></p></div>
                    </div>
                    
                    <div class="flex-1 overflow-y-auto pr-1 space-y-3 custom-scroll">
                        <div class="space-y-2">
                            <label class="text-[9px] font-bold text-gray-600 dark:text-gray-400 uppercase tracking-widest ml-1"><?php echo $L['sec_info']; ?></label>
                            <div class="grid grid-cols-2 gap-2">
                                <div class="relative w-full">
                                    <div class="absolute inset-y-0 left-0 flex items-center pl-2.5 pointer-events-none text-gray-500 dark:text-gray-400 text-xs"><i class="fas fa-user"></i></div>
                                    <input type="text" name="name" maxlength="64" class="glass-input w-full pl-8 pr-2 h-9 rounded-lg text-xs" placeholder="<?php echo $L['nickname']; ?>">
                                </div>
                                <div class="relative w-full">
                                    <div class="absolute inset-y-0 left-0 flex items-center pl-2.5 pointer-events-none text-gray-500 dark:text-gray-400 text-xs"><i class="fas fa-tag"></i></div>
                                    <input type="text" name="note" maxlength="128" class="glass-input w-full pl-8 pr-2 h-9 rounded-lg text-xs" placeholder="<?php echo $L['note']; ?>">
                                </div>
                            </div>
                        </div>
                        <div class="space-y-1.5">
                            <label class="text-[9px] font-bold text-gray-600 dark:text-gray-400 uppercase tracking-widest ml-1"><?php echo $L['sec_safe']; ?></label>
                            
                            <div class="relative group w-full mb-1">
                                <div class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-gray-500 dark:text-gray-400 text-xs"><i class="fas fa-key"></i></div>
                                <input type="password" id="passInput" name="pass" maxlength="64" class="glass-input w-full pl-9 pr-20 h-9 rounded-lg text-xs font-mono" placeholder="<?php echo $L['pass_set']; ?>">
                                <div class="absolute inset-y-0 right-0 flex items-center pr-2 gap-2">
                                    <button type="button" onclick="genPass()" class="pass-btn" title="<?php echo $L['gen_pass']; ?>"><i class="fas fa-wand-magic-sparkles text-[10px]"></i></button>
                                    <button type="button" onclick="togglePass()" class="pass-btn" title="<?php echo $L['toggle_pass']; ?>"><i class="fas fa-eye text-[10px]" id="eyeIcon"></i></button>
                                </div>
                            </div>
                            <div class="bg-white/40 dark:bg-black/20 rounded-xl p-2 border border-white/20 dark:border-gray-700/30 space-y-2">
                                <div>
                                    <div class="flex justify-between text-[10px] mb-1 px-1 font-medium text-gray-600 dark:text-gray-300"><span><?php echo $L['reads']; ?></span><span class="text-[9px] text-emerald-600"><?php echo sprintf($L['max_limit'], $maxReads); ?></span></div>
                                    <div class="flex items-center gap-1.5">
                                        <button type="button" onclick="setRead(1)" class="btn-act" title="<?php echo $L['tip_min']; ?>"><i class="fas fa-backward-step text-[10px]"></i></button>
                                        <button type="button" onclick="adjLimit(-1)" class="btn-act"><i class="fas fa-minus text-[10px]"></i></button>
                                        <input type="number" id="limitInput" name="limit" value="1" class="glass-input flex-1 h-8 text-center text-xs font-bold rounded">
                                        <button type="button" onclick="adjLimit(1)" class="btn-act"><i class="fas fa-plus text-[10px]"></i></button>
                                        <button type="button" onclick="setRead(<?php echo $maxReads; ?>)" class="btn-act" title="<?php echo $L['tip_max']; ?>"><i class="fas fa-forward-step text-[10px]"></i></button>
                                    </div>
                                </div>
                                <div>
                                    <div class="flex justify-between text-[10px] mb-1 px-1 font-medium text-gray-600 dark:text-gray-300"><span><?php echo $L['expiry']; ?></span><span class="text-[9px] text-gray-400"><?php echo sprintf($L['max_time'], ''); ?></span></div>
                                    <div class="flex items-center gap-1">
                                        <div class="relative flex-1"><input type="number" id="ed" name="ed" value="7" class="glass-input w-full h-8 text-center text-[10px] rounded font-mono pr-4"><div class="absolute inset-y-0 right-0 flex items-center pr-1 pointer-events-none"><span class="text-[8px] text-gray-400 font-bold">D</span></div></div>
                                        <div class="relative flex-1"><input type="number" id="eh" name="eh" placeholder="0" class="glass-input w-full h-8 text-center text-[10px] rounded font-mono pr-4"><div class="absolute inset-y-0 right-0 flex items-center pr-1 pointer-events-none"><span class="text-[8px] text-gray-400 font-bold">H</span></div></div>
                                        <div class="relative flex-1"><input type="number" id="em" name="em" placeholder="0" class="glass-input w-full h-8 text-center text-[10px] rounded font-mono pr-4"><div class="absolute inset-y-0 right-0 flex items-center pr-1 pointer-events-none"><span class="text-[8px] text-gray-400 font-bold">M</span></div></div>
                                        <button type="button" onclick="setMaxTime()" class="btn-act ml-0.5" title="<?php echo $L['tip_max']; ?>"><i class="fas fa-bolt text-[10px]"></i></button>
                                    </div>
                                </div>
                                <div>
                                    <div class="flex justify-between text-[10px] mb-1 px-1 font-medium text-gray-600 dark:text-gray-300"><span><?php echo $L['delay']; ?></span><span class="text-[9px] text-gray-400"><?php echo sprintf($L['max_delay'], ''); ?></span></div>
                                    <div class="flex items-center gap-1">
                                        <div class="relative flex-1"><input type="number" id="dd" name="dd" placeholder="0" class="glass-input w-full h-8 text-center text-[10px] rounded font-mono pr-4"><div class="absolute inset-y-0 right-0 flex items-center pr-1 pointer-events-none"><span class="text-[8px] text-gray-400 font-bold">D</span></div></div>
                                        <div class="relative flex-1"><input type="number" id="dh" name="dh" placeholder="0" class="glass-input w-full h-8 text-center text-[10px] rounded font-mono pr-4"><div class="absolute inset-y-0 right-0 flex items-center pr-1 pointer-events-none"><span class="text-[8px] text-gray-400 font-bold">H</span></div></div>
                                        <div class="relative flex-1"><input type="number" id="dm" name="dm" placeholder="0" class="glass-input w-full h-8 text-center text-[10px] rounded font-mono pr-4"><div class="absolute inset-y-0 right-0 flex items-center pr-1 pointer-events-none"><span class="text-[8px] text-gray-400 font-bold">M</span></div></div>
                                        <button type="button" onclick="resetDelay()" class="btn-act ml-0.5" title="<?php echo $L['tip_reset']; ?>"><i class="fas fa-rotate-left text-[10px]"></i></button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="pt-1">
                            <label class="text-[9px] font-bold text-gray-600 dark:text-gray-400 uppercase tracking-widest ml-1 mb-1 block"><?php echo $L['upload_label']; ?></label>
                            <div class="relative glass-input flex items-center gap-2 p-2 h-9 rounded-lg hover:bg-white/60 dark:hover:bg-black/40 transition-colors group cursor-pointer">
                                <div class="text-gray-400 dark:text-gray-500 group-hover:text-emerald-500 transition-colors p-1"><i class="fas fa-paperclip text-sm"></i></div>
                                <div id="fname" class="text-[10px] font-medium truncate opacity-70 flex-1"><?php echo $L['select_file']; ?></div>
                                <input type="file" name="file" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" onchange="document.getElementById('fname').innerText = this.files[0]?.name || '<?php echo $L['select_file']; ?>'">
                            </div>
                            <p class="text-[8px] text-gray-400 mt-1 ml-1 leading-tight"><?php echo sprintf($L['upload_hint'], $uploadMaxMB, implode(', ', $allowedExts)); ?></p>
                        </div>
                    </div>
                    <button class="w-full bg-gradient-to-r from-emerald-500 to-lime-600 hover:from-emerald-400 hover:to-lime-500 text-white py-3 rounded-xl font-bold mt-3 shadow-lg shadow-emerald-500/30 flex items-center justify-center gap-2 transition-all transform hover:-translate-y-0.5 text-sm shrink-0 border border-white/10"><i class="fas fa-lock"></i> <?php echo $L['gen_btn']; ?></button>
                </div>
            </div>
            <div class="lg:col-span-8 h-[500px] lg:h-full">
                <div class="glass rounded-2xl h-full flex flex-col p-1 relative overflow-hidden shadow-xl">
                    <div class="flex justify-between items-center px-5 py-3 z-20 relative">
                        <div class="bg-gray-200/40 dark:bg-black/20 rounded-full p-1 flex">
                            <button type="button" onclick="tab('edit')" id="btn-edit" class="px-4 py-1.5 rounded-full text-[10px] font-bold transition-all shadow-sm bg-white dark:bg-gray-600 text-emerald-600 dark:text-emerald-300"><?php echo $L['edit']; ?></button>
                            <button type="button" onclick="tab('prev')" id="btn-prev" class="px-4 py-1.5 rounded-full text-[10px] font-medium text-gray-500 dark:text-gray-400 hover:text-gray-700 transition-all"><?php echo $L['preview']; ?></button>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-[9px] font-bold text-gray-600 dark:text-gray-400 uppercase tracking-widest hidden sm:inline mr-2"><i class="fab fa-markdown mr-1"></i>Markdown</span>
                            <?php echo renderTools($L, $langCode); ?>
                        </div>
                    </div>
                    <div class="flex-1 relative group mt-1">
                        <textarea name="message" id="editor" maxlength="200000" class="absolute inset-0 w-full h-full bg-transparent p-6 outline-none resize-none text-gray-700 dark:text-gray-200 font-mono text-xs leading-relaxed" placeholder="<?php echo $L['placeholder']; ?>"></textarea>
                        <div id="preview" class="hidden absolute inset-0 w-full h-full bg-white/40 dark:bg-black/20 backdrop-blur-md p-6 overflow-y-auto markdown-body"></div>
                    </div>
                </div>
            </div>
        </form>
    <?php endif; ?>
    </div>
</div>

<footer class="py-4 text-center text-[10px] text-white/90 font-medium flex items-center justify-center gap-2 drop-shadow-[0_1px_2px_rgba(0,0,0,0.5)] z-20">
    <div class="px-4 py-1.5 bg-black/20 rounded-full backdrop-blur-sm flex items-center gap-3 shadow-2xl hover:bg-black/30 transition-all">
        <span>&copy; <?php echo date('Y'); ?> BurnRead Prince</span><span class="opacity-50">|</span>
        <a href="https://github.com/Andeasw/BurnRead" target="_blank" class="hover:scale-110 transition opacity-70 hover:opacity-100 text-white drop-shadow-md"><i class="fab fa-github"></i></a>
    </div>
</footer>

<script>
    const maxR = <?php echo $maxReads; ?>;
    function setRead(v) { document.getElementById('limitInput').value = v; }
    function adjLimit(d) { let el = document.getElementById('limitInput'); let v = parseInt(el.value)+d; el.value = Math.min(Math.max(v,1), maxR); }
    function setMaxTime() { document.getElementById('ed').value=<?php echo $maxExp; ?>; document.getElementById('eh').value=0; document.getElementById('em').value=0; }
    function resetDelay() { document.getElementById('dd').value=0; document.getElementById('dh').value=0; document.getElementById('dm').value=0; }
    
    function copyLink(txt) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(txt).then(() => alert('<?php echo $L['copied']; ?>')).catch(() => fallbackCopy(txt));
        } else { fallbackCopy(txt); }
    }
    function fallbackCopy(txt) {
        let ta = document.createElement("textarea"); ta.value = txt; ta.style.position = "fixed"; ta.style.left = "-9999px";
        document.body.appendChild(ta); ta.focus(); ta.select();
        try { document.execCommand('copy'); alert('<?php echo $L['copied']; ?>'); } catch (err) {}
        document.body.removeChild(ta);
    }
    function toggleTheme() { const h = document.documentElement; h.classList.contains('dark') ? (h.classList.remove('dark'),localStorage.setItem('t','l')) : (h.classList.add('dark'),localStorage.setItem('t','d')); }
    
    const defT = "<?php echo $env['DEFAULT_THEME']; ?>";
    if (localStorage.t) { if(localStorage.t==='d') document.documentElement.classList.add('dark'); }
    else if (defT === 'dark' || (defT === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) { document.documentElement.classList.add('dark'); }
    
    function tab(t) {
        const ed=document.getElementById('editor'), pr=document.getElementById('preview'), be=document.getElementById('btn-edit'), bp=document.getElementById('btn-prev');
        const act='px-4 py-1.5 rounded-full text-[10px] font-bold transition-all shadow-sm bg-white dark:bg-gray-600 text-emerald-600 dark:text-emerald-300', inact='px-4 py-1.5 rounded-full text-[10px] font-medium text-gray-500 dark:text-gray-400 hover:text-gray-700 transition-all';
        if(t==='edit') { ed.classList.remove('hidden'); pr.classList.add('hidden'); be.className=act; bp.className=inact; }
        else { ed.classList.add('hidden'); pr.classList.remove('hidden'); 
            const clean = DOMPurify.sanitize(marked.parse(ed.value), {FORBID_TAGS: ['img']});
            pr.innerHTML=clean; 
            bp.className=act; be.className=inact; }
    }
    function genPass() {
        const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"; let pass = "";
        for(let i=0;i<16;i++) pass += chars.charAt(Math.floor(Math.random() * chars.length));
        document.getElementById('passInput').type='text'; document.getElementById('passInput').value=pass; document.getElementById('eyeIcon').classList.replace('fa-eye','fa-eye-slash');
    }
    function togglePass() {
        const el = document.getElementById('passInput'); const icon = document.getElementById('eyeIcon');
        if (el.type === "password") { el.type = "text"; icon.classList.replace('fa-eye', 'fa-eye-slash'); }
        else { el.type = "password"; icon.classList.replace('fa-eye-slash', 'fa-eye'); }
    }
    document.getElementById('editor')?.addEventListener('keydown', function(e) { if (e.key == 'Tab') { e.preventDefault(); this.setRangeText("\t", this.selectionStart, this.selectionStart, "end"); } });
</script>
</body>
</html>