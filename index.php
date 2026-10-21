<?php
declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';
require __DIR__ . '/lib/views.php';

send_security_headers();
header('Cache-Control: no-store');

try {
    $pdo = db();
} catch (Throwable $ex) {
    error_log('[garde] ' . $ex->getMessage());
    render_simple_page('Le planning ne démarre pas', '<p>' . e($ex->getMessage()) . '</p><p>Consultez le fichier INSTALLATION.md, étape « Si quelque chose ne marche pas ».</p>');
    exit;
}

if (!admin_exists()) {
    header('Location: ' . app_path() . 'install.php');
    exit;
}

$error = '';

// Lien personnel : https://.../?k=XXXX
if (isset($_GET['k'])) {
    $token = (string)$_GET['k'];
    $u = find_user_by_token($token);
    if ($u) {
        login_user($u);
        set_token_cookie($token);
        header('Location: ' . app_path());
        exit;
    }
    $error = 'Ce lien n’est plus valable. Demandez un nouveau lien à la personne qui gère le planning.';
}

if (isset($_GET['logout'])) {
    logout_user();
    header('Location: ' . app_path());
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['action'] ?? '') === 'login') {
    start_session();
    $ip = client_ip();
    if (!hash_equals((string)($_SESSION['login_csrf'] ?? ''), (string)($_POST['csrf'] ?? ''))) {
        $error = 'Le formulaire a expiré. Réessayez.';
    } elseif (too_many_attempts($ip)) {
        $error = 'Trop d’essais. Attendez 15 minutes avant de réessayer.';
    } else {
        $email = strtolower(trim((string)($_POST['email'] ?? '')));
        $pw = (string)($_POST['password'] ?? '');
        $st = $pdo->prepare('SELECT * FROM users WHERE email = ? AND active = 1 AND password_hash IS NOT NULL');
        $st->execute([$email]);
        $u = $st->fetch();
        if ($u && password_verify($pw, (string)$u['password_hash'])) {
            clear_attempts($ip);
            login_user($u);
            header('Location: ' . app_path());
            exit;
        }
        record_attempt($ip);
        $error = 'Email ou mot de passe incorrect.';
    }
}

$user = current_user();
if (!$user) {
    render_login($error);
    exit;
}

header('X-Garde-App: 1');
render_app();
