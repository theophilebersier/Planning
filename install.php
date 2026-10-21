<?php
declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';
require __DIR__ . '/lib/views.php';

send_security_headers();
header('Cache-Control: no-store');

$problems = [];
if (!extension_loaded('pdo_sqlite')) {
    $problems[] = 'L’extension PHP « pdo_sqlite » n’est pas active. Dans le Manager Infomaniak, ouvrez votre site, puis Gestion PHP, et activez-la.';
}
if (!$problems) {
    try {
        db();
    } catch (Throwable $ex) {
        $problems[] = 'La base de données ne peut pas être créée : ' . $ex->getMessage();
    }
}
if ($problems) {
    render_simple_page('Installation impossible', '<ul class="authlist"><li>' . implode('</li><li>', array_map('e', $problems)) . '</li></ul><p>Corrigez le point ci-dessus puis rechargez cette page.</p>');
    exit;
}

// Mot de passe oublié : déposer par FTP un fichier vide nommé RESET_PASSWORD dans le dossier data,
// puis renvoyer install.php sur le serveur et ouvrir cette page.
$resetFlag = DATA_DIR . '/RESET_PASSWORD';
if (admin_exists() && is_file($resetFlag)) {
    start_session();
    if (empty($_SESSION['reset_csrf'])) {
        $_SESSION['reset_csrf'] = bin2hex(random_bytes(16));
    }
    $admin = db()->query("SELECT * FROM users WHERE role = 'admin' AND active = 1 ORDER BY id LIMIT 1")->fetch();
    $rerr = '';
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        $pw = (string)($_POST['password'] ?? '');
        if (!hash_equals((string)$_SESSION['reset_csrf'], (string)($_POST['csrf'] ?? ''))) {
            $rerr = 'Le formulaire a expiré. Réessayez.';
        } elseif (str_len($pw) < 10) {
            $rerr = 'Le mot de passe doit avoir au moins 10 caractères.';
        } elseif ($pw !== (string)($_POST['password2'] ?? '')) {
            $rerr = 'Les deux mots de passe ne sont pas identiques.';
        } else {
            db()->prepare('UPDATE users SET password_hash = ?, epoch = epoch + 1 WHERE id = ?')->execute([password_hash($pw, PASSWORD_DEFAULT), (int)$admin['id']]);
            @unlink($resetFlag);
            $deleted = @unlink(__FILE__);
            render_simple_page('Mot de passe changé', '<p>Connectez-vous avec ' . e((string)$admin['email']) . ' et le nouveau mot de passe.</p>'
                . ($deleted ? '' : '<p class="autherr">Supprimez maintenant install.php du serveur.</p>')
                . '<p><a class="btn pri" href="' . e(app_path()) . '">Ouvrir le planning</a></p>');
            exit;
        }
    }
    render_simple_page('Nouveau mot de passe', '<p class="authsub">Compte : ' . e((string)$admin['email']) . '</p>'
        . ($rerr !== '' ? '<p class="autherr" role="alert">' . e($rerr) . '</p>' : '')
        . '<form method="post" class="authform">'
        . '<input type="hidden" name="csrf" value="' . e((string)$_SESSION['reset_csrf']) . '">'
        . '<label>Nouveau mot de passe (10 caractères minimum)<input type="password" name="password" autocomplete="new-password" required minlength="10"></label>'
        . '<label>Répétez le mot de passe<input type="password" name="password2" autocomplete="new-password" required minlength="10"></label>'
        . '<button class="btn pri" type="submit">Changer le mot de passe</button></form>');
    exit;
}

if (admin_exists()) {
    render_simple_page('Le planning est déjà installé', '<p><a class="btn pri" href="' . e(app_path()) . '">Ouvrir le planning</a></p><p class="authsub">Par sécurité, supprimez le fichier install.php du serveur s’il est encore là.</p>');
    exit;
}

start_session();
if (empty($_SESSION['install_csrf'])) {
    $_SESSION['install_csrf'] = bin2hex(random_bytes(16));
}

$error = '';
$name = 'Papa';
$email = '';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $name = trim((string)($_POST['name'] ?? ''));
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $pw = (string)($_POST['password'] ?? '');
    $pw2 = (string)($_POST['password2'] ?? '');
    if (!hash_equals((string)$_SESSION['install_csrf'], (string)($_POST['csrf'] ?? ''))) {
        $error = 'Le formulaire a expiré. Réessayez.';
    } elseif ($name === '' || str_len($name) > 60) {
        $error = 'Indiquez votre nom.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Cette adresse email n’est pas valable.';
    } elseif (str_len($pw) < 10) {
        $error = 'Le mot de passe doit avoir au moins 10 caractères.';
    } elseif ($pw !== $pw2) {
        $error = 'Les deux mots de passe ne sont pas identiques.';
    } else {
        $pdo = db();
        $pdo->prepare('INSERT INTO users (name, email, password_hash, role, active, created_at) VALUES (?, ?, ?, \'admin\', 1, ?)')
            ->execute([$name, $email, password_hash($pw, PASSWORD_DEFAULT), now_iso()]);
        $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
        $st->execute([(int)$pdo->lastInsertId()]);
        login_user($st->fetch());
        $deleted = @unlink(__FILE__);
        render_simple_page('C’est prêt', '<p>Votre compte administrateur est créé.</p>'
            . ($deleted
                ? '<p class="authsub">Le fichier d’installation a été supprimé automatiquement.</p>'
                : '<p class="autherr">Supprimez maintenant le fichier install.php du serveur (gestionnaire de fichiers ou FTP).</p>')
            . '<p><a class="btn pri" href="' . e(app_path()) . '">Ouvrir le planning</a></p>');
        exit;
    }
}

$err = $error !== '' ? '<p class="autherr" role="alert">' . e($error) . '</p>' : '';
render_simple_page('Installation du planning', '<p class="authsub">Créez le compte de la personne qui gère le planning. Il aura tous les droits. Les autres personnes recevront plus tard un lien personnel.</p>'
    . $err
    . '<form method="post" class="authform">'
    . '<input type="hidden" name="csrf" value="' . e((string)$_SESSION['install_csrf']) . '">'
    . '<label>Votre nom<input type="text" name="name" value="' . e($name) . '" required maxlength="60"></label>'
    . '<label>Email<input type="email" name="email" value="' . e($email) . '" autocomplete="username" required></label>'
    . '<label>Mot de passe (10 caractères minimum)<input type="password" name="password" autocomplete="new-password" required minlength="10"></label>'
    . '<label>Répétez le mot de passe<input type="password" name="password2" autocomplete="new-password" required minlength="10"></label>'
    . '<button class="btn pri" type="submit">Créer mon compte</button>'
    . '</form>');
