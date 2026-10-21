<?php
declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

send_security_headers();
header('Cache-Control: no-store');

function need_admin(array $user): void
{
    if ($user['role'] !== 'admin') {
        json_out(['error' => 'Seul l’administrateur peut faire cela.'], 403);
    }
}

function need_post(bool $isPost): void
{
    if (!$isPost) {
        json_out(['error' => 'Méthode non autorisée.'], 405);
    }
}

function user_json(array $u): array
{
    return [
        'id' => (int)$u['id'],
        'name' => (string)$u['name'],
        'email' => $u['email'],
        'role' => (string)$u['role'],
        'active' => (int)$u['active'] === 1,
        'has_link' => !empty($u['token_hash']),
        'has_password' => !empty($u['password_hash']),
        'last_seen' => $u['last_seen'],
    ];
}

function person_json(array $p): array
{
    return [
        'id' => (int)$p['id'],
        'name' => (string)$p['name'],
        'color' => (string)$p['color'],
        'sort' => (int)$p['sort'],
        'active' => (int)$p['active'] === 1,
    ];
}

try {
    $user = current_user();
    if (!$user) {
        json_out(['error' => 'Votre session a expiré. Rechargez la page pour vous reconnecter.'], 401);
    }
    $pdo = db();
    $action = (string)($_GET['a'] ?? '');
    $isPost = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
    $in = [];
    if ($isPost) {
        if (!csrf_ok()) {
            json_out(['error' => 'La page a expiré. Rechargez-la puis réessayez.'], 403);
        }
        $raw = file_get_contents('php://input');
        $in = json_decode($raw === false || $raw === '' ? 'null' : $raw, true);
        if (!is_array($in)) {
            json_out(['error' => 'Requête invalide.'], 400);
        }
    }

    switch ($action) {

        case 'boot':
            $persons = array_map('person_json', $pdo->query('SELECT * FROM persons ORDER BY sort, id')->fetchAll());
            json_out([
                'user' => ['id' => (int)$user['id'], 'name' => (string)$user['name'], 'role' => (string)$user['role'], 'has_password' => !empty($user['password_hash'])],
                'csrf' => csrf_token(),
                'persons' => $persons,
                'settings' => ['papa_parity' => get_setting('papa_parity', 'even')],
                'template' => (object)template_map(),
            ]);
            break;

        case 'weeks':
            $from = (string)($_GET['from'] ?? '');
            $count = max(1, min(30, (int)($_GET['count'] ?? 1)));
            if (!valid_monday($from)) {
                json_out(['error' => 'Date de semaine invalide.'], 400);
            }
            $to = (new DateTimeImmutable($from))->modify('+' . ($count * 7 - 1) . ' days')->format('Y-m-d');
            $st = $pdo->prepare('SELECT * FROM weeks WHERE monday BETWEEN ? AND ?');
            $st->execute([$from, $to]);
            $weeks = array_map('week_json', $st->fetchAll());
            $st = $pdo->prepare('SELECT monday, day, moment, child, persons, note, school FROM cells WHERE monday BETWEEN ? AND ?');
            $st->execute([$from, $to]);
            $cells = [];
            foreach ($st as $c) {
                $cells[] = [
                    'monday' => $c['monday'],
                    'day' => (int)$c['day'],
                    'moment' => $c['moment'],
                    'child' => $c['child'],
                    'persons' => decode_ids($c['persons']),
                    'note' => (string)$c['note'],
                    'school' => $c['school'] === null ? null : (int)$c['school'],
                ];
            }
            json_out(['weeks' => $weeks, 'cells' => $cells]);
            break;

        case 'save_cells':
            need_post($isPost);
            $monday = $in['monday'] ?? null;
            if (!valid_monday($monday)) {
                throw new BadRequest('Date de semaine invalide.');
            }
            if (!can_edit_week($user, $monday)) {
                json_out(['error' => week_locked($monday)
                    ? 'Cette semaine est verrouillée. Déverrouillez-la pour la modifier.'
                    : 'Vous ne pouvez pas modifier cette semaine.'], 403);
            }
            $cells = $in['cells'] ?? [];
            $reset = $in['reset'] ?? [];
            if (!is_array($cells) || !is_array($reset) || count($cells) > 200 || count($reset) > 200) {
                throw new BadRequest('Requête invalide.');
            }
            $pdo->beginTransaction();
            if (!empty($in['replace'])) {
                $pdo->prepare('DELETE FROM cells WHERE monday = ?')->execute([$monday]);
            }
            $del = $pdo->prepare('DELETE FROM cells WHERE monday = ? AND day = ? AND moment = ? AND child = ?');
            foreach ($reset as $r) {
                [$d, $m, $c] = clean_key($r);
                $del->execute([$monday, $d, $m, $c]);
            }
            $up = $pdo->prepare('INSERT OR REPLACE INTO cells (monday, day, moment, child, persons, note, school, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
            foreach ($cells as $r) {
                [$d, $m, $c] = clean_key($r);
                $school = $r['school'] ?? null;
                if ($school !== null && $school !== 0 && $school !== 1) {
                    throw new BadRequest('Valeur école invalide.');
                }
                $up->execute([$monday, $d, $m, $c, json_encode(clean_persons($r['persons'] ?? [])), clean_note($r['note'] ?? ''), $school, now_iso(), (int)$user['id']]);
            }
            $pdo->commit();
            json_out(['ok' => true]);
            break;

        case 'save_template':
            need_post($isPost);
            need_admin($user);
            $cells = $in['cells'] ?? [];
            $reset = $in['reset'] ?? [];
            if (!is_array($cells) || !is_array($reset) || count($cells) > 200 || count($reset) > 200) {
                throw new BadRequest('Requête invalide.');
            }
            $pdo->beginTransaction();
            $del = $pdo->prepare('DELETE FROM template_cells WHERE day = ? AND moment = ? AND child = ?');
            foreach ($reset as $r) {
                [$d, $m, $c] = clean_key($r);
                $del->execute([$d, $m, $c]);
            }
            $up = $pdo->prepare('INSERT OR REPLACE INTO template_cells (day, moment, child, persons, note) VALUES (?, ?, ?, ?, ?)');
            foreach ($cells as $r) {
                [$d, $m, $c] = clean_key($r);
                $up->execute([$d, $m, $c, json_encode(clean_persons($r['persons'] ?? [])), clean_note($r['note'] ?? '')]);
            }
            $pdo->commit();
            json_out(['ok' => true, 'template' => (object)template_map()]);
            break;

        case 'week_meta':
            need_post($isPost);
            need_admin($user);
            $monday = $in['monday'] ?? null;
            if (!valid_monday($monday)) {
                throw new BadRequest('Date de semaine invalide.');
            }
            $pdo->beginTransaction();
            $pdo->prepare('INSERT OR IGNORE INTO weeks (monday, locked) VALUES (?, 0)')->execute([$monday]);
            $w = week_row($monday);
            $locked = (int)$w['locked'] === 1;
            if (array_key_exists('owner', $in)) {
                $owner = $in['owner'];
                if (!in_array($owner, ['papa', 'maman', null], true)) {
                    throw new BadRequest('Valeur invalide.');
                }
                if ($locked) {
                    $pdo->rollBack();
                    json_out(['error' => 'Déverrouillez la semaine avant de changer à qui elle est.'], 403);
                }
                $pdo->prepare('UPDATE weeks SET owner = ? WHERE monday = ?')->execute([$owner, $monday]);
            }
            if (array_key_exists('locked', $in)) {
                if ($in['locked']) {
                    // La semaine type est figée au moment du verrouillage.
                    if (empty($w['snapshot'])) {
                        $snap = json_encode((object)template_map(), JSON_UNESCAPED_UNICODE);
                        $pdo->prepare('UPDATE weeks SET snapshot = ? WHERE monday = ?')->execute([$snap, $monday]);
                    }
                    $pdo->prepare('UPDATE weeks SET locked = 1 WHERE monday = ?')->execute([$monday]);
                } else {
                    $pdo->prepare('UPDATE weeks SET locked = 0 WHERE monday = ?')->execute([$monday]);
                }
            }
            $pdo->commit();
            json_out(['week' => week_json(week_row($monday))]);
            break;

        case 'person_save':
            need_post($isPost);
            need_admin($user);
            $id = (int)($in['id'] ?? 0);
            $name = trim((string)($in['name'] ?? ''));
            $color = (string)($in['color'] ?? '');
            if ($name === '' || str_len($name) > 40) {
                throw new BadRequest('Donnez un nom de 40 caractères au plus.');
            }
            if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) {
                throw new BadRequest('Couleur invalide.');
            }
            $active = !empty($in['active']) ? 1 : 0;
            if ($id > 0) {
                $st = $pdo->prepare('UPDATE persons SET name = ?, color = ?, active = ? WHERE id = ?');
                $st->execute([$name, strtolower($color), $active, $id]);
                if ($st->rowCount() === 0 && !$pdo->query('SELECT 1 FROM persons WHERE id = ' . $id)->fetchColumn()) {
                    throw new BadRequest('Cette personne n’existe plus.');
                }
            } else {
                $sort = (int)$pdo->query('SELECT COALESCE(MAX(sort), 0) + 1 FROM persons')->fetchColumn();
                $pdo->prepare('INSERT INTO persons (name, color, sort, active) VALUES (?, ?, ?, 1)')->execute([$name, strtolower($color), $sort]);
                $id = (int)$pdo->lastInsertId();
            }
            $st = $pdo->prepare('SELECT * FROM persons WHERE id = ?');
            $st->execute([$id]);
            json_out(['person' => person_json($st->fetch())]);
            break;

        case 'users':
            need_admin($user);
            $rows = $pdo->query("SELECT * FROM users ORDER BY (role = 'admin') DESC, name COLLATE NOCASE")->fetchAll();
            json_out(['users' => array_map('user_json', $rows), 'me' => (int)$user['id']]);
            break;

        case 'user_save':
            need_post($isPost);
            need_admin($user);
            $id = (int)($in['id'] ?? 0);
            $name = trim((string)($in['name'] ?? ''));
            $role = (string)($in['role'] ?? 'view');
            if ($name === '' || str_len($name) > 60) {
                throw new BadRequest('Donnez un nom de 60 caractères au plus.');
            }
            if (!in_array($role, ['edit_all', 'edit_maman', 'view'], true)) {
                throw new BadRequest('Droit invalide.');
            }
            if ($id > 0) {
                $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
                $st->execute([$id]);
                $target = $st->fetch();
                if (!$target) {
                    throw new BadRequest('Cet accès n’existe plus.');
                }
                if ($target['role'] === 'admin') {
                    $pdo->prepare('UPDATE users SET name = ? WHERE id = ?')->execute([$name, $id]);
                } else {
                    $pdo->prepare('UPDATE users SET name = ?, role = ? WHERE id = ?')->execute([$name, $role, $id]);
                }
            } else {
                $pdo->prepare('INSERT INTO users (name, role, active, created_at) VALUES (?, ?, 1, ?)')->execute([$name, $role, now_iso()]);
                $id = (int)$pdo->lastInsertId();
            }
            $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
            $st->execute([$id]);
            json_out(['user' => user_json($st->fetch())]);
            break;

        case 'user_link':
            need_post($isPost);
            need_admin($user);
            $id = (int)($in['id'] ?? 0);
            $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
            $st->execute([$id]);
            $target = $st->fetch();
            if (!$target) {
                throw new BadRequest('Cet accès n’existe plus.');
            }
            if ($target['role'] === 'admin') {
                throw new BadRequest('L’administrateur se connecte avec son mot de passe, pas avec un lien.');
            }
            $token = bin2hex(random_bytes(24));
            $pdo->prepare('UPDATE users SET token_hash = ?, epoch = epoch + 1, active = 1 WHERE id = ?')->execute([token_hash($token), $id]);
            json_out(['url' => base_url() . '?k=' . $token]);
            break;

        case 'user_unlink':
            need_post($isPost);
            need_admin($user);
            $id = (int)($in['id'] ?? 0);
            if ($id === (int)$user['id']) {
                throw new BadRequest('Vous ne pouvez pas couper votre propre accès.');
            }
            $pdo->prepare("UPDATE users SET token_hash = NULL, epoch = epoch + 1 WHERE id = ? AND role <> 'admin'")->execute([$id]);
            json_out(['ok' => true]);
            break;

        case 'user_delete':
            need_post($isPost);
            need_admin($user);
            $id = (int)($in['id'] ?? 0);
            if ($id === (int)$user['id']) {
                throw new BadRequest('Vous ne pouvez pas supprimer votre propre accès.');
            }
            $pdo->prepare("DELETE FROM users WHERE id = ? AND role <> 'admin'")->execute([$id]);
            json_out(['ok' => true]);
            break;

        case 'settings_save':
            need_post($isPost);
            need_admin($user);
            $parity = (string)($in['papa_parity'] ?? '');
            if (!in_array($parity, ['even', 'odd'], true)) {
                throw new BadRequest('Valeur invalide.');
            }
            set_setting('papa_parity', $parity);
            json_out(['settings' => ['papa_parity' => $parity]]);
            break;

        case 'password':
            need_post($isPost);
            if (empty($user['password_hash'])) {
                throw new BadRequest('Cet accès n’utilise pas de mot de passe.');
            }
            $current = (string)($in['current'] ?? '');
            $new = (string)($in['new'] ?? '');
            if (!password_verify($current, (string)$user['password_hash'])) {
                throw new BadRequest('Le mot de passe actuel est incorrect.');
            }
            if (str_len($new) < 10) {
                throw new BadRequest('Le nouveau mot de passe doit avoir au moins 10 caractères.');
            }
            $pdo->prepare('UPDATE users SET password_hash = ?, epoch = epoch + 1 WHERE id = ?')->execute([password_hash($new, PASSWORD_DEFAULT), (int)$user['id']]);
            $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
            $st->execute([(int)$user['id']]);
            login_user($st->fetch());
            json_out(['ok' => true, 'csrf' => csrf_token()]);
            break;

        case 'backup':
            need_admin($user);
            if (!is_file(DB_FILE)) {
                json_out(['error' => 'Aucune donnée à sauvegarder.'], 404);
            }
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="planning-garde-' . date('Y-m-d') . '.sqlite"');
            header('Content-Length: ' . (string)filesize(DB_FILE));
            readfile(DB_FILE);
            exit;

        default:
            json_out(['error' => 'Action inconnue.'], 404);
    }
} catch (BadRequest $ex) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    json_out(['error' => $ex->getMessage()], 400);
} catch (Throwable $ex) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('[garde] ' . $ex->getMessage());
    json_out(['error' => 'Erreur du serveur. Réessayez dans un instant.'], 500);
}
