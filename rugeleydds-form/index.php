<?php
$form = $_GET['form'] ?? 'contact';

if ($form === 'appointment') {
    require __DIR__ . '/appointment.php';
} else {
    require __DIR__ . '/contact.php';
}
