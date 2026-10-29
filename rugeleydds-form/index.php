<?php
require_once 'config.php';
$form = $_GET['form'] ?? 'contact';
if ($form === 'appointment') {
    require 'appointment.php';
} else {
    require 'contact.php';
}
