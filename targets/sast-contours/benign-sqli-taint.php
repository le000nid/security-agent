<?php

// Safe in this context: values are bound rather than concatenated into SQL.

$name = $_POST["name"];

$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");

$stmt->execute([$name]);