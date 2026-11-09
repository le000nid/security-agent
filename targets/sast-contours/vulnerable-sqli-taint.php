<?php

// Educational fixture: HTTP input becomes part of SQL syntax.

$name = $_POST["name"];

$sql = "SELECT * FROM users WHERE name = '" . $name . "'";

$pdo->query($sql);