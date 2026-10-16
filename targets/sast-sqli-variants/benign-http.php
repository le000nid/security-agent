<?php

function cookieQuery($pdo) {
    $supplied = $_COOKIE["name"];
    $alias = $supplied;
    // ok: php-sql-tainted-query
    $statement = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    $statement->execute([$alias]);
    return $statement;
}

function realQuery($connection) {
    $supplied = $_POST["email"];
    // ok: php-sql-tainted-query
    return $connection->execute_query("SELECT * FROM users WHERE email = ?", [$supplied]);
}

function prepareOptions($pdo) {
    $supplied = $_GET["name"];
    // ok: php-prepare-sqli-taint
    $statement = $pdo->prepare("SELECT * FROM users WHERE name = ?", [PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY]);
    $statement->execute([$supplied]);
    return $statement;
}

function executeQuery($connection) {
    $supplied = $_REQUEST["id"];
    // ok: php-sql-tainted-query
    return $connection->execute_query("SELECT * FROM users WHERE id = ?", [$supplied]);
}
