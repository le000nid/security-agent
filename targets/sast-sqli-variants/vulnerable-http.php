<?php

function cookieQuery($pdo) {
    $supplied = $_COOKIE["name"];
    $alias = $supplied;
    $sql = "SELECT * FROM users WHERE name = '" . $alias . "'";
    // ruleid: php-sql-tainted-query
    return $pdo->query($sql, PDO::FETCH_ASSOC);
}

function realQuery($connection) {
    $supplied = $_POST["email"];
    $sql = "SELECT * FROM users WHERE email = '" . $supplied . "'";
    // ruleid: php-sql-tainted-query
    return mysqli_real_query($connection, $sql);
}

function prepareOptions($pdo) {
    $supplied = $_GET["name"];
    $sql = "SELECT * FROM users WHERE name = '$supplied'";
    // ruleid: php-prepare-sqli-taint
    return $pdo->prepare($sql, [PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY]);
}

function executeQuery($connection) {
    $supplied = $_REQUEST["id"];
    $sql = "SELECT * FROM users WHERE id = " . $supplied;
    // ruleid: php-sql-tainted-query
    return $connection->execute_query($sql);
}
