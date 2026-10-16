<?php

function assignedInclude() {
    $choice = $_GET["page"];
    $path = $choice === "help" ? "views/help.php" : "views/home.php";
    // ok: php-local-file-inclusion
    $result = include($path);
    return $result;
}

function returnedRequire() {
    $choice = $_POST["module"];
    $path = $choice === "profile" ? "modules/profile.php" : "modules/home.php";
    // ok: php-local-file-inclusion
    return require $path;
}

function assignedRequireOnce() {
    $choice = $_REQUEST["bootstrap"];
    $path = $choice === "admin" ? "bootstrap/admin.php" : "bootstrap/public.php";
    // ok: php-local-file-inclusion
    $result = require_once $path;
    return $result;
}
