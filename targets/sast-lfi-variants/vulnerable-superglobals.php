<?php

function queryInclude() {
    $supplied = $_GET["page"];
    $alias = $supplied;
    $path = "views/" . $alias . ".php";
    // ruleid: php-local-file-inclusion
    include $path;
}

function postIncludeOnce() {
    $supplied = $_POST["template"];
    $path = sprintf("templates/%s.php", $supplied);
    // ruleid: php-local-file-inclusion
    include_once($path);
}

function requestRequire() {
    $path = $_REQUEST["module"];
    // ruleid: php-local-file-inclusion
    require $path;
}

function cookieRequireOnce() {
    $path = $_COOKIE["theme"];
    // ruleid: php-local-file-inclusion
    require_once($path);
}
