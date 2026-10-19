<?php

function assignedInclude() {
    $path = $_GET["page"];
    // ruleid: php-local-file-inclusion
    $result = include($path);
    return $result;
}

function returnedRequire() {
    $supplied = $_POST["module"];
    $path = $supplied;
    // ruleid: php-local-file-inclusion
    return require $path;
}

function assignedRequireOnce() {
    $path = $_REQUEST["bootstrap"];
    // ruleid: php-local-file-inclusion
    $result = require_once $path;
    return $result;
}
