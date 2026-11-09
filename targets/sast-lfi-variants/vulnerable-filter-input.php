<?php

function filteredGet() {
    $supplied = filter_input(INPUT_GET, "page");
    $path = "views/" . $supplied . ".php";
    // ruleid: php-local-file-inclusion
    include($path);
}

function filteredPost() {
    $supplied = filter_input(INPUT_POST, "template", FILTER_UNSAFE_RAW);
    $path = rawurldecode($supplied);
    // ruleid: php-local-file-inclusion
    require($path);
}

function filteredCookie() {
    $supplied = filter_input(INPUT_COOKIE, "theme");
    $path = trim($supplied);
    // ruleid: php-local-file-inclusion
    include_once $path;
}
