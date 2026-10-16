<?php

function filteredGet() {
    $supplied = filter_input(INPUT_GET, "page");
    $pages = ["home" => "views/home.php", "help" => "views/help.php"];
    $path = $pages[$supplied] ?? "views/home.php";
    // ok: php-local-file-inclusion
    include($path);
}

function filteredPost() {
    $supplied = filter_input(INPUT_POST, "template", FILTER_UNSAFE_RAW);
    $pages = ["profile" => "templates/profile.php", "login" => "templates/login.php"];
    $path = $pages[$supplied] ?? "templates/login.php";
    // ok: php-local-file-inclusion
    require($path);
}

function filteredCookie() {
    $supplied = filter_input(INPUT_COOKIE, "theme");
    $pages = ["light" => "themes/light.php", "dark" => "themes/dark.php"];
    $path = $pages[$supplied] ?? "themes/light.php";
    // ok: php-local-file-inclusion
    include_once $path;
}
