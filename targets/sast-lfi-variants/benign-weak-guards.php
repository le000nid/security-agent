<?php

function explicitPageChoice() {
    $choice = $_GET["page"];
    if ($choice === "home") {
        $path = "views/home.php";
    } else {
        $path = "views/help.php";
    }
    // ok: php-local-file-inclusion
    include $path;
}

function explicitTemplateChoice() {
    $choice = $_POST["template"];
    if ($choice === "profile") {
        $path = "templates/profile.php";
    } else {
        $path = "templates/login.php";
    }
    // ok: php-local-file-inclusion
    require_once($path);
}
