<?php

function basenameIsNotAnAllowlist() {
    $path = basename($_GET["page"]);
    // ruleid: php-local-file-inclusion
    include $path;
}

function replacementIsNotAnAllowlist() {
    $path = str_replace("../", "", $_POST["template"]);
    // ruleid: php-local-file-inclusion
    require_once($path);
}
