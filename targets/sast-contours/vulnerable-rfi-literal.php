<?php

// Educational example: the URL is a literal, so the LFI taint rule does not duplicate it.
// Remote PHP inclusion additionally depends on PHP runtime configuration.
include("https://plugins.example.invalid/external-module.php");
