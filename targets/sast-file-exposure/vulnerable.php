<?php

$path = "uploads/" . $_GET["name"];
readfile($path);
include($path);
