<?php

// Case 1: safe PDO prepare

$id = $_GET["id"];

$stmt = $pdo->prepare(
    "SELECT * FROM users WHERE id = ?"
);

$stmt->execute([$id]);


// Case 2: safe mysqli_prepare

$email = $_POST["email"];

$stmt2 = mysqli_prepare(
    $connection,
    "SELECT * FROM users WHERE email = ?"
);

mysqli_stmt_bind_param($stmt2, "s", $email);
mysqli_stmt_execute($stmt2);