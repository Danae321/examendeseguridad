<?php
session_start();
date_default_timezone_set('America/La_Paz'); // Asegura la zona horaria correcta

// Conexión a la base de datos
$conn = new mysqli("localhost", "root", "root", "user_authentication");
if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

// Función para verificar si una IP está bloqueada
function isBlocked($ip, $conn) {
    // Limpia los intentos antiguos automáticamente (más de 2 minutos)
    $conn->query("DELETE FROM register_attempts WHERE attempt_time < NOW() - INTERVAL 2 MINUTE");

    // Verifica si hay más de 5 intentos fallidos en los últimos 2 minutos
    $stmt = $conn->prepare("SELECT COUNT(*) AS attempts FROM register_attempts WHERE ip_address = ? AND success = 0 AND attempt_time > NOW() - INTERVAL 2 MINUTE");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();

    return $result['attempts'] >= 5;
}

// Obtener la dirección IP del usuario
$ip = $_SERVER['REMOTE_ADDR'];

// Verifica si la IP está bloqueada
if (isBlocked($ip, $conn)) {
    die("Demasiados intentos fallidos. Espere 2 minutos para intentarlo de nuevo.");
}

// Función para validar la contraseña
function validatePassword($password) {
    // Al menos una letra y un carácter especial
    if (!preg_match('/[A-Za-z]/', $password) || !preg_match('/[\W_]/', $password)) {
        return "La contraseña debe contener al menos una letra y un carácter especial.";
    }
    return null;
}

// Procesar formulario de registro
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validar la contraseña
    $password_error = validatePassword($password);
    if ($password_error) {
        die($password_error);
    }

    $password_hashed = password_hash($password, PASSWORD_DEFAULT);

    // Validar que el usuario no exista ya
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // Registro del intento fallido
        $stmt = $conn->prepare("INSERT INTO register_attempts (ip_address, success) VALUES (?, 0)");
        $stmt->bind_param("s", $ip);
        $stmt->execute();

        die("El nombre de usuario ya está registrado. Intente con otro.");
    }

    // Registrar al usuario
    $stmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $password_hashed);
    if ($stmt->execute()) {
        // Registro exitoso
        $stmt = $conn->prepare("INSERT INTO register_attempts (ip_address, success) VALUES (?, 1)");
        $stmt->bind_param("s", $ip);
        $stmt->execute();

        echo "Registro exitoso. Bienvenido, " . htmlspecialchars($username) . "!";
    } else {
        echo "Error en el registro: " . $conn->error;
    }
}

$conn->close();
?>

<!-- Formulario integrado en la misma página -->
<h2>Formulario de Registro</h2>
<form action="register.php" method="POST">
    <label for="username">Nombre de usuario:</label>
    <input type="text" id="username" name="username" required><br><br>
    <label for="password">Contraseña:</label>
    <input type="password" id="password" name="password" required><br><br>
    <input type="submit" value="Registrar">
</form>
