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
    $conn->query("DELETE FROM login_attempts WHERE attempt_time < NOW() - INTERVAL 2 MINUTE");

    // Verifica si hay más de 5 intentos fallidos en los últimos 2 minutos
    $stmt = $conn->prepare("SELECT COUNT(*) AS attempts FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempt_time > NOW() - INTERVAL 2 MINUTE");
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

// Procesar formulario de inicio de sesión
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validar las credenciales
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();

        if (password_verify($password, $user['password_hash'])) {
            // Inicio de sesión exitoso
            $_SESSION['username'] = $username;
            $stmt = $conn->prepare("INSERT INTO login_attempts (ip_address, success) VALUES (?, 1)");
            $stmt->bind_param("s", $ip);
            $stmt->execute();
            echo "Bienvenido, " . htmlspecialchars($username) . "!";
        } else {
            // Intento fallido
            $stmt = $conn->prepare("INSERT INTO login_attempts (ip_address, success) VALUES (?, 0)");
            $stmt->bind_param("s", $ip);
            $stmt->execute();
            echo "Credenciales incorrectas.";
        }
    } else {
        // Intento fallido
        $stmt = $conn->prepare("INSERT INTO login_attempts (ip_address, success) VALUES (?, 0)");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        echo "Usuario no encontrado.";
    }
}

$conn->close();
?>

<!-- Formulario de inicio de sesión -->
<h2>Formulario de Inicio de Sesión</h2>
<form action="login.php" method="POST">
    <label for="username">Nombre de usuario:</label>
    <input type="text" id="username" name="username" required><br><br>
    <label for="password">Contraseña:</label>
    <input type="password" id="password" name="password" required><br><br>
    <input type="submit" value="Iniciar sesión">
</form>
