<?php
// Start a session
session_start();

// Database connection details
$servername = "localhost";  // Adjust as needed
$dbusername = "root";       // Your database username
$dbpassword = "";           // Your database password
$dbname = "mysql";  // Your database name

// Create connection
$conn = new mysqli($servername, $dbusername, "", $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate the input
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    // Check if fields are empty
    if (empty($username) || empty($password)) {
        echo "Both fields are required!";
    } else {
        // Prepare a statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);

        // Execute the statement
        $stmt->execute();
        $stmt->store_result();

        // Check if user exists
        if ($stmt->num_rows > 0) {
            // Bind result to variables
            $stmt->bind_result($id, $hashed_password);
            $stmt->fetch();

            // Verify the password
            if (password_verify($password, $hashed_password)) {
                // Store user information in session and redirect to dashboard
                $_SESSION['username'] = $username;
                $_SESSION['user_id'] = $id;
                header("Location: 1.html");  // Redirect to a protected page (dashboard.php)
                exit();
            } else {
                echo "Invalid password!";
            }
        } else {
            echo "No user found with that username!";
        }

        // Close the statement
        $stmt->close();
    }
}

// Close the connection
$conn->close();
?>
