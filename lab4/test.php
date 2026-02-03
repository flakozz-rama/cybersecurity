<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Test Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }
        form {
            margin: 20px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }
        input[type="submit"] {
            background-color: #007bff;
            color: white;
            padding: 10px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
        .result {
            background-color: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .test-payloads {
            margin-top: 30px;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }
        .test-payloads h3 {
            margin-top: 0;
        }
        .test-payloads code {
            background-color: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
        ul {
            line-height: 2;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>WAF Test Page</h1>

        <div class="warning">
            <strong>Warning:</strong> This page is intentionally vulnerable for testing WAF protection.
            Do not deploy in production!
        </div>

        <form method="GET" action="">
            <label for="id">Enter ID (test input for WAF):</label>
            <input type="text" name="id" id="id" placeholder="Enter a value...">
            <input type="submit" value="Submit">
        </form>

        <?php
        if(isset($_GET['id'])) {
            echo '<div class="result">';
            echo '<strong>You entered:</strong> ' . htmlspecialchars($_GET['id']);
            echo '</div>';
        }
        ?>

        <div class="test-payloads">
            <h3>Test Payloads (copy and paste to test WAF):</h3>
            <ul>
                <li><strong>SQL Injection:</strong> <code>1 OR 1=1</code></li>
                <li><strong>SQL Injection (UNION):</strong> <code>1 UNION SELECT * FROM users</code></li>
                <li><strong>XSS:</strong> <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
                <li><strong>XSS (event):</strong> <code>&lt;img src=x onerror=alert(1)&gt;</code></li>
                <li><strong>Path Traversal:</strong> <code>../../../etc/passwd</code></li>
                <li><strong>Command Injection:</strong> <code>; cat /etc/passwd</code></li>
                <li><strong>Command Injection:</strong> <code>| ls -la</code></li>
            </ul>
            <p><em>If WAF is working correctly, these requests should return HTTP 403 Forbidden.</em></p>
        </div>
    </div>
</body>
</html>
