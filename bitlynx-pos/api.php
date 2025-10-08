<?php
// api.php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

// Database configuration
$host = 'localhost';
$dbname = 'bitlynx_pos_pro';
$username = 'root'; // Change as needed
$password = ''; // Change as needed

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Get the action from query string
$action = $_GET['action'] ?? '';

// Helper function to send JSON response
function sendResponse($success, $data = null, $message = '') {
    echo json_encode([
        'success' => $success,
        'data' => $data,
        'message' => $message
    ]);
    exit;
}

// Helper function to verify required parameters
function verifyRequiredParams($required, $data) {
    foreach ($required as $param) {
        if (!isset($data[$param]) || empty($data[$param])) {
            sendResponse(false, null, "Missing required parameter: $param");
        }
    }
}

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true) ?? [];

switch ($action) {
    // User Management
    case 'get_users':
        try {
            $stmt = $pdo->query("SELECT * FROM users ORDER BY created_at DESC");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Convert JSON permissions to array
            foreach ($users as &$user) {
                $user['permissions'] = json_decode($user['permissions'], true);
            }
            
            sendResponse(true, $users);
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to fetch users: ' . $e->getMessage());
        }
        break;

    case 'add_user':
        verifyRequiredParams(['username', 'password', 'display_name', 'role', 'permissions'], $input);
        
        try {
            $id = 'user-' . uniqid();
            $permissions = json_encode($input['permissions']);
            
            $stmt = $pdo->prepare("INSERT INTO users (id, username, password, display_name, role, permissions) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$id, $input['username'], $input['password'], $input['display_name'], $input['role'], $permissions]);
            
            sendResponse(true, ['id' => $id], 'User added successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to add user: ' . $e->getMessage());
        }
        break;

    case 'update_user':
        verifyRequiredParams(['id', 'username', 'password', 'display_name', 'role', 'permissions'], $input);
        
        try {
            $permissions = json_encode($input['permissions']);
            
            $stmt = $pdo->prepare("UPDATE users SET username = ?, password = ?, display_name = ?, role = ?, permissions = ? WHERE id = ?");
            $stmt->execute([$input['username'], $input['password'], $input['display_name'], $input['role'], $permissions, $input['id']]);
            
            sendResponse(true, null, 'User updated successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to update user: ' . $e->getMessage());
        }
        break;

    case 'delete_user':
        verifyRequiredParams(['id'], $input);
        
        try {
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$input['id']]);
            
            sendResponse(true, null, 'User deleted successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to delete user: ' . $e->getMessage());
        }
        break;

    // Product Management
    case 'get_products':
        try {
            $stmt = $pdo->query("SELECT * FROM products ORDER BY created_at DESC");
            $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
            sendResponse(true, $products);
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to fetch products: ' . $e->getMessage());
        }
        break;

    case 'add_product':
        verifyRequiredParams(['barcode', 'name', 'category', 'buy_price', 'sell_price', 'available_stock', 'reorder_level'], $input);
        
        try {
            $id = 'prod-' . uniqid();
            $expiration_date = !empty($input['expiration_date']) ? $input['expiration_date'] : null;
            
            $stmt = $pdo->prepare("INSERT INTO products (id, barcode, name, category, buy_price, sell_price, available_stock, reorder_level, expiration_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $id, 
                $input['barcode'], 
                $input['name'], 
                $input['category'], 
                $input['buy_price'], 
                $input['sell_price'], 
                $input['available_stock'], 
                $input['reorder_level'], 
                $expiration_date
            ]);
            
            sendResponse(true, ['id' => $id], 'Product added successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to add product: ' . $e->getMessage());
        }
        break;

    case 'update_product':
        verifyRequiredParams(['id', 'barcode', 'name', 'category', 'buy_price', 'sell_price', 'available_stock', 'reorder_level'], $input);
        
        try {
            $expiration_date = !empty($input['expiration_date']) ? $input['expiration_date'] : null;
            
            $stmt = $pdo->prepare("UPDATE products SET barcode = ?, name = ?, category = ?, buy_price = ?, sell_price = ?, available_stock = ?, reorder_level = ?, expiration_date = ? WHERE id = ?");
            $stmt->execute([
                $input['barcode'], 
                $input['name'], 
                $input['category'], 
                $input['buy_price'], 
                $input['sell_price'], 
                $input['available_stock'], 
                $input['reorder_level'], 
                $expiration_date,
                $input['id']
            ]);
            
            sendResponse(true, null, 'Product updated successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to update product: ' . $e->getMessage());
        }
        break;

    case 'delete_product':
        verifyRequiredParams(['id'], $input);
        
        try {
            $stmt = $pdo->prepare("DELETE FROM products WHERE id = ?");
            $stmt->execute([$input['id']]);
            
            sendResponse(true, null, 'Product deleted successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to delete product: ' . $e->getMessage());
        }
        break;

    // Sales Management
    case 'get_sales':
        try {
            $stmt = $pdo->query("SELECT * FROM sales ORDER BY date DESC");
            $sales = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Convert JSON items to array
            foreach ($sales as &$sale) {
                $sale['items'] = json_decode($sale['items'], true);
            }
            
            sendResponse(true, $sales);
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to fetch sales: ' . $e->getMessage());
        }
        break;

    case 'add_sale':
        verifyRequiredParams(['date', 'user_id', 'user_name', 'items', 'total', 'payment_method'], $input);
        
        try {
            $id = 'sale-' . uniqid();
            $items = json_encode($input['items']);
            
            $stmt = $pdo->prepare("INSERT INTO sales (id, date, user_id, user_name, items, total, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $id, 
                $input['date'], 
                $input['user_id'], 
                $input['user_name'], 
                $items, 
                $input['total'], 
                $input['payment_method']
            ]);
            
            sendResponse(true, ['id' => $id], 'Sale added successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to add sale: ' . $e->getMessage());
        }
        break;

    // Settings Management
    case 'get_settings':
        try {
            $stmt = $pdo->query("SELECT * FROM settings WHERE id = 1");
            $settings = $stmt->fetch(PDO::FETCH_ASSOC);
            sendResponse(true, $settings);
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to fetch settings: ' . $e->getMessage());
        }
        break;

    case 'update_settings':
        verifyRequiredParams(['business_name', 'currency', 'tax_rate', 'receipt_footer'], $input);
        
        try {
            $stmt = $pdo->prepare("UPDATE settings SET business_name = ?, currency = ?, tax_rate = ?, receipt_footer = ? WHERE id = 1");
            $stmt->execute([
                $input['business_name'], 
                $input['currency'], 
                $input['tax_rate'], 
                $input['receipt_footer']
            ]);
            
            sendResponse(true, null, 'Settings updated successfully');
        } catch (PDOException $e) {
            sendResponse(false, null, 'Failed to update settings: ' . $e->getMessage());
        }
        break;

    // Authentication
    case 'login':
        verifyRequiredParams(['username', 'password'], $input);
        
        try {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
            $stmt->execute([$input['username'], $input['password']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                // Convert JSON permissions to array
                $user['permissions'] = json_decode($user['permissions'], true);
                
                // Set session (you might want to use proper session management)
                session_start();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_role'] = $user['role'];
                
                sendResponse(true, $user, 'Login successful');
            } else {
                sendResponse(false, null, 'Invalid username or password');
            }
        } catch (PDOException $e) {
            sendResponse(false, null, 'Login failed: ' . $e->getMessage());
        }
        break;

    case 'logout':
        session_start();
        session_destroy();
        sendResponse(true, null, 'Logout successful');
        break;

    case 'get_current_user':
        session_start();
        if (isset($_SESSION['user_id'])) {
            try {
                $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($user) {
                    $user['permissions'] = json_decode($user['permissions'], true);
                    sendResponse(true, $user);
                } else {
                    sendResponse(false, null, 'User not found');
                }
            } catch (PDOException $e) {
                sendResponse(false, null, 'Failed to fetch user: ' . $e->getMessage());
            }
        } else {
            sendResponse(false, null, 'No user logged in');
        }
        break;

    default:
        sendResponse(false, null, 'Invalid action');
        break;
}
?>