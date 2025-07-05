<?php
// includes/shiprocket-whitelist.php
// API Whitelist for Security Plugin (Shiprocket, Google Merchant, WooCommerce)

if (!defined('ABSPATH')) {
    exit;
}

class APIWhitelist {
    private $api_domains = array(
        // Shiprocket domains
        'app.shiprocket.in',
        'apiv2.shiprocket.in',
        'api.shiprocket.in',
        'shiprocket.in',
        'www.shiprocket.in',
        'sr-posthog.shiprocket.in',
        
        // Google domains
        'accounts.google.com',
        'oauth2.googleapis.com',
        'www.googleapis.com',
        'merchantcenter.googleapis.com',
        'content.googleapis.com',
        'shopping.googleapis.com',
        'jetpack.wordpress.com',
        'jetpack.com',
        'public-api.wordpress.com'
    );
    
    private $api_ips = array(
        // Add known API IP ranges if available
        '52.66.0.0/16',
        '13.126.0.0/16',
        '13.232.0.0/16'
    );
    
    public function __construct() {
        // Hook early to bypass all security checks for API requests
        add_action('plugins_loaded', array($this, 'whitelist_api_requests'), 1); // Priority 1 - runs very early
        
        // Handle OPTIONS requests for CORS
        add_action('init', array($this, 'handle_cors_preflight'), 0);
        
        // Add specific WooCommerce admin hooks
        add_action('rest_api_init', array($this, 'whitelist_wc_admin_routes'), 1);
    }
    
    public function handle_cors_preflight() {
        // Handle CORS preflight requests
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-WP-Nonce');
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Max-Age: 86400'); // Cache for 24 hours
            
            // Exit early for OPTIONS requests
            exit(0);
        }
    }
    
    public function whitelist_wc_admin_routes() {
        // Whitelist specific WooCommerce admin routes
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        $wc_admin_routes = array(
            '/wp-json/wc/gla/',
            '/wp-json/wc/v3/',
            '/wp-json/wc/v2/',
            '/wp-json/wc/v1/',
            '/wp-json/wc-admin/',
            '/wp-json/jetpack/',
            '/wp-admin/admin.php?page=wc-admin'
        );
        
        foreach ($wc_admin_routes as $route) {
            if (strpos($request_uri, $route) !== false) {
                define('API_REQUEST_WHITELISTED', true);
                $this->add_cors_headers();
                return;
            }
        }
    }
    
    public function whitelist_api_requests() {
        // Check if this is an API request that should be whitelisted
        if ($this->is_api_request()) {
            // Set flag to skip security checks
            define('API_REQUEST_WHITELISTED', true);
            
            // Add CORS headers immediately
            $this->add_cors_headers();
            
            // Remove security hooks that might interfere
            remove_action('init', array('SecurityWAF', 'waf_check'));
            remove_action('init', array('BotBlackhole', 'check_bot_access'));
            remove_action('init', array('BotBlocker', 'check_bot_request'));
            
            // Allow the request to proceed normally
            return;
        }
    }
    
    private function add_cors_headers() {
        if (!headers_sent()) {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-WP-Nonce');
            header('Access-Control-Allow-Credentials: true');
        }
    }
    
    private function is_api_request() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        
        // CRITICAL: Check for WooCommerce admin pages first
        if (strpos($request_uri, '/wp-admin/admin.php?page=wc-admin') !== false) {
            return true;
        }
        
        // Check for API indicators
        $api_indicators = array(
            'shiprocket',
            'woocommerce',
            'google',
            'jetpack',
            'merchant',
            'rest_route=/wc/',
            '/wp-json/wc/',
            '/wp-json/wc/gla/',
            '/wp-json/jetpack/',
            'consumer_key',
            'consumer_secret',
            'oauth',
            'api_key'
        );
        
        foreach ($api_indicators as $indicator) {
            if (stripos($user_agent, $indicator) !== false ||
                stripos($referer, $indicator) !== false ||
                stripos($request_uri, $indicator) !== false ||
                stripos($origin, $indicator) !== false) {
                return true;
            }
        }
        
        // Check for WooCommerce REST API endpoints
        if (strpos($request_uri, '/wp-json/wc/') !== false ||
            strpos($request_uri, '/wp-json/wc-admin/') !== false ||
            strpos($request_uri, '/wp-json/jetpack/') !== false) {
            return true;
        }
        
        // Check for authentication headers
        if (isset($_SERVER['HTTP_AUTHORIZATION']) || 
            isset($_GET['consumer_key']) || 
            isset($_POST['consumer_key']) ||
            isset($_GET['oauth_token']) ||
            isset($_POST['oauth_token'])) {
            return true;
        }
        
        // Check if origin is from known API domains
        foreach ($this->api_domains as $domain) {
            if (strpos($origin, $domain) !== false ||
                strpos($referer, $domain) !== false) {
                return true;
            }
        }
        
        // Check for WordPress admin AJAX requests
        if (strpos($request_uri, '/wp-admin/admin-ajax.php') !== false ||
            strpos($request_uri, '/wp-admin/') !== false) {
            return true;
        }
        
        return false;
    }
}

// Initialize API whitelist
new APIWhitelist();