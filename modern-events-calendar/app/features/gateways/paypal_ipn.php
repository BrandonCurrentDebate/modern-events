<?php
/**
 *  WordPress initializing
 */
function mec_find_wordpress_base_path_pi()
{
    $dir = dirname(__FILE__);
    
    do
    {
        if(file_exists($dir.'/wp-load.php') and file_exists($dir.'/wp-config.php')) return $dir;
    }
    while($dir = realpath($dir.'/..'));
    
    return NULL;
}

define('BASE_PATH', mec_find_wordpress_base_path_pi().'/');
define('WP_USE_THEMES', false);

global $wp, $wp_query, $wp_the_query, $wp_rewrite, $wp_did_header;
require(BASE_PATH.'wp-load.php');

// exit if request method is GET
if(!isset($_SERVER['REQUEST_METHOD']) or (isset($_SERVER['REQUEST_METHOD']) and $_SERVER['REQUEST_METHOD'] == 'GET')) exit;

$model = new MEC_gateway_paypal_express();

$vars = array_map('stripslashes', $model->main->sanitize_deep_array($_POST));
$verified = $model->validate_express_payment($vars);