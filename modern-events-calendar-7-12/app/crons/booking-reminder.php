<?php
/**
 *  WordPress initializing
 */
function mec_find_wordpress_base_path_br()
{
    $dir = dirname(__FILE__);
    
    do
    {
        if(
            (file_exists($dir.'/wp-load.php') || is_link($dir.'/wp-load.php')) &&
            (file_exists($dir.'/wp-config.php') || is_link($dir.'/wp-config.php'))
        ) return $dir;
    }
    while($dir = realpath($dir.'/..'));
    
    return NULL;
}

define('BASE_PATH', mec_find_wordpress_base_path_br().'/');
if(!defined('WP_USE_THEMES')) define('WP_USE_THEMES', false);

global $wp, $wp_query, $wp_the_query, $wp_rewrite, $wp_did_header;
require BASE_PATH.'wp-load.php';

/** @var $main MEC_main **/

// MEC libraries
$main = MEC::getInstance('app.libraries.main');

// Blogs
$blogs = array(1);

// Current Blog ID
$multisite = function_exists('is_multisite') && is_multisite();
$current_blog_id = get_current_blog_id();

// Database
$db = $main->getDB();

// Multisite
if($multisite) $blogs = $db->select("SELECT `blog_id` FROM `#__blogs`", 'loadColumn');

$sent_reminders = 0;
$now = current_time('Y-m-d H:00');

foreach($blogs as $blog)
{
    // Switch to Blog
    if($multisite) switch_to_blog($blog);

    // MEC notifications
    $notifications = $main->get_notifications();

    // MEC Settings
    $settings = $main->get_settings();

    // Booking is disabled
    if(!isset($settings['booking_status']) || !$settings['booking_status']) continue;

    // Status
    $status = isset($notifications['booking_reminder']['status']) && $notifications['booking_reminder']['status'];

    // Booking Reminder Email is disabled
    if(!$status) continue;

    // Hours
    $hours = isset($notifications['booking_reminder']['hours']) ? explode(',', trim($notifications['booking_reminder']['hours'], ', ')) : [];

    // Hours are invalid
    if(!is_array($hours) || !count($hours)) continue;

    // Check Last Run Date & Time
    $latest_run = get_option('mec_booking_reminder_last_run_datetime', NULL);
    if($latest_run && strtotime($latest_run) > strtotime('-1 Hour', strtotime($now))) continue;

    /**
     * Notification Sender Library
     */
    $notif = $main->getNotifications();

    foreach($hours as $hour)
    {
        $hour = (int) trim($hour, ', ');

        // Hour is not accepted as a valid value for hours
        if($hour <= 0) continue;

        // It's time of the hour that we're going to check
        $time = strtotime('+'.$hour.' hours', strtotime($now));

        /**
         * NORMAL BOOKINGS
         */

        $bookings = $main->get_bookings_for_occurrence(array(
            $time,
            ($time + 3600)
        ), array(
            'confirmed' => 1,
            'verified' => 1,
            'status' => array(),
            'limit' => -1
        ));

        foreach($bookings as $booking)
        {
            $event_id = get_post_meta($booking->ID, 'mec_event_id', true);
            $end = $db->select("SELECT `tend` FROM `#__mec_dates` WHERE `post_id`='".$event_id."' AND `tstart`='".$booking->mec_timestamp."' LIMIT 1", 'loadResult');

            $timestamps = $booking->mec_timestamp.':'.$end;

            $result = $notif->booking_reminder($booking->ID, $timestamps);
            if($result) $sent_reminders++;
        }

        /**
         * ALL AT ONCE BOOKINGS
         */

        $q = new WP_Query();
        $events = $q->query(array
        (
            'post_type'=>$main->get_main_post_type(),
            'posts_per_page'=>-1,
            'post_status'=>'any',
            'meta_query'=>array
            (
                array(
                    'key'=>'mec_booking',
                    'value'=>'"bookings_all_occurrences";s:1:"1"',
                    'compare'=>'LIKE',
                ),
            ),
        ));

        $all_ids = [];
        foreach($events as $event) $all_ids[] = $event->ID;

        $all_ids = array_unique($all_ids);
        if(!count($all_ids)) continue;

        $tstart = floor($time / 3600) * 3600;
        $tend = $time + 3600;

        $event_ids = $db->select("SELECT `post_id` FROM `#__mec_dates` WHERE `post_id` IN (".implode(',', $all_ids).") AND `tstart` >= $tstart AND `tstart` < $tend", 'loadColumn');
        if(!count($event_ids)) continue;

        $q = new WP_Query();
        $bookings = $q->query(array
        (
            'post_type'=>$main->get_book_post_type(),
            'posts_per_page'=>-1,
            'post_status'=>'any',
            'meta_query'=>array
            (
                array(
                    'key'=>'mec_event_id',
                    'value'=>$event_ids,
                    'compare'=>'IN',
                ),
                array(
                    'key'=>'mec_verified',
                    'value'=>'1',
                    'compare'=>'='
                ),
                array(
                    'key'=>'mec_confirmed',
                    'value'=>'1',
                    'compare'=>'='
                ),
            ),
        ));

        $booking_ids = [];
        foreach($bookings as $booking) $booking_ids[] = $booking->ID;

        $booking_ids = array_unique($booking_ids);
        foreach($booking_ids as $booking_id)
        {
            $mec_timestamps = explode(':', get_post_meta($booking_id, 'mec_date', true));

            // Do not send for first occurrence
            if($mec_timestamps[0] >= $tstart && $mec_timestamps[0] <= $tend) continue;

            $event_id = get_post_meta($booking_id, 'mec_event_id', true);

            $event_status = get_post_status($event_id);
            if(!$event_status || in_array($event_status, ['draft', 'trash', 'auto-draft'])) continue;

            $occurrence = $db->select("SELECT `tstart`, `tend` FROM `#__mec_dates` WHERE `post_id` = '".$event_id."' AND `tstart` >= $tstart AND `tstart` < $tend ORDER BY `tstart` ASC LIMIT 1", 'loadObject');

            // Occurrence not Found
            if(!is_object($occurrence)) continue;

            $timestamps = $occurrence->tstart.':'.$occurrence->tend;

            $result = $notif->booking_reminder($booking_id, $timestamps);
            if($result) $sent_reminders++;
        }
    }

    // Last Run
    update_option('mec_booking_reminder_last_run_datetime', $now, false);
}

// Switch to Current Blog
if($multisite) switch_to_blog($current_blog_id);

echo sprintf(esc_html__('%s reminder(s) sent.', 'mec'), $sent_reminders);
exit;