<?php
/**
 *  WordPress initializing
 */
function mec_find_wordpress_base_path_mi()
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

define('BASE_PATH', mec_find_wordpress_base_path_mi().'/');
if(!defined('WP_USE_THEMES')) define('WP_USE_THEMES', false);

global $wp, $wp_query, $wp_the_query, $wp_rewrite, $wp_did_header;
require BASE_PATH.'wp-load.php';

/** @var $main MEC_main **/

$main = MEC::getInstance('app.libraries.main');
$db = $main->getDB();

// Get MEC IX options
$ix = $main->get_ix_options();

// Auto sync is disabled
if(!isset($internal_cron_system) && (!isset($ix['sync_meetup_import']) || !$ix['sync_meetup_import'])) exit(__('Auto-import for Meetup is disabled!', 'mec'));
elseif(isset($internal_cron_system)) return;

$public_key = $ix['meetup_public_key'] ?? '';
$secret_key = $ix['meetup_secret_key'] ?? '';
$group_name = $ix['meetup_group_name'] ?? '';

if(!trim($public_key) || !trim($secret_key) || !trim($group_name)) exit(__('API public key, secret key, and group URL are required!', 'mec'));

// Meetup API
$meetup = $main->getMeetup();

try
{
    // Token
    $token = $meetup->get_token();

    // Upcoming Events
    $events = $meetup->get_group_events($token, $group_name);

    // Timezone
    $timezone = $main->get_timezone();

    // MEC File
    $file = $main->getFile();
    $wp_upload_dir = wp_upload_dir();
    
    // Imported Events
    $posts = [];

    if(isset($events['data']['groupByUrlname']['upcomingEvents']['edges']))
    {
        foreach($events['data']['groupByUrlname']['upcomingEvents']['edges'] as $edge)
        {
            try
            {
                $data = $meetup->get_event($token, $edge['node']['id']);
                $event = isset($data['data']['event']) && is_array($data['data']['event']) ? $data['data']['event'] : [];

                if(!count($event)) continue;
            }
            catch(Exception $e)
            {
                continue;
            }

            // Event Title and Content
            $title = $event['title'];
            $description = $event['description'];
            $mcal_id = $event['id'];

            // Event location
            $location = $event['venue'] ?? [];
            $location_id = 1;

            // Import Event Locations into MEC locations
            if(isset($ix['import_locations']) && $ix['import_locations'] && count($location))
            {
                $address  = $location['address'] ?? '';
                $address .= isset($location['city']) ? ', '.$location['city'] : '';
                $address .= isset($location['state']) ? ', '.$location['state'] : '';
                $address .= isset($location['country']) ? ', '.$location['country'] : '';

                $location_id = $main->save_location([
                    'name' => trim($location['name']),
                    'latitude' => trim($location['lat']),
                    'longitude' => trim($location['lng']),
                    'address' => $address
                ]);
            }

            // Event Organizer
            $organizers = $event['hosts'] ?? [];
            $main_organizer_id = 1;
            $additional_organizer_ids = [];

            // Import Event Organizer into MEC organizers
            if(isset($ix['import_organizers']) && $ix['import_organizers'] && count($organizers))
            {
                $o = 1;
                foreach($organizers as $organizer)
                {
                    $organizer_id = $main->save_organizer([
                        'name' => $organizer['name'],
                        'thumbnail' => ''
                    ]);

                    if($o == 1) $main_organizer_id = $organizer_id;
                    else $additional_organizer_ids[] = $organizer_id;

                    $o++;
                }
            }

            // Timezone
            $TZ = $event['timezone'] ?? 'UTC';

            // Event Start Date and Time
            $start = strtotime($event['dateTime']);

            $date_start = new DateTime(date('Y-m-d H:i:s', $start), new DateTimeZone($TZ));
            $date_start->setTimezone(new DateTimeZone($timezone));

            $start_date = $date_start->format('Y-m-d');
            $start_hour = $date_start->format('g');
            $start_minutes = $date_start->format('i');
            $start_ampm = $date_start->format('A');

            // Event End Date and Time
            $end = strtotime($event['endTime']);

            $date_end = new DateTime(date('Y-m-d H:i:s', $end), new DateTimeZone($TZ));
            $date_end->setTimezone(new DateTimeZone($timezone));

            $end_date = $date_end->format('Y-m-d');
            $end_hour = $date_end->format('g');
            $end_minutes = $date_end->format('i');
            $end_ampm = $date_end->format('A');

            // Meetup Link
            $more_info = $event['eventUrl'] ?? '';

            // Fee Options
            $fee = 0;
            if(isset($event['feeSettings']) && is_array($event['feeSettings']))
            {
                $fee = $event['feeSettings']['amount'].' '.$event['feeSettings']['currency'];
            }

            // Event Time Options
            $allday = 0;

            // Single Event
            $repeat_status = 0;
            $repeat_type = '';
            $interval = NULL;
            $finish = $end_date;
            $year = NULL;
            $month = NULL;
            $day = NULL;
            $week = NULL;
            $weekday = NULL;
            $weekdays = NULL;

            $args = [
                'title'=>$title,
                'content'=>$description,
                'location_id'=>$location_id,
                'organizer_id'=>$main_organizer_id,
                'date'=>[
                    'start'=>[
                        'date'=>$start_date,
                        'hour'=>$start_hour,
                        'minutes'=>$start_minutes,
                        'ampm'=>$start_ampm,
                    ],
                    'end'=>[
                        'date'=>$end_date,
                        'hour'=>$end_hour,
                        'minutes'=>$end_minutes,
                        'ampm'=>$end_ampm,
                    ],
                    'repeat'=>[],
                    'allday'=>$allday,
                    'comment'=>'',
                    'hide_time'=>0,
                    'hide_end_time'=>0,
                ],
                'start'=>$start_date,
                'start_time_hour'=>$start_hour,
                'start_time_minutes'=>$start_minutes,
                'start_time_ampm'=>$start_ampm,
                'end'=>$end_date,
                'end_time_hour'=>$end_hour,
                'end_time_minutes'=>$end_minutes,
                'end_time_ampm'=>$end_ampm,
                'repeat_status'=>$repeat_status,
                'repeat_type'=>$repeat_type,
                'interval'=>$interval,
                'finish'=>$finish,
                'year'=>$year,
                'month'=>$month,
                'day'=>$day,
                'week'=>$week,
                'weekday'=>$weekday,
                'weekdays'=>$weekdays,
                'meta'=>[
                    'mec_source'=>'meetup',
                    'mec_meetup_id'=>$mcal_id,
                    'mec_meetup_series_id'=>'',
                    'mec_more_info'=>$more_info,
                    'mec_more_info_title'=>__('Check at Meetup', 'mec'),
                    'mec_more_info_target'=>'_self',
                    'mec_cost'=>$fee,
                    'mec_meetup_url'=>$group_name,
                    'mec_allday'=>$allday
                ]
            ];

            $post_id = $db->select("SELECT `post_id` FROM `#__postmeta` WHERE `meta_value`='$mcal_id' AND `meta_key`='mec_meetup_id'", 'loadResult');

            // Insert the event into MEC
            $post_id = $main->save_event($args, $post_id);
            $posts[] = $post_id;

            // Set location to the post
            if($location_id) wp_set_object_terms($post_id, (int) $location_id, 'mec_location');

            // Set organizer to the post
            if($main_organizer_id) wp_set_object_terms($post_id, (int) $main_organizer_id, 'mec_organizer');

            // Set Additional Organizers
            if(count($additional_organizer_ids))
            {
                foreach($additional_organizer_ids as $additional_organizer_id) wp_set_object_terms($post_id, (int) $additional_organizer_id, 'mec_organizer', true);
                update_post_meta($post_id, 'mec_additional_organizer_ids', $additional_organizer_ids);
            }

            // Featured Image
            if(!has_post_thumbnail($post_id) && isset($event['imageUrl']))
            {
                $photo = $main->get_web_page($event['imageUrl']);
                $file_name = md5($post_id).'.'.$main->get_image_type_by_buffer($photo);

                $path = rtrim($wp_upload_dir['path'], DS.' ').DS.$file_name;
                $url = rtrim($wp_upload_dir['url'], '/ ').'/'.$file_name;

                $file->write($path, $photo);
                $main->set_featured_image($url, $post_id);
            }
        }
    }

    if(!isset($internal_cron_system))
    {
        echo sprintf(esc_html__('%s meetup events imported/updated.', 'mec'), count($posts));
        exit;
    }
}
catch(Exception $e)
{
    if(!isset($internal_cron_system))
    {
        $error = $e->getMessage();
        exit($error);
    }
}