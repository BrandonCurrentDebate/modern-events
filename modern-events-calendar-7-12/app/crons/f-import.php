<?php
/**
 *  WordPress initializing
 */
function mec_find_wordpress_base_path_fi()
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

define('BASE_PATH', mec_find_wordpress_base_path_fi().'/');
define('WP_USE_THEMES', false);

global $wp, $wp_query, $wp_the_query, $wp_rewrite, $wp_did_header;
require BASE_PATH.'wp-load.php';

/** @var $main MEC_main **/

$main = MEC::getInstance('app.libraries.main');
$db = $main->getDB();

// Get MEC IX options
$ix = $main->get_ix_options();

// Auto sync is disabled
if(!isset($ix['sync_f_import']) || !$ix['sync_f_import']) exit(__('Auto-import from Facebook is disabled!', 'mec'));

$fb_page_link = $ix['facebook_import_page_link'] ?? NULL;
if(!trim($fb_page_link)) exit(__("Please paste the link to your Facebook page.", 'mec'));

$fb_access_token = $ix['facebook_app_token'] ?? NULL;

$fb_page_result = $main->get_web_page('https://graph.facebook.com/v12.0/?access_token='.$fb_access_token.'&id='.$fb_page_link);
$fb_page = json_decode($fb_page_result, true);

$fb_page_id = $fb_page['id'] ?? 0;
if(!$fb_page_id) exit(__("We were not able to recognize your Facebook page. Please check again and provide a valid link.", 'mec'));

$next_page = 'https://graph.facebook.com/v12.0/'.$fb_page_id.'/events/?access_token='.$fb_access_token;

// Timezone
$timezone = $main->get_timezone();

// MEC File
$file = $main->getFile();
$wp_upload_dir = wp_upload_dir();

// Imported Events
$posts = [];

do
{
    $events_result = $main->get_web_page($next_page);
    $fb_events = json_decode($events_result, true);

    // Exit the loop if no event found
    if(!isset($fb_events['data'])) break;

    foreach($fb_events['data'] as $fb_event)
    {
        $events_result = $main->get_web_page('https://graph.facebook.com/v12.0/'.$fb_event['id'].'?fields=name,place,description,start_time,end_time,cover,event_times&access_token='.$fb_access_token);
        $event = json_decode($events_result, true);

        // Event organizer
        $organizer_id = 1;

        // Event location
        $location = $event['place'] ?? [];
        
        $location_name = $location['name'];
        $location_address = trim($location_name.' '.($location['location']['city'] ?? '').' '.($location['location']['state'] ?? '').' '.($location['location']['country'] ?? '').' '.($location['location']['zip'] ?? ''), '');
        $location_id = $main->save_location(array
        (
            'name'=>trim($location_name),
            'address'=>$location_address,
            'latitude'=>$location['location']['latitude'],
            'longitude'=>$location['location']['longitude'],
        ));

        // Event Title and Content
        $title = $event['name'];
        $description = $event['description'] ?? '';

        // Event Times (Custom Events)
        $event_times = ((isset($event['event_times']) and is_array($event['event_times'])) ? $event['event_times'] : array());

        if(count($event_times))
        {
            $days = '';
            $main_datetime = [];

            $i = 1;
            foreach($event_times as $event_time)
            {
                if($i == count($event_times)) $main_datetime = $event_time;
                else
                {
                    $ds = new DateTime($event_time['start_time']);
                    $ds->setTimezone(new DateTimeZone($timezone));

                    $de = new DateTime($event_time['end_time']);
                    $de->setTimezone(new DateTimeZone($timezone));

                    $days .= $ds->format('Y-m-d').':'.$de->format('Y-m-d').':'.$ds->format('h-i-A').':'.$de->format('h-i-A').',';
                }

                $i++;
            }

            $date_start = new DateTime($main_datetime['start_time']);
            $date_start->setTimezone(new DateTimeZone($timezone));

            $start_date = $date_start->format('Y-m-d');
            $start_hour = $date_start->format('g');
            $start_minutes = $date_start->format('i');
            $start_ampm = $date_start->format('A');

            $date_end = new DateTime($main_datetime['end_time']);
            $date_end->setTimezone(new DateTimeZone($timezone));

            $end_date = $date_end->format('Y-m-d');
            $end_hour = $date_end->format('g');
            $end_minutes = $date_end->format('i');
            $end_ampm = $date_end->format('A');

            $repeat_status = 1;
            $repeat_type = 'custom_days';
            $days = trim($days, ', ');
        }
        else
        {
            $date_start = new DateTime($event['start_time']);
            $date_start->setTimezone(new DateTimeZone($timezone));

            $start_date = $date_start->format('Y-m-d');
            $start_hour = $date_start->format('g');
            $start_minutes = $date_start->format('i');
            $start_ampm = $date_start->format('A');

            $end_timestamp = isset($event['end_time']) ? strtotime($event['end_time']) : 0;
            if($end_timestamp)
            {
                $date_end = new DateTime($event['end_time']);
                $date_end->setTimezone(new DateTimeZone($timezone));
            }

            $end_date = $end_timestamp ? $date_end->format('Y-m-d') : $start_date;
            $end_hour = $end_timestamp ? $date_end->format('g') : 8;
            $end_minutes = $end_timestamp ? $date_end->format('i') : '00';
            $end_ampm = $end_timestamp ? $date_end->format('A') : 'PM';

            $repeat_status = 0;
            $repeat_type = '';
            $days = NULL;
        }

        // Event Time Options
        $allday = 0;

        $args = array
        (
            'title'=>$title,
            'content'=>$description,
            'location_id'=>$location_id,
            'organizer_id'=>$organizer_id,
            'date'=>array
            (
                'start'=>array(
                    'date'=>$start_date,
                    'hour'=>$start_hour,
                    'minutes'=>$start_minutes,
                    'ampm'=>$start_ampm,
                ),
                'end'=>array(
                    'date'=>$end_date,
                    'hour'=>$end_hour,
                    'minutes'=>$end_minutes,
                    'ampm'=>$end_ampm,
                ),
                'repeat'=>array(),
                'allday'=>$allday,
                'comment'=>'',
                'hide_time'=>0,
                'hide_end_time'=>0,
            ),
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
            'interval'=>NULL,
            'finish'=>$end_date,
            'year'=>NULL,
            'month'=>NULL,
            'day'=>NULL,
            'week'=>NULL,
            'weekday'=>NULL,
            'weekdays'=>NULL,
            'days'=>$days,
            'meta'=>array
            (
                'mec_source'=>'facebook-calendar',
                'mec_facebook_page_id'=>$fb_page_id,
                'mec_facebook_event_id'=>$fb_event['id'],
                'mec_allday'=>$allday,
                'mec_in_days'=>$days,
            )
        );

        $post_id = $db->select("SELECT `post_id` FROM `#__postmeta` WHERE `meta_value`='".$fb_event['id']."' AND `meta_key`='mec_facebook_event_id'", 'loadResult');

        // Insert the event into MEC
        $post_id = $main->save_event($args, $post_id);
        
        // Add it to the imported posts
        $posts[] = $post_id;
        
        // Set location to the post
        if($location_id) wp_set_object_terms($post_id, (int) $location_id, 'mec_location');

        if(!has_post_thumbnail($post_id) and isset($event['cover']) and is_array($event['cover']) and count($event['cover']))
        {
            $photo = $main->get_web_page($event['cover']['source']);
            $file_name = md5($post_id).'.'.$main->get_image_type_by_buffer($photo);

            $path = rtrim($wp_upload_dir['path'], DS.' ').DS.$file_name;
            $url = rtrim($wp_upload_dir['url'], '/ ').'/'.$file_name;

            $file->write($path, $photo);
            $main->set_featured_image($url, $post_id);
        }
    }

    $next_page = $fb_events['paging']['next'] ?? NULL;
}
while($next_page);

echo sprintf(esc_html__('%s Facebook events imported/updated.', 'mec'), count($posts));
exit;