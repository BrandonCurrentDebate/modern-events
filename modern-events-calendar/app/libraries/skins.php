<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC skins class.
 * @author Webnus <info@webnus.net>
 */
class MEC_skins extends MEC_base
{
    /**
     * Default skin
     * @var string
     */
    public $skin = 'list';

    /**
     * @var array
     */
    public $atts = [];

    /**
     * @var array
     */
    public $args = [];

    /**
     * @var int
     */
    public $maximum_dates = 6;

    /**
     * Offset for don't load duplicated events in list/grid views on load more action
     * @var int
     */
    public $offset = 0;

    /**
     * Offset for next load more action
     * @var int
     */
    public $next_offset = 0;

    /**
     * Display Booking Method
     * @var int
     */
    public $booking_button = 0;

    /**
     * Single Event Display Method
     * @var string
     */
    public $sed_method = '0';

    /**
     * Order Method
     * @var string
     */
    public $order_method = 'ASC';

    public $factory;
    public $main;
    public $db;
    public $file;
    public $render;
    public $found;
    public $multiple_days_method;
    public $hide_time_method;
    public $skin_options;
    public $style;
    public $show_only_expired_events;
    public $maximum_date_range = '';
    public $limit;
    public $paged;
    public $start_date;
    public $end_date;
    public $show_ongoing_events;
    public $include_ongoing_events;
    public $maximum_date = '';
    public $html_class;
    public $sf;
    public $sf_status;
    public $sf_display_label;
    public $sf_reset_button;
    public $sf_refine;
    public $sf_options;
    public $id;
    public $events;
    public $widget;
    public $count;
    public $settings;
    public $ml_settings;
    public $layout;
    public $year;
    public $month;
    public $day;
    public $next_previous_button;
    public $active_date;
    public $today;
    public $weeks;
    public $week;
    public $week_of_days;
    public $events_str;
    public $active_day;
    public $load_more_button;
    public $pagination = 'loadmore';
    public $month_divider;
    public $toggle_month_divider;
    public $image_popup;
    public $map_on_top;
    public $geolocation;
    public $geolocation_focus;
    public $include_events_times;
    public $localtime;
    public $reason_for_cancellation;
    public $display_label;
    public $display_price;
    public $display_detailed_time;
    public $display_progress_bar = false;
    public $cache;
    public $from_full_calendar = false;
    public $unique_event_ids = [];

    /**
     * Has More Events
     * @var bool
     */
    public $has_more_events = true;

    /**
     * Auto Month Rotation
     * @var bool
     */
    public $auto_month_rotation = true;

    /**
     * @var MEC_icons
     */
    public $icons;

    /**
     * Constructor method
     * @author Webnus <info@webnus.net>
     */
    public function __construct()
    {
        // MEC factory library
        $this->factory = $this->getFactory();

        // MEC main library
        $this->main = $this->getMain();

        // MEC file library
        $this->file = $this->getFile();

        // MEC db library
        $this->db = $this->getDB();

        // MEC render library
        $this->render = $this->getRender();

        // MEC Settings
        $this->settings = $this->main->get_settings();

        // Found Events
        $this->found = 0;

        // How to show multiple days events
        $this->multiple_days_method = $this->main->get_multiple_days_method();

        // Hide event on start or on end
        $this->hide_time_method = $this->main->get_hide_time_method();

        // Cache
        $this->cache = $this->getCache();

        // Icons
        $this->icons = $this->main->icons();
    }

    /**
     * Registers skin actions into WordPress hooks
     * @author Webnus <info@webnus.net>
     */
    public function actions()
    {
    }

    /**
     * Loads all skins
     * @author Webnus <info@webnus.net>
     */
    public function load()
    {
        $skins = $this->main->get_skins();
        foreach($skins as $skin=>$skin_name)
        {
            $path = MEC::import('app.skins.'.$skin, true, true);
            $skin_path = apply_filters('mec_skin_path', $skin);

            if($skin_path != $skin and $this->file->exists($skin_path)) $path = $skin_path;
            if(!$this->file->exists($path)) continue;

            include_once $path;

            $skin_class_name = 'MEC_skin_'.$skin;

            // Create Skin Object Class
            $SKO = new $skin_class_name();

            // init the actions
            $SKO->actions();
        }

        // Init Single Skin
        include_once MEC::import('app.skins.single', true, true);

        // Register the actions
        $SKO = new MEC_skin_single();
        $SKO->actions();
    }

    /**
     * Get path of one skin file
     * @author Webnus <info@webnus.net>
     * @param string $file
     * @return string
     */
    public function get_path($file = 'tpl')
    {
        return MEC::import('app.skins.'.$this->skin.'.'.$file, true, true);
    }

    /**
     * Returns path of skin tpl
     * @author Webnus <info@webnus.net>
     * @return string
     */
    public function get_tpl_path()
    {
        $path = $this->get_path();

        // Apply filters
        $settings = $this->main->get_settings();

        if('single' === $this->skin)
        {
            $single_style = $settings['single_single_style'] ?? '';
            $single_style = apply_filters( 'mec_filter_single_style', $single_style );
            $filtered_path = apply_filters('mec_get_skin_tpl_path', $this->skin, $single_style, $path);
        }
        else
        {
            $filtered_path = apply_filters('mec_get_skin_tpl_path', $this->skin, $this->style, $path);
        }

        if($filtered_path != $this->skin and $this->file->exists($filtered_path)) $path = $filtered_path;

        return $path;
    }

    /**
     * Returns path of skin render file
     * @author Webnus <info@webnus.net>
     * @return string
     */
    public function get_render_path()
    {
        $path = $this->get_path('render');

        // Apply filters
        $filtered_path = apply_filters('mec_get_skin_render_path', $this->skin);
        if($filtered_path != $this->skin and $this->file->exists($filtered_path)) $path = $filtered_path;

        return $path;
    }

    /**
     * Returns calendar file path of calendar views
     * @author Webnus <info@webnus.net>
     * @param string $style
     * @return string
     */
    public function get_calendar_path($style = 'calendar')
    {
        $path = $this->get_path($style);

        // Apply filters
        $filtered_path = apply_filters('mec_get_skin_calendar_path', $this->skin);
        if($filtered_path != $this->skin and $this->file->exists($filtered_path)) $path = $filtered_path;

        return $path;
    }

    /**
     * Generates skin output
     * @author Webnus <info@webnus.net>
     * @return string
     */
    public function output()
    {
        if(!$this->main->getPRO() and in_array($this->skin, array('agenda', 'yearly_view', 'timetable', 'masonry', 'map', 'available_spot')))
        {
            return '';
        }

        // Include needed assets for loading single event details page
        if($this->sed_method === 'm1') $this->main->load_sed_assets($this->settings);

        $custom_output = apply_filters('mec_skin_output_html', null, $this);
        if(!is_null($custom_output)) return $custom_output;

        ob_start();
        include $this->get_tpl_path();
        return ob_get_clean();
    }

    /**
     * Returns keyword query for adding to WP_Query
     * @author Webnus <info@webnus.net>
     * @return null|string
     */
    public function keyword_query()
    {
        // Add keyword to filters
        if(isset($this->atts['s']) and trim($this->atts['s']) != '') return $this->atts['s'];
        else return NULL;
    }

    /**
     * Returns taxonomy query for adding to WP_Query
     * @author Webnus <info@webnus.net>
     * @return array
     */
    public function tax_query()
    {
        $tax_query = array('relation'=>'AND');

        // Include label to filter
        if(isset($this->atts['label']) and trim($this->atts['label'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_label',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['label'], ', '))
            );
        }

        // Exclude label from filter
        if(isset($this->atts['ex_label']) and trim($this->atts['ex_label'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_label',
                'field'=>'term_id',
                'operator'=>'NOT IN',
                'terms'=>explode(',', trim($this->atts['ex_label'], ', '))
            );
        }

        // Include category to filter
        if(isset($this->atts['category']) and trim($this->atts['category'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_category',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['category'], ', '))
            );
        }

        // Exclude category from filter
        if(isset($this->atts['ex_category']) and trim($this->atts['ex_category'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_category',
                'field'=>'term_id',
                'operator'=>'NOT IN',
                'terms'=>explode(',', trim($this->atts['ex_category'], ', '))
            );
        }

        // Include location to filter
        if(isset($this->atts['location']) and trim($this->atts['location'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_location',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['location'], ', '))
            );
        }

        // Exclude location from filter
        if(isset($this->atts['ex_location']) and trim($this->atts['ex_location'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_location',
                'field'=>'term_id',
                'operator'=>'NOT IN',
                'terms'=>explode(',', trim($this->atts['ex_location'], ', '))
            );
        }

        // Add event address to filter
        if(isset($this->atts['address']) and trim($this->atts['address'], ', ') != '')
        {
            $get_locations_id = $this->get_locations_id($this->atts['address']);
            $tax_query[] = array(
                'taxonomy'=>'mec_location',
                'field'=>'term_id',
                'terms'=>$get_locations_id,
            );
        }

        // Include organizer to filter
        if(isset($this->atts['organizer']) and trim($this->atts['organizer'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_organizer',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['organizer'], ', '))
            );
        }

        // Exclude location from filter
        if(isset($this->atts['ex_organizer']) and trim($this->atts['ex_organizer'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_organizer',
                'field'=>'term_id',
                'operator'=>'NOT IN',
                'terms'=>explode(',', trim($this->atts['ex_organizer'], ', '))
            );
        }

        // Include sponsor to filter
        if(isset($this->atts['sponsor']) and trim($this->atts['sponsor'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_sponsor',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['sponsor'], ', '))
            );
        }

        // Include speaker to filter
        if(isset($this->atts['speaker']) and trim($this->atts['speaker'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_speaker',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['speaker'], ', '))
            );
        }

        // Include Event Type 1
        if(isset($this->atts['event_type']) and trim($this->atts['event_type'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_event_type',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['event_type'], ', '))
            );
        }

        // Include Event Type 2
        if(isset($this->atts['event_type_2']) and trim($this->atts['event_type_2'], ', ') != '')
        {
            $tax_query[] = array(
                'taxonomy'=>'mec_event_type_2',
                'field'=>'term_id',
                'terms'=>explode(',', trim($this->atts['event_type_2'], ', '))
            );
        }

        // Include tags to filter
        if(apply_filters('mec_taxonomy_tag', '') !== 'post_tag' and isset($this->atts['tag']) and trim($this->atts['tag'], ', ') != '')
        {
            if(is_numeric($this->atts['tag']))
            {
                $tax_query[] = array(
                    'taxonomy'=>'mec_tag',
                    'field'=>'term_id',
                    'terms'=>explode(',', trim($this->atts['tag'], ', '))
                );
            }
            else
            {
                $tax_query[] = array(
                    'taxonomy'=>'mec_tag',
                    'field'=>'name',
                    'terms'=>explode(',', trim($this->atts['tag'], ', '))
                );
            }
        }

        // Exclude tags from filter
        if(isset($this->atts['ex_tag']) and trim($this->atts['ex_tag'], ', ') != '')
        {
            if(is_numeric($this->atts['ex_tag']))
            {
                $tax_query[] = array(
                    'taxonomy'=>apply_filters('mec_taxonomy_tag', ''),
                    'field'=>'term_id',
                    'operator'=>'NOT IN',
                    'terms'=>explode(',', trim($this->atts['ex_tag'], ', '))
                );
            }
            else
            {
                $tax_query[] = array(
                    'taxonomy'=>apply_filters('mec_taxonomy_tag', ''),
                    'field'=>'name',
                    'operator'=>'NOT IN',
                    'terms'=>explode(',', trim($this->atts['ex_tag'], ', '))
                );
            }
        }

        return apply_filters('mec_map_tax_query', $tax_query, $this->atts);
    }

    /**
     * Returns meta query for adding to WP_Query
     * @author Webnus <info@webnus.net>
     * @return array
     */
    public function meta_query()
    {
        $meta_query = [];
        $meta_query['relation'] = 'AND';

        // Event Min Cost
        if(isset($this->atts['cost-min']) and trim($this->atts['cost-min']) != '')
        {
            $meta_query[] = array(
                'key'     => 'mec_cost',
                'value'   => $this->atts['cost-min'],
                'type'    => 'numeric',
                'compare' => '>=',
            );
        }

        // Event Max Cost
        if(isset($this->atts['cost-max']) and trim($this->atts['cost-max']) != '')
        {
            $meta_query[] = array(
                'key'     => 'mec_cost',
                'value'   => $this->atts['cost-max'],
                'type'    => 'numeric',
                'compare' => '<=',
            );
        }

        // Event Fields
        if(isset($this->atts['fields']) and is_array($this->atts['fields']) and count($this->atts['fields']))
        {
            foreach($this->atts['fields'] as $field_id => $field_value)
            {
                if(is_array($field_value) and isset($field_value['date_min'], $field_value['date_max']) and trim($field_value['date_min']) and trim($field_value['date_max']))
                {
                    $meta_query[] = array(
                        'key'     => 'mec_fields_'.$field_id,
                        'value'   => array($field_value['date_min'], $field_value['date_max']),
                        'type'    => 'DATE',
                        'compare' => 'BETWEEN',
                    );
                }
                elseif(is_string($field_value) and trim($field_value) !== '')
                {
                    $meta_query[] = array(
                        'key'     => 'mec_fields_'.$field_id,
                        'value'   => $field_value,
                        'compare' => 'LIKE',
                    );
                }
            }
        }

        // Event Status
        if(isset($this->atts['event_status']) && !empty($this->atts['event_status']) && trim($this->atts['event_status']) != 'all'){

            $meta_query[] = array(
                'key'     => 'mec_event_status',
                'value'   => $this->atts['event_status'],
                'compare' => '=',
            );
        }

        return apply_filters('mec_map_meta_query', $meta_query, $this->atts);
    }

    /**
     * Returns tag query for adding to WP_Query
     * @author Webnus <info@webnus.net>
     * @return string
     */
    public function tag_query()
    {
        $tag = '';

        // Add event tags to filter
        if(isset($this->atts['tag']) and trim($this->atts['tag'], ', ') != '')
        {
            if(is_numeric($this->atts['tag']))
            {
                $term = get_term_by('id', $this->atts['tag'], apply_filters('mec_taxonomy_tag', ''));
                if($term) $tag = $term->slug;
            }
            else
            {
                $tags = explode(',', $this->atts['tag']);
                foreach($tags as $t)
                {
                    $term = get_term_by('name', $t, apply_filters('mec_taxonomy_tag', ''));
                    if($term) $tag .= $term->slug.',';
                }
            }
        }

        return trim($tag, ', ');
    }

    /**
     * Returns author query for adding to WP_Query
     * @author Webnus <info@webnus.net>
     * @return array
     */
    public function author_query()
    {
        $author = '';

        // Add event authors to filter
        if(isset($this->atts['author']) and trim($this->atts['author'], ', ') != '')
        {
            $author = $this->atts['author'];
        }

        return $author;
    }

    public function author_query_ex()
    {
        $author = [];

        // Exclude event authors from filter
        if(isset($this->atts['ex_author']) and trim($this->atts['ex_author'], ', ') != '')
        {
            $author = explode(',', $this->atts['ex_author']);
        }

        return $author;
    }

    /**
     * Set the current day for filtering events in WP_Query
     * @author Webnus <info@webnus.net>
     * @param String $today
     * @return void
     */
    public function setToday($today = NULL)
    {
        if(is_null($today)) $today = date('Y-m-d');

        $this->args['mec-today'] = $today;
        $this->args['mec-now'] = strtotime($this->args['mec-today']);

        $this->args['mec-year'] = date('Y', $this->args['mec-now']);
        $this->args['mec-month'] = date('m', $this->args['mec-now']);
        $this->args['mec-day'] = date('d', $this->args['mec-now']);

        $this->args['mec-week'] = (int) ((date('d', $this->args['mec-now']) - 1) / 7) + 1;
        $this->args['mec-weekday'] = date('N', $this->args['mec-now']);
    }

    /**
     * Join MEC table with WP_Query for filtering the events
     * @author Webnus <info@webnus.net>
     * @param string $join
     * @param object $wp_query
     * @return string
     */
    public function join($join, $wp_query)
    {
        if(is_string($wp_query->query_vars['post_type']) and $wp_query->query_vars['post_type'] == $this->main->get_main_post_type() and $wp_query->get('mec-init', false))
        {
            $join .= $this->db->_prefix(" LEFT JOIN `#__mec_events` AS mece ON #__posts.ID = mece.post_id LEFT JOIN `#__mec_dates` AS mecd ON #__posts.ID = mecd.post_id");
        }

        return $join;
    }

    /**
     * @param string $start
     * @param string $end
     * @param boolean $exclude
     * @return array
     */
    public function period($start, $end, $exclude = false)
    {
        // Search till the end of End Date!
        if(!$this->show_only_expired_events and $this->order_method === 'ASC' and date('H:i:s', strtotime($end)) == '00:00:00') $end .= ' 23:59:59';

        // Search From last second of start date
        if($this->show_only_expired_events or $this->order_method === 'DESC')
        {
            if(date('Y-m-d', strtotime($start)) !== current_time('Y-m-d') and date('H:i:s', strtotime($start)) == '00:00:00') $start .= ' 23:59:59';
            elseif(date('Y-m-d', strtotime($start)) === current_time('Y-m-d') and date('H:i:s', strtotime($start)) == '00:00:00') $start .= ' '.current_time('H:i:s');
        }

        $seconds_start = strtotime($start);
        $seconds_end = strtotime($end);

        $order = "`tstart` ASC, `id` ASC";
        $where_OR = "(`tstart`>='".$seconds_start."' AND `tend`<='".$seconds_end."') OR (`tstart`<='".$seconds_end."' AND `tend`>='".$seconds_end."') OR (`tstart`<='".$seconds_start."' AND `tend`>='".$seconds_start."')";
        // (Start: In, Finish: In) OR (Start: Before or In, Finish: After) OR (Start: Before, Finish: In or After)

        if($this->show_only_expired_events or $this->order_method === 'DESC')
        {
            $column = 'tstart';

            if($this->hide_time_method == 'plus1') $seconds_start -= 3600;
            elseif($this->hide_time_method == 'plus2') $seconds_start -= 7200;
            elseif($this->hide_time_method == 'plus10') $seconds_start -= 36000;
            elseif($this->hide_time_method == 'end') $column = 'tend';

            $order = "`tstart` DESC, `id` DESC";

            $where_OR = "`".$column."`<'".$seconds_start."'";
            if($column != 'tend') $where_OR .= " AND `tend`<'".$seconds_start."'";

            // Fix for Tile skin
            if($this->skin === 'tile' && $this->next_previous_button) $where_OR .= " AND `tstart`>='".$seconds_end."'";
        }
        elseif($this->show_ongoing_events)
        {
            $now = current_time('timestamp');
            if(in_array($this->skin, ['list', 'grid']) && !(strpos($this->style, 'fluent') === false || strpos($this->style, 'liquid') === false))
            {
                if($this->skin_options['start_date_type'] != 'today')
                {
                    $startDateTime = strtotime($this->start_date) + (int) $this->main->get_gmt_offset_seconds();
                    $now = max($startDateTime, $now);
                }

                $where_OR = "(`tstart`>'".$now."' AND `tend`<='".$seconds_end."')";
            }
            else
            {
                $where_OR = "(`tstart`<='".$now."' AND `tend`>='".$now."')";
            }
        }

        $where_AND = "1 AND `public`=1 AND `status`='publish'";

        // Exclude Events
        if(isset($this->atts['exclude']) and is_array($this->atts['exclude']) and count($this->atts['exclude'])) $where_AND .= " AND `post_id` NOT IN (".implode(',', $this->atts['exclude']).")";

        // Include Events
        if(isset($this->atts['include']) and is_array($this->atts['include']) and count($this->atts['include'])) $where_AND .= " AND `post_id` IN (".implode(',', $this->atts['include']).")";

        $query = "SELECT * FROM `#__mec_dates` WHERE (".$where_OR.") AND (".$where_AND.") ORDER BY ".$order;
        $mec_dates = $this->db->select($query);

        // Today and Now
        $today = current_time('Y-m-d');
        $now = current_time('timestamp');

        // Midnight Hour
        $midnight_hour = (isset($this->settings['midnight_hour']) and $this->settings['midnight_hour']) ? $this->settings['midnight_hour'] : 0;

        // Local Time Filter
        $local_time_start = NULL;
        $local_time_start_datetime = NULL;
        $local_time_end = NULL;

        if(isset($this->atts['time-start']) and trim($this->atts['time-start'])) $local_time_start = $this->atts['time-start'];
        if(isset($this->atts['time-end']) and trim($this->atts['time-end'])) $local_time_end = $this->atts['time-end'];

        // Local Timezone
        $local_timezone = NULL;
        if($local_time_start or $local_time_end)
        {
            $local_timezone = $this->main->get_timezone_by_ip();
            if(!trim($local_timezone)) $local_timezone = $this->main->get_timezone();
        }

        $dates = [];
        foreach($mec_dates as $mec_date)
        {
            $s = strtotime($mec_date->dstart);
            $e = strtotime($mec_date->dend);

            // Skip Events Based on Local Start Time Search
            if($local_time_start)
            {
                $local_time_start_datetime = $mec_date->dstart.' '.$local_time_start;

                // Local Current Time
                $local = new DateTime($local_time_start_datetime, new DateTimeZone($local_timezone));

                $event_timezone = $this->main->get_timezone($mec_date->post_id);
                $local_time_in_event_timezone = $local->setTimezone(new DateTimeZone($event_timezone))->format('Y-m-d H:i:s');

                if(strtotime($local_time_in_event_timezone) > $mec_date->tstart) continue;
            }

            // Skip Events Based on Local End Time Search
            if($local_time_end)
            {
                $local_time_end_datetime = ($this->atts['date-range-end'] ?? $mec_date->dstart).' '.$local_time_end;

                // End Time is Earlier than Start Time so Add 1 Day to the End Date
                if($local_time_start_datetime and strtotime($local_time_end_datetime) <= strtotime($local_time_start_datetime)) $local_time_end_datetime = date('Y-m-d', strtotime('+1 Day', strtotime($mec_date->dend))).' '.$local_time_end;

                // Local Current Time
                $local = new DateTime($local_time_end_datetime, new DateTimeZone($local_timezone));

                $event_timezone = $this->main->get_timezone($mec_date->post_id);
                $local_time_in_event_timezone = $local->setTimezone(new DateTimeZone($event_timezone))->format('Y-m-d H:i:s');

                if(strtotime($local_time_in_event_timezone) < $mec_date->tend) continue;
            }

            // Hide Events Based on Start Time
            if(!$this->include_ongoing_events and !$this->show_ongoing_events and !$this->show_only_expired_events and !$this->args['mec-past-events'] and $s <= strtotime($today))
            {
                if($this->hide_time_method == 'start' and $now >= $mec_date->tstart) continue;
                elseif($this->hide_time_method == 'plus1' and $now >= $mec_date->tstart+3600) continue;
                elseif($this->hide_time_method == 'plus2' and $now >= $mec_date->tstart+7200) continue;
                elseif($this->hide_time_method == 'plus10' and $now >= $mec_date->tstart+36000) continue;
            }

            // Hide Events Based on End Time
            if(!$this->show_only_expired_events and !$this->args['mec-past-events'] and $e <= strtotime($today))
            {
                if($this->hide_time_method == 'end' and $now >= $mec_date->tend) continue;
            }

            if(($this->multiple_days_method == 'first_day' or ($this->multiple_days_method == 'first_day_listgrid' and in_array($this->skin, array('list', 'grid', 'slider', 'carousel', 'agenda', 'tile')))))
            {
                // Hide Shown Events on AJAX
                if(defined('DOING_AJAX') and DOING_AJAX and $s != $e and $s < strtotime($start) and !$this->include_ongoing_events and !$this->show_only_expired_events and $this->order_method === 'ASC') continue;

                $d = date('Y-m-d', $s);

                if(!isset($dates[$d])) $dates[$d] = [];
                $dates[$d][] = $mec_date->post_id;
            }
            else
            {
                $diff = $this->main->date_diff($mec_date->dstart, $mec_date->dend);
                $days_long = (isset($diff->days) and !$diff->invert) ? $diff->days : 0;

                while($s <= $e)
                {
                    if((!$this->show_only_expired_events and $this->order_method === 'ASC' and $seconds_start <= $s and $s <= $seconds_end) or (($this->show_only_expired_events or $this->order_method === 'DESC') and $seconds_start >= $s and $s >= $seconds_end))
                    {
                        $d = date('Y-m-d', $s);
                        if(!isset($dates[$d])) $dates[$d] = [];

                        // Check for exclude events
                        if($exclude)
                        {
                            $current_id = !isset($current_id) ? 0 : $current_id;

                            if(!isset($not_in_day))
                            {
                                $query = "SELECT `post_id`,`not_in_days` FROM `#__mec_events`";
                                $not_in_day = $this->db->select($query);
                            }

                            if(array_key_exists($mec_date->post_id, $not_in_day) and trim($not_in_day[$mec_date->post_id]->not_in_days))
                            {
                                $days = $not_in_day[$mec_date->post_id]->not_in_days;
                                $current_id = $mec_date->post_id;
                            }
                            else $days = '';

                            if(strpos($days, $d) === false)
                            {
                                $midnight = $s+(3600*$midnight_hour);
                                if($days_long == '1' and $midnight >= $mec_date->tend) break;

                                $dates[$d][] = $mec_date->post_id;
                            }
                        }
                        else
                        {
                            $midnight = $s+(3600*$midnight_hour);
                            if($days_long == '1' and $midnight >= $mec_date->tend) break;

                            $dates[$d][] = $mec_date->post_id;
                        }
                    }

                    $s += 86400;
                }
            }
        }

        $one_occurrence_sql = "SELECT `post_id`, `tstart` FROM `#__mec_dates` WHERE `tstart` >= $now AND `tstart` <= $seconds_end ORDER BY `tstart` ASC";
        if($this->hide_time_method == 'end') $one_occurrence_sql = "SELECT `post_id`, `tstart` FROM `#__mec_dates` WHERE `tend` >= $now AND `tstart` <= $seconds_end ORDER BY `tstart` ASC";
        if($this->include_ongoing_events) $one_occurrence_sql = "SELECT `post_id`, `tstart` FROM `#__mec_dates` WHERE (`tstart` >= $now AND `tstart` <= $seconds_end) OR (`tstart` <= $now AND `tend` >= $now) ORDER BY `tstart` ASC";

        // Show only one occurrence of events
        $first_event = $this->db->select($one_occurrence_sql);

        // Force to Show Only Once Occurrence Based on Shortcode Options
        $shortcode_display_one_occurrence = isset($this->atts['show_only_one_occurrence']) && $this->atts['show_only_one_occurrence'];

        $did_one_occurrence = [];
        foreach($dates as $date => $event_ids)
        {
            if(!is_array($event_ids) || !count($event_ids)) continue;

            // Add to Unique Event IDs
            $this->unique_event_ids = array_merge($this->unique_event_ids, $event_ids);

            foreach($event_ids as $index => $event_id)
            {
                $one_occurrence = get_post_meta($event_id, 'one_occurrence', true);
                if($one_occurrence != '1' && !$shortcode_display_one_occurrence) continue;

                if(isset($first_event[$event_id]->tstart) and date('Y-m-d', strtotime($date)) != date('Y-m-d', $first_event[$event_id]->tstart))
                {
                    $dates[$date][$index] = '';
                }
                else
                {
                    if(in_array($event_id, $did_one_occurrence)) $dates[$date][$index] = '';
                    else $did_one_occurrence[] = $event_id;
                }
            }
        }

        // Remove Global Exceptional Dates
        $global_exceptional_dates = isset($this->settings['global_exceptional_days']) && is_array($this->settings['global_exceptional_days']) ? $this->settings['global_exceptional_days'] : [];
        foreach($global_exceptional_dates as $k => $e)
        {
            if(!is_numeric($k)) continue;
            $e = $this->main->standardize_format($e);

            if(isset($dates[$e])) unset($dates[$e]);
        }

        // Make the event ids Unique
        $this->unique_event_ids = array_unique($this->unique_event_ids);

        // Initialize Metadata of Events
        $this->cache_mec_events();

        return $dates;
    }

    /**
     * Perform the search
     * @return array of objects \stdClass
     * @throws Exception
     * @author Webnus <info@webnus.net>
     */
    public function search()
    {
        global $MEC_Events_dates;
        if($this->show_only_expired_events)
        {
            $apply_sf_date = isset($_REQUEST['apply_sf_date']) ? sanitize_text_field($_REQUEST['apply_sf_date']) : 1;
            $sf = (isset($_REQUEST['sf']) and is_array($_REQUEST['sf'])) ? $this->main->sanitize_deep_array($_REQUEST['sf']) : [];

            $start = ((isset($this->sf) || $sf) and $apply_sf_date) ? date('Y-m-t', strtotime($this->start_date)) : $this->start_date;
            $end = date('Y-m-01', strtotime('-15 Years', strtotime($start)));
        }
        elseif($this->order_method === 'DESC')
        {
            $start = $this->start_date;
            $end = date('Y-m-01', strtotime('-15 Years', strtotime($start)));
        }
        else
        {
            $start = $this->start_date;
            $end = date('Y-m-t', strtotime('+15 Years', strtotime($start)));
        }

        // Set a certain maximum date from shortcode page.
        if(trim($this->maximum_date) == '' and (isset($this->maximum_date_range) and trim($this->maximum_date_range))) $this->maximum_date = $this->maximum_date_range;

        // Date Events
        $dates = $this->period($start, $end, true);

        // Limit
        $this->args['posts_per_page'] = apply_filters('mec_skins_search_posts_per_page', 100);
        $dates = apply_filters('mec_event_dates_search', $dates, $start, $end, $this);

        $last_timestamp = NULL;
        $last_event_id = NULL;

        $i = 0;
        $found = 0;
        $events = [];
        $qs = [];

        foreach($dates as $date=>$IDs)
        {
            // No Event
            if(!is_array($IDs) or (is_array($IDs) and !count($IDs))) continue;

            // Check Finish Date
            if(isset($this->maximum_date) and trim($this->maximum_date) and ((strtotime($date) > strtotime($this->maximum_date) and $this->order_method === 'ASC') or (strtotime($date) < strtotime($this->maximum_date) and $this->order_method === 'DESC'))) break;

            // Include Available Events
            $this->args['post__in'] = array_unique($IDs);

            // Count of events per day
            $IDs_count = array_count_values($IDs);

            // Extending the end date
            $this->end_date = $date;

            // Continue to load rest of events in the first date
            if($i === 0 and $this->start_date === $date) $this->args['offset'] = $this->offset;
            // Load all events in the rest of dates
            else
            {
                $this->offset = 0;
                $this->args['offset'] = 0;
            }

            // The Query
            $this->args = apply_filters('mec_skin_query_args', $this->args, $this);

            // Query Key
            $q_key = base64_encode(json_encode($this->args));

            // Get From Cache
            if(isset($qs[$q_key])) $query = $qs[$q_key];
            // Search & Cache
            else
            {
                $query = new WP_Query($this->args);
                $qs[$q_key] = $query;
            }

            if($query->have_posts())
            {
                if(!isset($events[$date])) $events[$date] = [];

                // Day Events
                $d = [];

                // The Loop
                while($query->have_posts())
                {
                    $query->the_post();
                    $ID = get_the_ID();

                    $ID_count = $IDs_count[$ID] ?? 1;
                    for($i = 1; $i <= $ID_count; $i++)
                    {
                        $rendered = $this->render->data($ID);

                        $data = new stdClass();
                        $data->ID = $ID;
                        $data->data = $rendered;

                        $data->date = array
                        (
                            'start' => array('date'=>$date),
                            'end' => array('date'=>$this->main->get_end_date($date, $rendered))
                        );

                        $event_data = $this->render->after_render($data, $this, $i);
                        $date_times = $this->get_event_datetimes($event_data);

                        $last_timestamp = $event_data->data->time['start_timestamp'];
                        $last_event_id = $ID;

                        // global variable for use dates
                        $MEC_Events_dates[$ID][] = $date_times;

                        $d[] = $event_data;
                        $found++;
                    }

                    if($found >= $this->limit)
                    {
                        // Next Offset
                        $this->next_offset = ($query->post_count-($query->current_post+1)) >= 0 ? ($query->current_post+1)+$this->offset : 0;

                        usort($d, [$this, 'sort_day_events']);
                        $events[$date] = $d;

                        // Restore original Post Data
                        wp_reset_postdata();

                        break 2;
                    }
                }

                usort($d, [$this, 'sort_day_events']);
                $events[$date] = $d;
            }

            // Restore original Post Data
            wp_reset_postdata();

            $i++;
        }

        // Initialize Occurrences' Data
        MEC_feature_occurrences::fetch($events);

        // Set Offset for Last Page
        if($found < $this->limit)
        {
            // Next Offset
            $this->next_offset = $found + ((isset($date) and $this->start_date === $date) ? $this->offset : 0);
        }

        // Set found events
        $this->found = $found;

        // Has More Events
        if($last_timestamp and $last_event_id) $this->has_more_events = (boolean) $this->db->select("SELECT COUNT(id) FROM `#__mec_dates` WHERE `tstart` > ".$last_timestamp." OR (`tstart` = ".$last_timestamp." AND `post_id`!='".$last_event_id."')", 'loadResult');

        $event_include=array();
        $occurrences_status = (isset($this->settings['per_occurrences_status']) and $this->settings['per_occurrences_status'] );
        if(isset($this->atts['location']) and trim($this->atts['location'], ', ') != '' and $occurrences_status)
        {
            $include_location = explode(',', trim($this->atts['location'], ', '));
            foreach ($events as $date=>$event_details){
                foreach($event_details as $event)
                {
                    $location_id = $this->main->get_master_location_id($event);
                    if (in_array($location_id, $include_location) || in_array($event->data->meta['mec_location_id'], $include_location)) {
                        $event_include[$date]=$event_details;
                    }
                }
            }
        }

        if(isset($this->atts['organizer']) and trim($this->atts['organizer'], ', ') != '' and $occurrences_status)
        {
            $include_organizer = explode(',', trim($this->atts['organizer'], ', '));
            foreach ($events as $date=>$event_details){
                foreach($event_details as $event)
                {
                    $organizer_id = $this->main->get_master_organizer_id($event);
                    if (in_array($organizer_id, $include_organizer) || in_array($event->data->meta['mec_organizer_id'], $include_organizer)) {
                        $event_include[$date]=$event_details;
                    }
                }
            }
        }

        if(count($event_include)>0){
            $events = $event_include;
        }

        return $events;
    }

    public function get_event_datetimes($event)
    {
        $start_date = $event->date['start']['date'];
        $start_time = $event->data->time['start'];
        $start_datetime = esc_html__('All Day', 'mec') !== $start_time ? "$start_date $start_time" : $start_date;
        $start_timestamp = strtotime( $start_datetime );

        $end_date = $event->date['end']['date'];
        $end_time = $event->data->time['end'];
        $end_datetime = esc_html__('All Day', 'mec') !== $end_time ? "$end_date $end_time" : $end_date;
        $end_timestamp = strtotime( $end_datetime );

        return array(
            'start' => array(
                'date' => $start_date,
                'time' => $start_time,
                'timestamp' => $start_timestamp,
            ),
            'end' => array(
                'date' => $end_date,
                'time' => $end_time,
                'timestamp' => $end_timestamp,
            ),
        );
    }

    /**
     * Run the search command
     * @return array of objects
     * @throws Exception
     * @author Webnus <info@webnus.net>
     */
    public function fetch()
    {
        // Events! :)
        return $this->events = $this->search();
    }

    /**
     * Draw Monthly Calendar
     * @author Webnus <info@webnus.net>
     * @param string|int $month
     * @param string|int $year
     * @param array $events
     * @param string $style
     * @return string
     */
    public function draw_monthly_calendar($year, $month, $events = array(), $style = 'calendar')
    {
        $calendar_path = $this->get_calendar_path($style);

        // Generate Month
        ob_start();
        include $calendar_path;
        return ob_get_clean();
    }

    /**
     * @param object $event
     * @return string
     */
    public function get_event_classes($event)
    {
        // Labels are not set
        if(!isset($event->data) || !isset($event->data->labels)) return NULL;

        // No Labels
        if(!is_array($event->data->labels) or (is_array($event->data->labels) and !count($event->data->labels))) return NULL;

        $classes = '';
        foreach($event->data->labels as $label)
        {
            if(!isset($label['style']) || !trim($label['style'])) continue;
            $classes .= ' '.$label['style'];
        }

        return trim($classes);
    }

    /**
     * Generates Search Form
     * @author Webnus <info@webnus.net>
     * @return string
     */
    public function sf_search_form()
    {
        // If no fields specified
        if(!count($this->sf_options)) return '';

        $display_style = $fields = '';
        $first_row = 'not-started';
        $display_form = [];

        foreach($this->sf_options as $field=>$options)
        {
            // Event Fields is disabled
            if($field === 'fields' and (!isset($this->settings['display_event_fields_search']) or (isset($this->settings['display_event_fields_search']) and !$this->settings['display_event_fields_search']))) continue;

            $display_form[] = $options['type'] ?? ($field === 'fields' ? 'fields' : NULL);
            $fields_array = array('category', 'location', 'organizer', 'speaker', 'tag', 'label');
            $fields_array = apply_filters('mec_filter_fields_search_array', $fields_array);

            if(in_array($field, $fields_array) and $first_row == 'not-started')
            {
                $first_row = 'started';
                if($this->sf_options['category']['type'] == "0" and $this->sf_options['location']['type'] == '0' and $this->sf_options['organizer']['type'] == '0' and (isset($this->sf_options['speaker']['type']) && $this->sf_options['speaker']['type'] == '0') and (isset($this->sf_options['tag']['type']) && $this->sf_options['tag']['type'] == '0') and  $this->sf_options['label']['type'] == '0')
                {
                    $display_style = 'style="display: none;"';
                }

                $fields .= '<div class="mec-dropdown-wrap" ' . $display_style . '>';
            }

            if(!in_array($field, $fields_array) and $first_row == 'started')
            {
                $first_row = 'finished';
                $fields .= '</div>';
            }

            $fields .= $this->sf_search_field($field, $options, $this->sf_display_label);
        }

        $fields = apply_filters('mec_filter_fields_search_form', $fields, $this);

        $form = '';
        if(trim($fields) && (in_array('dropdown', $display_form) || in_array('simple-checkboxes', $display_form) || in_array('checkboxes', $display_form) || in_array('text_input', $display_form) || in_array('address_input', $display_form) || in_array('minmax', $display_form) || in_array('local-time-picker', $display_form) || in_array('fields', $display_form)))
        {
            $form .= '<div id="mec_search_form_'.esc_attr($this->id).'" class="mec-search-form mec-totalcal-box">';
            $form .= $fields;

            // Reset Button
            if($this->sf_reset_button) $form .='<div class="mec-search-reset-button"><button class="button mec-button" id="mec_search_form_'.esc_attr($this->id).'_reset" type="button">'.esc_html__('Reset', 'mec').'</button></div>';

            $form = apply_filters('mec_sf_search_form_end', $form, $this);

            $form .= '</div>';
        }

        return apply_filters('mec_sf_search_form', $form, $this);
    }

    /**
     * Generate a certain search field
     * @author Webnus <info@webnus.net>
     * @param string $field
     * @param array $options
     * @param int $display_label
     * @return string
     */
    public function sf_search_field($field, $options, $display_label = null)
    {
        $type = $options['type'] ?? '';

        // Field is disabled
        if(!trim($type) and $field !== 'fields') return '';

        // Status of Speakers Feature
        $speakers_status = isset($this->settings['speakers_status']) && $this->settings['speakers_status'];

        // Import
        self::import('app.libraries.walker');
        if(!function_exists('wp_terms_checklist')) include ABSPATH.'wp-admin/includes/template.php';

        $output = '';
        if($field == 'category')
        {
            $label = $this->main->m('taxonomy_category', esc_html__('Category', 'mec'));

            if($type == 'dropdown')
            {
                $output .='<div class="mec-dropdown-search">';
                if($display_label == 1) $output .= '<label for="mec_sf_category_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('folder');

                $include = (isset($this->atts['category']) and trim($this->atts['category'])) ? explode(',', trim($this->atts['category'], ', ')) : [];
                $include = $this->sf_only_valid_terms('mec_category', $include);

                $output .= wp_dropdown_categories(array
                (
                    'echo'=>false,
                    'taxonomy'=>'mec_category',
                    'name'=>' ',
                    'include'=>$include,
                    'id'=>'mec_sf_category_'.$this->id,
                    'hierarchical'=>true,
                    'show_option_none'=>$label,
                    'option_none_value'=>'',
                    'selected'=>($this->atts['category'] ?? ''),
                    'orderby'=>'name',
                    'order'=>'ASC',
                    'show_count'=>0,
                ));

                $output .= '</div>';
            }
            elseif($type == 'checkboxes' and wp_count_terms(array('taxonomy' => 'mec_category')))
            {
                $output .= '<div class="mec-checkboxes-search">';
                if($display_label == 1) $output .='<label for="mec_sf_category_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('folder');

                $selected = (isset($this->atts['category']) and trim($this->atts['category'])) ? explode(',', trim($this->atts['category'], ', ')) : [];
                $exclude = (isset($this->atts['ex_category']) and trim($this->atts['ex_category'])) ? explode(',', trim($this->atts['ex_category'], ', ')) : [];

                $output .= '<div class="mec-searchbar-category-wrap">';
                $output .= '<div id="mec_sf_category_'.esc_attr($this->id).'">';
                $output .= wp_terms_checklist(0, array
                (
                    'echo'=>false,
                    'taxonomy'=>'mec_category',
                    'selected_cats'=>$selected,
                    'checked_ontop'=>false,
                    'walker'=>(new MEC_walker(array(
                        'include'=>$selected,
                        'exclude'=>$exclude,
                        'id' => $this->id,
                    ))),
                ));

                $output .= '</div>';
                $output .= '</div>';
                $output .= '</div>';
            }
            elseif($type == 'simple-checkboxes' and wp_count_terms(array('taxonomy' => 'mec_category')))
            {
                $output .= '<div class="mec-simple-checkboxes-search">';
                $output .= $this->icons->display('folder');
                if($display_label == 1) $output .='<label for="mec_sf_category_'.esc_attr($this->id).'">'.esc_html($label).': </label>';

                $selected = (isset($this->atts['category']) and trim($this->atts['category'])) ? explode(',', trim($this->atts['category'], ', ')) : [];
                $exclude = (isset($this->atts['ex_category']) and trim($this->atts['ex_category'])) ? explode(',', trim($this->atts['ex_category'], ', ')) : [];

                $output .= '<div class="mec-searchbar-category-wrap">';
                $output .= '<ul id="mec_sf_category_'.esc_attr($this->id).'">';

                $terms_category = get_terms([
                    'taxonomy' => 'mec_category',
                    'hide_empty' => true,
                    'include' => $selected,
                    'exclude' => $exclude,
                ]);

                foreach($terms_category as $term_category)
                {
                    $output .= '<li id="mec_category-'.esc_attr($term_category->term_id).'">
                        <label class="selectit"><input value="'.esc_attr($term_category->term_id).'" title="'.esc_attr($term_category->name).'" type="checkbox" name="tax_input[mec_category][]" id="in-mec_category-'.esc_attr($term_category->term_id).'" '.(in_array($term_category->term_id, $selected) ? 'checked' : '').'> '.esc_html($term_category->name).'</label>
                    </li>';
                }

                $output .= '</ul>';
                $output .= '</div>';
                $output .= '</div>';
            }
        }
        elseif($field == 'location')
        {
            $label = $this->main->m('taxonomy_location', esc_html__('Location', 'mec'));

            if($type == 'dropdown')
            {
                $output .= '<div class="mec-dropdown-search">';
                if($display_label == 1) $output .='<label for="mec_sf_location_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('location-pin');

                $include = (isset($this->atts['location']) and trim($this->atts['location'])) ? explode(',', trim($this->atts['location'], ', ')) : [];
                $include = $this->sf_only_valid_terms('mec_location', $include);

                $output .= wp_dropdown_categories(array
                (
                    'echo'=>false,
                    'taxonomy'=>'mec_location',
                    'name'=>' ',
                    'include'=>$include,
                    'id'=>'mec_sf_location_'.$this->id,
                    'hierarchical'=>true,
                    'show_option_none'=>$label,
                    'option_none_value'=>'',
                    'selected'=>$this->atts['location'] ?? '',
                    'orderby'=>'name',
                    'order'=>'ASC',
                    'show_count'=>0,
                ));

                $output .= '</div>';
            }
            elseif($type == 'simple-checkboxes' and wp_count_terms(array('taxonomy' => 'mec_location')))
            {
                $output .= '<div class="mec-simple-checkboxes-search">';
                $output .= $this->icons->display('location-pin');
                if($display_label == 1) $output .='<label for="mec_sf_location_'.esc_attr($this->id).'">'.esc_html($label).': </label>';

                $selected = ((isset($this->atts['location']) and trim($this->atts['location'])) ? explode(',', trim($this->atts['location'], ', ')) : array());

                $output .= '<div class="mec-searchbar-location-wrap">';
                $output .= '<ul id="mec_sf_location_'.esc_attr($this->id).'">';

                $terms_location = get_terms([
                    'taxonomy' => 'mec_location',
                    'hide_empty' => true,
                    'include' => $selected,
                ]);

                foreach($terms_location as $term_location)
                {
                    $output .= '<li id="mec_location-'.esc_attr($term_location->term_id).'">
                        <label class="selectit"><input value="'.esc_attr($term_location->term_id).'" title="'.esc_attr($term_location->name).'" type="checkbox" name="tax_input[mec_location][]" id="in-mec_location-'.esc_attr($term_location->term_id).'" '.(in_array($term_location->term_id, $selected) ? 'checked' : '').'> '.esc_html($term_location->name).'</label>
                    </li>';
                }

                $output .= '</ul>';
                $output .= '</div>';
                $output .= '</div>';
            }
        }
        elseif($field == 'organizer' && (!isset($this->settings['organizers_status']) || $this->settings['organizers_status']))
        {
            $label = $this->main->m('taxonomy_organizer', esc_html__('Organizer', 'mec'));

            if($type == 'dropdown')
            {
                $output .= '<div class="mec-dropdown-search">';
                if($display_label == 1) $output .='<label for="mec_sf_organizer_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('user');

                $include = (isset($this->atts['organizer']) and trim($this->atts['organizer'])) ? explode(',', trim($this->atts['organizer'], ', ')) : [];
                $include = $this->sf_only_valid_terms('mec_organizer', $include);

                $output .= wp_dropdown_categories(array
                (
                    'echo'=>false,
                    'taxonomy'=>'mec_organizer',
                    'name'=>' ',
                    'include'=>$include,
                    'id'=>'mec_sf_organizer_'.$this->id,
                    'hierarchical'=>true,
                    'show_option_none'=>$label,
                    'option_none_value'=>'',
                    'selected'=>$this->atts['organizer'] ?? '',
                    'orderby'=>'name',
                    'order'=>'ASC',
                    'show_count'=>0,
                ));

                $output .= '</div>';
            }
            elseif($type == 'simple-checkboxes' and wp_count_terms(array('taxonomy' => 'mec_organizer')))
            {
                $output .= '<div class="mec-simple-checkboxes-search">';
                $output .= $this->icons->display('user');
                if($display_label == 1) $output .='<label for="mec_sf_organizer_'.esc_attr($this->id).'">'.esc_html($label).': </label>';

                $selected = ((isset($this->atts['organizer']) and trim($this->atts['organizer'])) ? explode(',', trim($this->atts['organizer'], ', ')) : array());

                $output .= '<div class="mec-searchbar-organizer-wrap">';
                $output .= '<ul id="mec_sf_organizer_'.esc_attr($this->id).'">';

                $terms_organizer = get_terms([
                    'taxonomy' => 'mec_organizer',
                    'hide_empty' => true,
                    'include' => $selected,
                ]);

                foreach($terms_organizer as $term_organizer)
                {
                    $output .= '<li id="mec_organizer-'.esc_attr($term_organizer->term_id).'">
                        <label class="selectit"><input value="'.esc_attr($term_organizer->term_id).'" title="'.esc_attr($term_organizer->name).'" type="checkbox" name="tax_input[mec_organizer][]" id="in-mec_organizer-'.esc_attr($term_organizer->term_id).'" '.(in_array($term_organizer->term_id, $selected) ? 'checked' : '').'> '.esc_html($term_organizer->name).'</label>
                    </li>';
                }

                $output .= '</ul>';
                $output .= '</div>';
                $output .= '</div>';
            }
        }
        elseif($field == 'speaker' and $speakers_status)
        {
            $label = $this->main->m('taxonomy_speaker', esc_html__('Speaker', 'mec'));

            if($type == 'dropdown')
            {
                $output .= '<div class="mec-dropdown-search">';
                if($display_label == 1) $output .='<label for="mec_sf_speaker_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('microphone');

                $include = (isset($this->atts['speaker']) and trim($this->atts['speaker'])) ? explode(',', trim($this->atts['speaker'], ', ')) : [];
                $include = $this->sf_only_valid_terms('mec_speaker', $include);

                $output .= wp_dropdown_categories(array
                (
                    'echo'=>false,
                    'taxonomy'=>'mec_speaker',
                    'name'=>' ',
                    'include'=>$include,
                    'id'=>'mec_sf_speaker_'.$this->id,
                    'hierarchical'=>true,
                    'show_option_none'=>$label,
                    'option_none_value'=>'',
                    'selected'=>$this->atts['speaker'] ?? '',
                    'orderby'=>'name',
                    'order'=>'ASC',
                    'show_count'=>0,
                ));

                $output .= '</div>';
            }
            elseif($type == 'simple-checkboxes' and wp_count_terms(array('taxonomy' => 'mec_speaker')))
            {
                $output .= '<div class="mec-simple-checkboxes-search">';
                $output .= $this->icons->display('microphone');
                if($display_label == 1) $output .='<label for="mec_sf_speaker_'.esc_attr($this->id).'">'.esc_html($label).': </label>';

                $selected = ((isset($this->atts['speaker']) and trim($this->atts['speaker'])) ? explode(',', trim($this->atts['speaker'], ', ')) : array());

                $output .= '<div class="mec-searchbar-speaker-wrap">';
                $output .= '<ul id="mec_sf_speaker_'.esc_attr($this->id).'">';

                $terms_speaker = get_terms([
                    'taxonomy' => 'mec_speaker',
                    'hide_empty' => true,
                    'include' => $selected,
                ]);

                foreach($terms_speaker as $term_speaker)
                {
                    $output .= '<li id="mec_speaker-'.esc_attr($term_speaker->term_id).'">
                        <label class="selectit"><input value="'.esc_attr($term_speaker->term_id).'" title="'.esc_attr($term_speaker->name).'" type="checkbox" name="tax_input[mec_speaker][]" id="in-mec_speaker-'.esc_attr($term_speaker->term_id).'" '.(in_array($term_speaker->term_id, $selected) ? 'checked' : '').'> '.esc_html($term_speaker->name).'</label>
                    </li>';
                }

                $output .= '</ul>';
                $output .= '</div>';
                $output .= '</div>';
            }
        }
        elseif($field == 'tag')
        {
            $label = $this->main->m('taxonomy_tag', esc_html__('Tag', 'mec'));

            if($type == 'dropdown')
            {
                $output .= '<div class="mec-dropdown-search">';
                if($display_label == 1) $output .='<label for="mec_sf_tag_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('tag');

                $include = (isset($this->atts['tag']) and trim($this->atts['tag'])) ? explode(',', trim($this->atts['tag'], ', ')) : [];
                $include = $this->main->convert_term_name_to_id($include, apply_filters('mec_taxonomy_tag', ''));
                $include = $this->sf_only_valid_terms(apply_filters('mec_taxonomy_tag', ''), $include);

                $output .= wp_dropdown_categories(array
                (
                    'echo'=>false,
                    'taxonomy'=>apply_filters('mec_taxonomy_tag', ''),
                    'name'=>' ',
                    'include'=>$include,
                    'id'=>'mec_sf_tag_'.$this->id,
                    'hierarchical'=>true,
                    'show_option_none'=>$label,
                    'option_none_value'=>'',
                    'selected'=>$this->atts['tag'] ?? '',
                    'orderby'=>'name',
                    'order'=>'ASC',
                    'show_count'=>0,
                ));

                $output .= '</div>';
            }
        }
        elseif($field == 'label')
        {
            $label = $this->main->m('taxonomy_label', esc_html__('Label', 'mec'));

            if($type == 'dropdown')
            {
                $output .= '<div class="mec-dropdown-search">';
                if($display_label == 1) $output .='<label for="mec_sf_label_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('pin');

                $include = (isset($this->atts['label']) and trim($this->atts['label'])) ? explode(',', trim($this->atts['label'], ', ')) : [];
                $include = $this->sf_only_valid_terms('mec_label', $include);

                $output .= wp_dropdown_categories(array
                (
                    'echo'=>false,
                    'taxonomy'=>'mec_label',
                    'name'=>' ',
                    'include'=>$include,
                    'id'=>'mec_sf_label_'.$this->id,
                    'hierarchical'=>true,
                    'show_option_none'=>$label,
                    'option_none_value'=>'',
                    'selected'=>$this->atts['label'] ?? '',
                    'orderby'=>'name',
                    'order'=>'ASC',
                    'show_count'=>0,
                ));

                $output .= '</div>';
            }
            elseif($type == 'simple-checkboxes' and wp_count_terms(array('taxonomy' => 'mec_label')))
            {
                $output .= '<div class="mec-simple-checkboxes-search">';
                $output .= $this->icons->display('pin');

                if($display_label == 1) $output .='<label for="mec_sf_label_'.esc_attr($this->id).'">'.esc_html($label).': </label>';

                $selected = ((isset($this->atts['label']) and trim($this->atts['label'])) ? explode(',', trim($this->atts['label'], ', ')) : array());
                $exclude = (isset($this->atts['ex_label']) and trim($this->atts['ex_label'])) ? explode(',', trim($this->atts['ex_label'], ', ')) : [];

                $output .= '<div class="mec-searchbar-label-wrap">';
                $output .= '<ul id="mec_sf_label_'.esc_attr($this->id).'">';

                $terms_label = get_terms([
                    'taxonomy' => 'mec_label',
                    'hide_empty' => true,
                    'include' => $selected,
                    'exclude' => $exclude,
                ]);

                foreach($terms_label as $term_label)
                {
                    $output .= '<li id="mec_label-'.esc_attr($term_label->term_id).'">
                        <label class="selectit"><input value="'.esc_attr($term_label->term_id).'" title="'.esc_attr($term_label->name).'" type="checkbox" name="tax_input[mec_label][]" id="in-mec_label-'.esc_attr($term_label->term_id).'" '.(in_array($term_label->term_id, $selected) ? 'checked' : '').'> '.esc_html($term_label->name).'</label>
                    </li>';
                }

                $output .= '</ul>';
                $output .= '</div>';
                $output .= '</div>';
            }
        }
        elseif($field == 'month_filter')
        {
            $label = esc_html__('Date', 'mec');
            if($type == 'dropdown')
            {
                $time = isset($this->start_date) ? strtotime($this->start_date) : '';
                $now = current_time('timestamp');

                $skins = ['list', 'grid', 'agenda', 'map'];
                if(isset($this->skin_options['default_view']) and $this->skin_options['default_view'] == 'list') $skins[] = 'full_calendar';

                $item = esc_html__('Select', 'mec');
                $option = in_array($this->skin, $skins) ? '<option class="mec-none-item" value="none" selected="selected">'.esc_html($item).'</option>' : '';

                $output .= '<div class="mec-date-search"><input type="hidden" id="mec-filter-none" value="'.esc_attr($item).'">';
                if($display_label == 1) $output .='<label for="mec_sf_month_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('calendar').'
                    <select id="mec_sf_month_'.esc_attr($this->id).'" title="'.esc_attr__('Month Filter', 'mec').'">
                        '.($option ? '' : '<option value="">'.esc_html__('Select Month', 'mec').'</option>');

                $output .= $option;
                $Y = date('Y', $time);

                for($i = 1; $i <= 12; $i++)
                {
                    $output .= '<option value="'.($i < 10 ? esc_attr('0'.$i) : esc_attr($i)).'">'.esc_html($this->main->date_i18n('F', mktime(0, 0, 0, $i, 10))).'</option>';
                }

                $output .= '</select>';
                $output .= '<select id="mec_sf_year_'.esc_attr($this->id).'" title="'.esc_attr__('Year Filter', 'mec').'">'.$option;

                $start_year = $min_start_year = $this->db->select("SELECT MIN(cast(meta_value as unsigned)) AS date FROM `#__postmeta` WHERE `meta_key`='mec_start_date'", 'loadResult');
                $end_year = $this->db->select("SELECT MAX(cast(meta_value as unsigned)) AS date FROM `#__postmeta` WHERE `meta_key`='mec_end_date'", 'loadResult');

                if(!trim($start_year)) $start_year = date('Y', strtotime('-4 Years', $time));
                if(!trim($end_year) or $end_year < date('Y', strtotime('+4 Years', $time))) $end_year = date('Y', strtotime('+4 Years', $time));

                if(!isset($this->atts['show_past_events']) or (isset($this->atts['show_past_events']) and !$this->atts['show_past_events']))
                {
                    $start_year = $Y;
                    $end_year = date('Y', strtotime('+8 Years', $time));
                }

                if(isset($this->show_only_expired_events) and $this->show_only_expired_events)
                {
                    $start_year = $min_start_year;
                    $end_year = $Y;
                }

                $output .= $option ? '' : '<option value="">'.esc_html__('Select Year', 'mec').'</option>';
                for($i = $start_year; $i <= $end_year; $i++)
                {
                    $selected = (!in_array($this->skin, $skins) and $i == date('Y', $now)) ? 'selected' : '';
                    $output .= '<option value="'.esc_attr($i).'" '.esc_attr($selected).'>'.esc_html($i).'</option>';
                }

                $output .= '</select></div>';
            }
            elseif($type == 'date-range-picker')
            {
                $min_date = $this->start_date ?? NULL;

                $output .= '<div class="mec-date-search">';
                if($display_label == 1) $output .='<label for="mec_sf_date_start_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('calendar').'
                    <input class="mec-col-3 mec_date_picker_dynamic_format_start" data-min="'.esc_attr($min_date).'" type="text"
                           id="mec_sf_date_start_'.esc_attr($this->id).'"
                           placeholder="'.esc_attr__('Start', 'mec').'" title="'.esc_attr__('Start', 'mec').'" autocomplete="off">
                    <input class="mec-col-3 mec_date_picker_dynamic_format_end" type="text"
                           id="mec_sf_date_end_'.esc_attr($this->id).'"
                           placeholder="'.esc_attr__('End', 'mec').'" title="'.esc_attr__('End', 'mec').'" autocomplete="off">
                </div>';
            }
        }
        elseif($field == 'time_filter')
        {
            $label = esc_html__('Time', 'mec');
            if($type == 'local-time-picker')
            {
                $this->main->load_time_picker_assets();

                $output .= '<div class="mec-time-picker-search">';
                if($display_label == 1) $output .='<label for="mec_sf_timepicker_start_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('clock').'
                    <input type="text" class="mec-timepicker-start" id="mec_sf_timepicker_start_'.esc_attr($this->id).'" placeholder="'.esc_html__('Start Time', 'mec').'" title="'.esc_html__('Start Time', 'mec').'" data-format="'.esc_attr($this->main->get_hour_format()).'" />
                    <input type="text" class="mec-timepicker-end" id="mec_sf_timepicker_end_'.esc_attr($this->id).'" placeholder="'.esc_html__('End Time', 'mec').'" title="'.esc_html__('End Time', 'mec').'" data-format="'.esc_attr($this->main->get_hour_format()).'" />
                </div>';
            }
        }
        elseif($field == 'text_search')
        {
            $label = esc_html__('Text', 'mec');
            if($type == 'text_input')
            {
                $placeholder = $options['placeholder'] ?? '';

                $output .= '<div class="mec-text-input-search">';
                if($display_label == 1) $output .='<label for="mec_sf_s_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('magnifier').'
                    <input type="search" value="'.($this->atts['s'] ?? '').'" id="mec_sf_s_'.esc_attr($this->id).'" placeholder="'.esc_attr($placeholder).'" title="'.esc_attr($placeholder).'" />
                </div>';
            }
        }
        elseif($field == 'address_search')
        {
            $label = esc_html__('Address', 'mec');
            if($type == 'address_input')
            {
                $placeholder = $options['placeholder'] ?? '';

                $output .= '<div class="mec-text-address-search">';
                if($display_label == 1) $output .='<label for="mec_sf_address_s_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('map').'
                    <input type="search" value="'.($this->atts['address'] ?? '').'" id="mec_sf_address_s_'.esc_attr($this->id).'" placeholder="'.esc_attr($placeholder).'" title="'.esc_attr($placeholder).'" />
                </div>';
            }
        }
        elseif($field == 'event_cost')
        {
            $label = esc_html__('Cost', 'mec');
            if($type == 'minmax')
            {
                $output .= '<div class="mec-minmax-event-cost">';
                if($display_label == 1) $output .='<label for="mec_sf_event_cost_min_'.esc_attr($this->id).'">'.esc_html($label).': </label>';
                $output .= $this->icons->display('credit-card').'
                    <input type="number" min="0" step="0.01" value="'.($this->atts['event-cost-min'] ?? '').'" id="mec_sf_event_cost_min_'.esc_attr($this->id).'" class="mec-minmax-price" placeholder="'.esc_attr__('Min Price', 'mec').'" title="'.esc_attr__('Min Price', 'mec').'" />
                    <input type="number" min="0" step="0.01" value="'.($this->atts['event-cost-max'] ?? '').'" id="mec_sf_event_cost_max_'.esc_attr($this->id).'" class="mec-minmax-price" placeholder="'.esc_attr__('Max Price', 'mec').'" title="'.esc_attr__('Max Price', 'mec').'" />
                </div>';
            }
        }
        elseif($field == 'fields')
        {
            $event_fields = $this->main->get_event_fields();
            foreach($options as $field_id => $field_options)
            {
                $event_field = $event_fields[$field_id] ?? [];
                $label = $event_field['label'] ?? '';
                $type = $field_options['type'] ?? '';

                // Disabled Field
                if(!$label or !$type) continue;

                $field_values = (isset($event_field['options']) and is_array($event_field['options'])) ? $event_field['options'] : [];

                if($type === 'text_input')
                {
                    $output .= '<div class="mec-text-input-search">';
                    if($display_label == 1) $output .= '<label for="mec_sf_fields_'.esc_attr($this->id).'_'.esc_attr($field_id).'">'.esc_html($label).': </label>';

                    $output .= $this->icons->display('magnifier').'
                        <input type="search" value="" class="mec-custom-event-field" data-field-id="'.esc_attr($field_id).'" id="mec_sf_fields_'.esc_attr($this->id).'_'.esc_attr($field_id).'" placeholder="'.esc_attr($label).'" title="'.esc_attr($label).'" />
                    </div>';
                }
                elseif($type === 'dropdown')
                {
                    $output .= '<div class="mec-dropdown-search">';
                    if($display_label == 1) $output .= '<label for="mec_sf_fields_'.esc_attr($this->id).'_'.esc_attr($field_id).'">'.esc_html($label).': </label>';

                    $output .= $this->icons->display('pin');
                    $output .= '<select class="mec-custom-event-field" data-field-id="'.esc_attr($field_id).'" id="mec_sf_fields_'.esc_attr($this->id).'_'.esc_attr($field_id).'" title="'.esc_attr($label).'">';
                    $output .= '<option value="">'.esc_html($label).'</option>';

                    foreach($field_values as $field_value)
                    {
                        $field_value_label = $field_value['label'] ?? null;
                        if(is_null($field_value_label)) continue;

                        $output .= '<option value="'.esc_attr($field_value_label).'">'.esc_html($field_value_label).'</option>';
                    }

                    $output .= '</select></div>';
                }
                elseif($type === 'date-range-picker')
                {
                    $min_date = $this->start_date ?? NULL;

                    $output .= '<div class="mec-date-search">';
                    if($display_label == 1) $output .= '<label for="mec_sf_fields_'.esc_attr($this->id).'_'.esc_attr($field_id).'_start">'.esc_html($label).': </label>';

                    $output .= $this->icons->display('calendar').'
                        <input class="mec-col-3 mec-custom-event-field mec_date_picker_dynamic_format_start" data-field-id="'.esc_attr($field_id).'" data-request-key="date_min" data-min="'.esc_attr($min_date).'" type="text"
                               id="mec_sf_fields_'.esc_attr($this->id).'_'.esc_attr($field_id).'_start"
                               placeholder="'.esc_attr__('Start', 'mec').'" title="'.esc_attr__('Start', 'mec').'" autocomplete="off">
                        <input class="mec-col-3 mec-custom-event-field mec_date_picker_dynamic_format_end" data-field-id="'.esc_attr($field_id).'" data-request-key="date_max" type="text"
                               id="mec_sf_fields_'.esc_attr($this->id).'_'.esc_attr($field_id).'_end"
                               placeholder="'.esc_attr__('End', 'mec').'" title="'.esc_attr__('End', 'mec').'" autocomplete="off">
                    </div>';
                }
            }
        }

        return apply_filters('mec_search_fields_to_box', $output, $field, $type, $this->atts, $this->id);
    }

    public function sf_only_valid_terms($taxonomy, $existing_terms = [])
    {
        if($this->show_only_expired_events) $event_ids = $this->main->get_expired_event_ids(current_time('timestamp'), 'publish');
        elseif(isset($this->args['mec-past-events']) and $this->args['mec-past-events']) $event_ids = $this->main->get_all_event_ids('publish');
        elseif($this->show_ongoing_events) $event_ids = $this->main->get_ongoing_event_ids(current_time('timestamp'), 'publish');
        elseif($this->include_ongoing_events)
        {
            $ongoing_ids = $this->main->get_ongoing_event_ids(current_time('timestamp'), 'publish');
            $upcoming_ids = $this->main->get_upcoming_event_ids(current_time('timestamp'), 'publish');

            $event_ids = array_merge($ongoing_ids, $upcoming_ids);
            $event_ids = array_unique($event_ids);
        }
        else $event_ids = $this->main->get_upcoming_event_ids(current_time('timestamp'), 'publish');

        $terms = [];

        $post_terms = wp_get_object_terms($event_ids, $taxonomy);
        if(is_array($post_terms)) foreach($post_terms as $post_term) $terms[] = $post_term->term_id;

        $existing_terms = array_unique($existing_terms);
        $terms = array_unique($terms);

        // No Terms
        if(!count($terms)) return [-1];

        $exclude = [];

        if($taxonomy === 'mec_category' && isset($this->atts['ex_category']) && trim($this->atts['ex_category'])) $exclude = explode(',', trim($this->atts['ex_category'], ', '));
        else if($taxonomy === 'mec_location' && isset($this->atts['ex_location']) && trim($this->atts['ex_location'])) $exclude = explode(',', trim($this->atts['ex_location'], ', '));
        else if($taxonomy === 'mec_organizer' && isset($this->atts['ex_organizer']) && trim($this->atts['ex_organizer'])) $exclude = explode(',', trim($this->atts['ex_organizer'], ', '));
        else if($taxonomy === 'mec_label' && isset($this->atts['ex_label']) && trim($this->atts['ex_label'])) $exclude = explode(',', trim($this->atts['ex_label'], ', '));
        else if($taxonomy === 'mec_tag' && isset($this->atts['ex_tag']) && trim($this->atts['ex_tag'])) $exclude = explode(',', trim($this->atts['ex_tag'], ', '));

        // Exclude Terms
        if(count($exclude))
        {
            foreach($exclude as $ex_id)
            {
                if(in_array($ex_id, $terms)) unset($terms[array_search($ex_id, $terms)]);
            }
        }

        // No Existing Terms
        if(!count($existing_terms)) return $terms;

        // Intersect
        $intersect = array_intersect($existing_terms, $terms);

        // No Intersect
        if(!count($intersect)) return $terms;

        // Return
        return $intersect;
    }

    public function sf_apply($atts, $sf = array(), $apply_sf_date = 1)
    {
        // Return normal atts if sf is empty
        if(!count($sf)) return $atts;

        // Apply Text Search Query
        if(isset($sf['s'])) $atts['s'] = $sf['s'];

        // Apply Address Search Query
        if(isset($sf['address'])) $atts['address'] = $sf['address'];

        // Apply Category Query
        if(isset($sf['category']) and trim($sf['category'])) $atts['category'] = $sf['category'];

        // Apply Location Query
        if(isset($sf['location'])) $atts['location'] = $sf['location'];

        // Apply Organizer Query
        if(isset($sf['organizer']) and trim($sf['organizer'])) $atts['organizer'] = $sf['organizer'];

        // Apply speaker Query
        if(isset($sf['speaker']) and trim($sf['speaker'])) $atts['speaker'] = $sf['speaker'];

        // Apply tag Query
        if(isset($sf['tag']) and trim($sf['tag'])) $atts['tag'] = $sf['tag'];

        // Apply Label Query
        if(isset($sf['label']) and trim($sf['label'])) $atts['label'] = $sf['label'];

        // Apply Event Cost Query
        if(isset($sf['cost-min'])) $atts['cost-min'] = $sf['cost-min'];
        if(isset($sf['cost-max'])) $atts['cost-max'] = $sf['cost-max'];

        // Event Status
        if(isset($sf['event_status'])) $atts['event_status'] = $sf['event_status'];

        // Apply Local Time Query
        if(isset($sf['time-start'])) $atts['time-start'] = $sf['time-start'];
        if(isset($sf['time-end'])) $atts['time-end'] = $sf['time-end'];

        // Apply Event Fields
        if(isset($sf['fields']) and is_array($sf['fields']) and count($sf['fields'])) $atts['fields'] = $sf['fields'];

        // Apply SF Date or Not
        if($apply_sf_date == 1)
        {
            // Apply Month of Month Filter
            if(isset($sf['month']) and trim($sf['month'])) $_REQUEST['mec_month'] = $sf['month'];

            // Apply Year of Month Filter
            if(isset($sf['year']) and trim($sf['year'])) $_REQUEST['mec_year'] = $sf['year'];

            // Apply to Start Date
            if(isset($sf['month']) and trim($sf['month']) and isset($sf['year']) and trim($sf['year']))
            {
                $start_date = $sf['year'].'-'.$sf['month'].'-'.($sf['day'] ?? '01');
                $_REQUEST['mec_start_date'] = $start_date;

                $skins = $this->main->get_skins();
                foreach($skins as $skin=>$label)
                {
                    $atts['sk-options'][$skin]['start_date_type'] = 'date';
                    $atts['sk-options'][$skin]['start_date'] = $start_date;
                }
            }

            // Apply Start and End Dates
            if(isset($sf['start']) and trim($sf['start']) and isset($sf['end']) and trim($sf['end']))
            {
                $start = $this->main->standardize_format($sf['start']);
                $_REQUEST['mec_start_date'] = $start;

                $end = $this->main->standardize_format($sf['end']);
                $_REQUEST['mec_maximum_date'] = $end;
                $this->maximum_date = $end;

                $skins = $this->main->get_skins();
                foreach($skins as $skin=>$label)
                {
                    $atts['sk-options'][$skin]['start_date_type'] = 'date';
                    $atts['sk-options'][$skin]['start_date'] = $start;
                }

                $atts['date-range-start'] = $start;
                $atts['date-range-end'] = $end;
            }
        }

        return apply_filters('add_to_search_box_query', $atts, $sf);
    }

    /**
     * Get Locations ID
     * @param string $address
     * @return array
     */
    public function get_locations_id($address = '')
    {
        if(!trim($address)) return [];

        $address = str_replace(' ', ',', $address);
        $locations = explode(',', $address);
        $query = "SELECT `term_id` FROM `#__termmeta` WHERE `meta_key` = 'address'";

        foreach($locations as $location) if(trim($location)) $query .= " AND `meta_value` LIKE '%" . trim($location) . "%'";

        $locations_id = $this->db->select($query, 'loadAssocList');
        return array_map(function($value)
        {
            return intval($value['term_id']);
        }, $locations_id);
    }

    public function sort_day_events($a, $b)
    {
        if(isset($a->date['start']['timestamp'], $b->date['start']['timestamp']))
        {
            $a_timestamp = $a->date['start']['timestamp'];
            $b_timestamp = $b->date['start']['timestamp'];
        }
        else
        {
            $a_start_date = $a->date['start']['date'];
            $b_start_date = $b->date['start']['date'];

            $a_timestamp = strtotime($a_start_date.' '.$a->data->time['start_raw']);
            $b_timestamp = strtotime($b_start_date.' '.$b->data->time['start_raw']);
        }

        if($a_timestamp == $b_timestamp) return 0;

        if($this->order_method === 'DESC') return ($a_timestamp < $b_timestamp) ? +1 : -1;
        else return ($a_timestamp > $b_timestamp) ? +1 : -1;
    }

    public function sort_dates($a, $b)
    {
        $a_timestamp = strtotime($a);
        $b_timestamp = strtotime($b);

        if($a_timestamp == $b_timestamp) return 0;
        return ($a_timestamp > $b_timestamp) ? +1 : -1;
    }

    public function booking_button($event, $type = 'button')
    {
        if(!$this->booking_button) return '';
        if(!$this->main->can_show_booking_module($event)) return '';
        if($this->main->is_sold($event, $event->data->time['start_timestamp']) and isset($this->settings['single_date_method']) and $this->settings['single_date_method'] !== 'referred') return '';

        $link = $this->main->get_event_date_permalink($event, $event->date['start']['date']);
        $link = $this->main->add_qs_var('method', 'mec-booking-modal', $link);

        $modal = 'data-featherlight="iframe" data-featherlight-iframe-height="450" data-featherlight-iframe-width="700"';
        $title = $this->main->m('booking_button', esc_html__('Book Event', 'mec'));

        $booking_options = (isset($event->data, $event->data->meta, $event->data->meta['mec_booking'], $event->data->meta['mec_booking']) and is_array($event->data->meta['mec_booking'])) ? $event->data->meta['mec_booking'] : [];
        $booking_button_label = (isset($booking_options['bookings_booking_button_label']) and trim($booking_options['bookings_booking_button_label'])) ? $booking_options['bookings_booking_button_label'] : '';

        if(trim($booking_button_label)) $title = $booking_button_label;

        if($type === 'button') return '<a class="mec-modal-booking-button mec-mb-button" href="'.esc_url($link).'" '.$modal.'>'.esc_html($title).'</a>';
        else return '<a class="mec-modal-booking-button mec-mb-icon" title="' . esc_attr($title) . '" href="'.esc_url($link).'" '.$modal.'><i class="mec-sl-note"></i></a>';
    }

    public function display_custom_data($event)
    {
        $output = '';

        $status = isset($this->skin_options['custom_data']) && $this->skin_options['custom_data'];
        if($status and is_object($event))
        {
            $single = new MEC_skin_single();

            ob_start();
            $single->display_data_fields($event, false, true);
            $output .= ob_get_clean();
        }

        return $output;
    }

    public function display_detailed_time($event)
    {
        // Event Date
        $date = ($event->date ?? array());

        $to = $date['end']['date'];
        $from = $this->main->get_start_of_multiple_days($event->ID, $to);

        $start_time = NULL;
        if(isset($date['start']['hour']))
        {
            $s_hour = $date['start']['hour'];
            if(strtoupper($date['start']['ampm']) == 'AM' and $s_hour == '0') $s_hour = 12;

            $start_time = sprintf("%02d", $s_hour).':';
            $start_time .= sprintf("%02d", $date['start']['minutes']);
            $start_time .= ' '.trim($date['start']['ampm']);
        }
        elseif(isset($event->data->time) and is_array($event->data->time) and isset($event->data->time['start_timestamp'])) $start_time = date('H:i', $event->data->time['start_timestamp']);

        $end_time = NULL;
        if(isset($date['end']['hour']))
        {
            $e_hour = $date['end']['hour'];
            if(strtoupper($date['end']['ampm']) == 'AM' and $e_hour == '0') $e_hour = 12;

            $end_time = sprintf("%02d", $e_hour).':';
            $end_time .= sprintf("%02d", $date['end']['minutes']);
            $end_time .= ' '.trim($date['end']['ampm']);
        }
        elseif(isset($event->data->time) and is_array($event->data->time) and isset($event->data->time['end_timestamp'])) $end_time = date('H:i', $event->data->time['end_timestamp']);

        $date_format = get_option('date_format');
        $time_format = get_option('time_format');

        $output = '<div class="mec-detailed-time-wrapper">';
        $output .= '<div class="mec-detailed-time-start">'.sprintf(esc_html__('Start from: %s - %s', 'mec'), date_i18n($date_format, strtotime($from)), date_i18n($time_format, strtotime($from.' '.$start_time))).'</div>';
        $output .= '<div class="mec-detailed-time-end">'.sprintf(esc_html__('End at: %s - %s', 'mec'), date_i18n($date_format, strtotime($to)), date_i18n($time_format, strtotime($to.' '.$end_time))).'</div>';
        $output .= '</div>';

        return $output;
    }

    public function display_categories($event)
    {
        $output = '';

        $status = isset($this->skin_options['display_categories']) && $this->skin_options['display_categories'];
        if($status and is_object($event) and isset($event->data->categories) and count($event->data->categories))
        {
            foreach($event->data->categories as $category)
            {
                if(isset($category['name']) and trim($category['name']))
                {
                    $color = ((isset($category['color']) and trim($category['color'])) ? $category['color'] : '');

                    $color_html = '';
                    if($color) $color_html .= '<span class="mec-event-category-color" style="--background-color: '.esc_attr($color).';background-color: '.esc_attr($color).'">&nbsp;</span>';

                    $output .= '<li class="mec-category"><a class="mec-color-hover" href="'.esc_url(get_term_link($category['id'])).'" target="_blank">' . trim($category['name']) . $color_html .'</a></li>';
                }
            }
        }

        return $output ? '<div class="mec-categories-wrapper">'.$this->icons->display('folder').'<ul class="mec-categories">' . $output . '</ul></div>' : $output;
    }

    public function display_organizers($event)
    {
        $output = '';

        $status = isset($this->skin_options['display_organizer']) && $this->skin_options['display_organizer'] && (!isset($this->settings['organizers_status']) || $this->settings['organizers_status']);
        if($status and is_object($event) and isset($event->data->organizers) and count($event->data->organizers))
        {
            $organizers = [];

            // Occurrence
            $occurrence = isset($event->date, $event->date['start'], $event->date['start']['timestamp']) ? $event->date['start']['timestamp'] : NULL;

            // Main Organizer
            if(isset($event->data, $event->data->meta, $event->data->meta['mec_organizer_id']) and $event->data->meta['mec_organizer_id'] > 1)
            {
                $organizers[] = $occurrence
                    ? MEC_feature_occurrences::param($event->ID, $occurrence, 'organizer_id', $event->data->meta['mec_organizer_id'])
                    : $event->data->meta['mec_organizer_id'];
            }

            // Additional Organizers
            $additional_organizers = isset($event->data->meta['mec_additional_organizer_ids']) && is_array($event->data->meta['mec_additional_organizer_ids']) && count($event->data->meta['mec_additional_organizer_ids']) ? $event->data->meta['mec_additional_organizer_ids'] : [];
            $organizers = array_merge($organizers, $additional_organizers);

            // Unique
            $organizers = array_unique($organizers);

            foreach($organizers as $organizer_id)
            {
                $term = get_term($organizer_id, 'mec_organizer');
                if(!isset($term->term_id)) continue;

                $url = get_term_meta($organizer_id, 'url', true);
                $name = $term->name;

                $organizer_url = !empty($url) ? 'href="'. esc_url($url) .'" target="_blank"' : '';
                if(trim($name))
                {
                    $name_url = trim($organizer_url) ? '<a class="mec-color-hover" '.$organizer_url.'>' . esc_html(trim($name)) . '</a>' : '<span>' . esc_html(trim($name)) . '</span>';
                    $output .= '<li class="mec-organizer-item">'.$name_url.'</li>';
                }
            }
        }

        return $output ? '<div class="mec-shortcode-organizers">'.$this->icons->display('user').'<ul class="mec-organizers">' . $output . '</ul></div>' : $output;
    }

    public function display_cost($event)
    {
        $output = '';
        if($this->display_price)
        {
            $cost = (isset($event->data->meta) and isset($event->data->meta['mec_cost']) and trim($event->data->meta['mec_cost'])) ? $event->data->meta['mec_cost'] : '';
            if(isset($event->date) and isset($event->date['start']) and isset($event->date['start']['timestamp'])) $cost = MEC_feature_occurrences::param($event->ID, $event->date['start']['timestamp'], 'cost', $cost);

            $event_id = $event->ID;
            if(isset($event->requested_id)) $event_id = $event->requested_id;

            if($cost)
            {
                $output .= '<div class="mec-price-details">
                    '.$this->icons->display('wallet').'
                    <span>'.(is_numeric($cost) ? $this->main->render_price($cost, $event_id) : $cost).'</span>
                </div>';
            }
        }

        return $output;
    }

    public function get_register_button_title( $event, $event_start_date ){

        $soldout = $this->main->get_flags($event, $event_start_date);

        $can_register = (is_array($event->data->tickets) and count($event->data->tickets) and !strpos($soldout, '%%soldout%%') and !$this->booking_button and !$this->main->is_expired($event));

        if($can_register)
        {
            $title = $this->main->m('register_button', esc_html__('REGISTER', 'mec'));
        }
        else
        {
            $title = $this->main->m('view_detail', esc_html__('View Detail', 'mec'));
        }

        return $title;
    }

    public function get_sed_method()
    {
        // SED Method
        $sed_method = $this->skin_options['sed_method'] ?? '0';

        // Fix Backend Editors Like Elementor
        if(is_admin()) $sed_method = '0';

        return $sed_method;
    }

    /**
     * @param $event
     * @param null $title
     * @param null $class
     * @param null $attributes
     * @return string|null
     */
    public function display_link($event, $title = NULL, $class = NULL, $attributes = NULL)
    {
        $link_for_title = false;

        // Event Title
        if(is_null($title))
        {
            $title = $event->data->title;
            $link_for_title = true;
        }

        // Link Class
        if(is_null($class)) $class = 'mec-color-hover';

        // Single Event Display Method
        $method = $this->skin_options['sed_method'] ?? false;

        // Occurrence Type
        $one_occurrence = (isset($this->atts['show_only_one_occurrence']) && $this->atts['show_only_one_occurrence']);

        // Repeat Type
        $repeat_label = '';
        if($one_occurrence and $link_for_title)
        {
            $repeat_type = (isset($event->data) and isset($event->data->meta) and isset($event->data->meta['mec_repeat_type'])) ? $event->data->meta['mec_repeat_type'] : '';

            // Change to switch case for translatability
            switch ($repeat_type) {
                case 'daily':
                    $repeat_label = '<span class="mec-repeating-label">'.esc_html__('Daily' , 'mec').'</span>';
                    break;
                case 'weekly':
                    $repeat_label = '<span class="mec-repeating-label">'.esc_html__('Weekly' , 'mec').'</span>';
                    break;
                case 'monthly':
                    $repeat_label = '<span class="mec-repeating-label">'.esc_html__('Monthly' , 'mec').'</span>';
                    break;
                case 'yearly':
                    $repeat_label = '<span class="mec-repeating-label">'.esc_html__('Yearly' , 'mec').'</span>';
                    break;
                case 'weekend':
                    $repeat_label = '<span class="mec-repeating-label">'.esc_html__('Every Weekend' , 'mec').'</span>';
                    break;
                case 'weekday':
                    $repeat_label = '<span class="mec-repeating-label">'.esc_html__('Every Weekday' , 'mec').'</span>';
                    break;
                case 'certain_weekdays':
                case 'custom_days':
                case 'advanced':
                    $repeat_label = '<span class="mec-repeating-label">'.esc_html__('Repeating Event' , 'mec').'</span>';
                    break;
            }
        }

        // Link is disabled
        if($method == 'no' and in_array($class, array('mec-booking-button', 'mec-detail-button', 'mec-booking-button mec-bg-color-hover mec-border-color-hover', 'mec-event-link'))) return '';
        elseif($method == 'no') return MEC_kses::form($title.$repeat_label);
        else
        {
            $sed_method = $this->skin_options['sed_method'] ?? '';
            switch($sed_method)
            {
                case '0':

                    $sed_method = '_self';
                    break;
                case 'new':

                    $sed_method = '_blank';
                    break;
            }

            $sed_method = ($sed_method ?: '_self');
        }

        $target = (!empty($sed_method) ? 'target="'.esc_attr($sed_method).'" rel="noopener"' : '');
        $target = apply_filters('mec_event_link_change_target', $target, $event->data->ID);

        return '<a '.($class ? 'class="'.esc_attr($class).'"' : '').' '.($attributes ?: '').' data-event-id="'.esc_attr($event->data->ID).'" aria-label="'.esc_attr($event->data->title).'" href="'.esc_url($this->main->get_event_date_permalink($event, $event->date['start']['date'])).'" '.$target.'>'.MEC_kses::form($title).'</a>'.MEC_kses::element($repeat_label);
    }

    public function get_end_date()
    {
        $end_date_type = (isset($this->skin_options['end_date_type']) and trim($this->skin_options['end_date_type'])) ? trim($this->skin_options['end_date_type']) : 'date';

        if($end_date_type === 'today') $maximum_date = current_time('Y-m-d');
        elseif($end_date_type === 'tomorrow') $maximum_date = date('Y-m-d', strtotime('Tomorrow'));
        else $maximum_date = (isset($this->skin_options['maximum_date_range']) and trim($this->skin_options['maximum_date_range'])) ? trim($this->skin_options['maximum_date_range']) : '';

        return $maximum_date;
    }

    public function get_label_captions($event, $extra_class = null)
    {
        $captions = '';
        if(isset($event->data->labels) and is_array($event->data->labels) and count($event->data->labels))
        {
            foreach($event->data->labels as $label)
            {
                if(!isset($label['style']) || !trim($label['style'])) continue;

                $captions .= '<span class="mec-event-label-captions '.esc_attr($extra_class).'" style="--background-color: '.esc_attr($label['color']).';background-color: '.esc_attr($label['color']).'">';
                if($label['style'] == 'mec-label-featured') $captions .= esc_html__($label['name'], 'mec');
                elseif($label['style'] == 'mec-label-canceled') $captions .= esc_html__($label['name'], 'mec');
                elseif($label['style'] == 'mec-label-custom' and isset($label['name']) and trim($label['name'])) $captions .= esc_html__($label['name'], 'mec');
                $captions .= '</span>';

                break;
            }
        }

        return $captions;
    }

    public function cache_mec_events(): bool
    {
        // First Validation
        if(!is_array($this->unique_event_ids) || !count($this->unique_event_ids)) return false;

        // Cache
        $cache = $this->getCache();

        // Db
        $db = $this->getDB();

        // Records
        $records = $db->select("SELECT * FROM `#__mec_events` WHERE `post_id` IN (".implode(',', $this->unique_event_ids).")");

        // Cache Data
        foreach($records as $record) $cache->set('mec-events-data-'.$record->post_id, $record);

        return true;
    }

    /**
     * @param $event
     * @param bool $only_color_code
     * @return string
     */
    public function get_event_color_dot($event, $only_color_code = false)
    {
        return $this->main->get_event_color_dot($event, $only_color_code);
    }

    public function display_status_bar($event)
    {
        if(!is_object($event)) return '';

        // Status Bar is Disabled
        if(!isset($this->skin_options['status_bar']) || !$this->skin_options['status_bar']) return '';

        $event_id = $event->ID;
        if(isset($event->requested_id)) $event_id = $event->requested_id; // Requested Event in Multilingual Websites

        $start_timestamp = $event->data->time['start_timestamp'] ?? ($event->date['start']['timestamp'] ?? strtotime($event->date['start']['date']));

        // All Params
        $params = MEC_feature_occurrences::param($event_id, $start_timestamp, '*');

        $event_status = (isset($event->data->meta['mec_event_status']) and trim($event->data->meta['mec_event_status'])) ? $event->data->meta['mec_event_status'] : 'EventScheduled';
        $event_status = (isset($params['event_status']) and trim($params['event_status']) != '') ? $params['event_status'] : $event_status;

        $output = '';

        // Ongoing Icon
        if($this->main->is_ongoing($event)) $output .= '<li class="mec-event-status-ongoing">'.$this->main->svg('mec-live-now').' '.esc_html__('Live Now', 'mec').'</li>';

        if($event_status === 'EventScheduled') $output .= '<li class="mec-event-status-scheduled">'.$this->main->svg('ontime').' '.esc_html__('On Schedule', 'mec').'</li>';
        elseif($event_status === 'EventPostponed') $output .= '<li class="mec-event-status-postponed">'.$this->main->svg('delay').' '.esc_html__('Delayed', 'mec').'</li>';
        elseif($event_status === 'EventCancelled') $output .= '<li class="mec-event-status-cancelled">'.$this->main->svg('cancel').' '.esc_html__('Cancelled', 'mec').'</li>';
        elseif($event_status === 'EventMovedOnline') $output .= '<li class="mec-event-status-movedonline">'.$this->main->svg('camrecorder').' '.esc_html__('Virtual', 'mec').'</li>';

        return trim($output) ? '<ul class="mec-event-status-icons">'.$output.'</ul>' : '';
    }

    public function get_pagination_bar()
    {
        if($this->pagination === 'loadmore' and $this->found >= $this->limit)
        {
            return '<div class="mec-load-more-wrap">
                <div tabindex="0" onkeydown="if(event.keyCode===13){jQuery(this).trigger(\'click\');}" class="mec-load-more-button '.($this->has_more_events ? '' : 'mec-util-hidden').'">'.esc_html__('Load More', 'mec').'</div>
            </div>';
        }

        if($this->pagination === 'scroll' and $this->found >= $this->limit)
        {
            return '<div class="mec-load-more-wrap"></div>';
        }

        if($this->pagination === 'nextprev' and $this->found >= $this->limit)
        {
            $offset = $this->end_date.':'.$this->next_offset;

            return '<div class="mec-nextprev-wrap" id="mec-nextprev-wrap-'.esc_attr($this->id).'">
                <span class="mec-nextprev-prev-button mec-util-hidden">
                    <svg xmlns="http://www.w3.org/2000/svg" width="13" height="10" viewBox="0 0 13 10"><path id="next-icon" d="M92.034,76.719l-.657.675,3.832,3.857H84v.937H95.208l-3.832,3.857.657.675,4.967-5Z" transform="translate(-84.001 -76.719)" fill="#07bbe9"/></svg>
                    '.esc_html__('Prev', 'mec').'
                </span>
                <a class="mec-nextprev-next-button" href="'.esc_url($this->main->add_qs_var('mec_next_page', $offset)).'">
                    '.esc_html__('Next', 'mec').'
                    <svg xmlns="http://www.w3.org/2000/svg" width="13" height="10" viewBox="0 0 13 10"><path id="next-icon" d="M92.034,76.719l-.657.675,3.832,3.857H84v.937H95.208l-3.832,3.857.657.675,4.967-5Z" transform="translate(-84.001 -76.719)" fill="#07bbe9"/></svg>
                </a>
            </div>';
        }

        return '';
    }

    /**
     * Display Powered By MEC URL
     *
     * @return string
     */
    public function display_credit_url()
    {
        $status = (isset($this->settings['display_credit_url']) && $this->settings['display_credit_url']);

        // Disabled
        if(!$status) return '';

        // Powered By Feature
        return '<div class="mec-credit-url">'.sprintf(esc_html__('Powered by %s', 'mec'), '<a href="https://webnus.net/modern-events-calendar/" rel="nofollow noopener sponsored" target="_blank">Modern Events Calendar</a>').'</div>';
    }

    /**
     * Subscribe + To Calendar
     *
     * @return string
     */
    public function subscribe_to_calendar()
    {
        if($this->from_full_calendar) return '';

        $ical_status = isset($this->settings['ical_feed']) && $this->settings['ical_feed'];
        if(!$ical_status) return '';

        $status = isset($this->settings['ical_feed_subscribe_to_calendar']) && $this->settings['ical_feed_subscribe_to_calendar'];
        if(!$status) return '';

        $base_url =  trim($this->main->URL(), '/ ');

        $webcal_base_url =  str_replace(['http://', 'https://'], 'webcal://', $base_url);
        $webcal_feed_url = $webcal_base_url . '/?mec-ical-feed=1';

        $feed_url = $base_url . '/?mec-ical-feed=1';
        $outlook = 'owa?path=/calendar/action/compose&rru=addsubscription&url=' . $feed_url . '&name=' .  get_bloginfo('name') . ' ' . get_the_title($this->id);

        return '<div class="mec-subscribe-to-calendar-container">
        <button class="mec-subscribe-to-calendar-btn">' . __('Add to calendar', 'mec') . '</button>
        <div class="mec-subscribe-to-calendar-items" style="display: none">' .
            '<a target="_blank" href="https://www.google.com/calendar/render?cid=' . $webcal_feed_url . '">' . __('Google Calendar', 'mec') . '</a>' .
            '<a target="_blank" href="' . $webcal_feed_url . '">' . __('iCalendar', 'mec') . '</a>' .
            '<a target="_blank" href="https://outlook.office.com/' . $outlook . '">' . __('Outlook 365', 'mec') . '</a>' .
            '<a target="_blank" href="https://outlook.live.com/' . $outlook . '">' .__('Outlook Live', 'mec'). '</a>' .
            '<a target="_blank" href="' . $feed_url . '">' . __('Export .ics file', 'mec') . '</a></div></div>';
    }
}
