<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Hourly Schedule class.
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_hourlyschedule extends MEC_base
{
    public $factory;
    public $main;
    public $cart;
    public $book;
    public $settings;

    /**
     * Constructor method
     * @author Webnus <info@webnus.net>
     */
    public function __construct()
    {
        // Import MEC Factory
        $this->factory = $this->getFactory();

        // Import MEC Main
        $this->main = $this->getMain();
        
        // MEC Settings
        $this->settings = $this->main->get_settings();
    }
    
    /**
     * Initialize Hourly Schedule Feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        // Hourly Schedule Shortcode
        $this->factory->shortcode('mec-hourly-schedule', array($this, 'shortcode'));
    }

    /**
     * @param $atts
     * @return string
     * @throws Exception
     */
    public function shortcode($atts)
    {
        $event_id = $atts['event-id'] ?? 0;
        if(!$event_id) return '<p class="warning-msg">'.esc_html__('Please insert event id!', 'mec').'</p>';

        $event = get_post($event_id);
        if(!$event || $event->post_type != $this->main->get_main_post_type()) return '<p class="warning-msg">'.esc_html__('Event is not valid!', 'mec').'</p>';

        // Create Single Skin
        $single = new MEC_skin_single();

        // Initialize the skin
        $single->initialize([
            'id' => $event_id,
            'maximum_dates' => $this->settings['booking_maximum_dates'] ?? 6
        ]);

        // Fetch the events
        $events = $single->fetch();

        if(!isset($events[0])) return '<p class="warning-msg">'.esc_html__('Event is not valid!', 'mec').'</p>';

        ob_start();
        $single->display_hourly_schedules_widget($events[0], [
            'title' => $event->post_title
        ]);

        $html = ob_get_clean();

        return '<div class="mec-wrap mec-events-meta-group mec-events-meta-group-hourly-schedule mec-events-meta-group-hourly-schedule-shortcode">' . MEC_kses::full($html) . '</div>';
    }
}