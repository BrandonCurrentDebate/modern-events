<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Certificates class.
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_certificates extends MEC_base
{
    public $factory;
    public $main;
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
     * Initialize Auto Email feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        // PRO Version is required
        if(!$this->getPRO()) return false;

        // Show certificate feature only if module is enabled
        if(!isset($this->settings['certificate_status']) || !$this->settings['certificate_status']) return false;

        $this->factory->action('init', [$this, 'register_post_type']);
        $this->factory->filter('template_include', [$this, 'include_cert_template']);

        $this->factory->shortcode('mec_cert_event_title', [$this, 'shortcode_event_title']);
        $this->factory->shortcode('mec_cert_event_date', [$this, 'shortcode_event_date']);
        $this->factory->shortcode('mec_cert_attendee_name', [$this, 'shortcode_attendee_name']);
        $this->factory->shortcode('mec_cert_attendee_id', [$this, 'shortcode_attendee_id']);
        $this->factory->shortcode('mec_cert_transaction_id', [$this, 'shortcode_transaction_id']);
        $this->factory->shortcode('mec_cert_ticket_id', [$this, 'shortcode_ticket_id']);
        $this->factory->shortcode('mec_cert_ticket_name', [$this, 'shortcode_ticket_name']);

        $this->factory->action('wp_ajax_mec_send_certificates', [$this, 'send_certificates']);

        return true;
    }

    /**
     * Registers certificate post type
     * @author Webnus <info@webnus.net>
     */
    public function register_post_type()
    {
        $singular_label = esc_html__('Certificate', 'mec');
        $plural_label = esc_html__('Certificates', 'mec');

        $capability = 'manage_options';
        register_post_type($this->main->get_certificate_post_type(), array(
            'labels' => array(
                'name' => $plural_label,
                'singular_name' => $singular_label,
                'add_new' => sprintf(esc_html__('Add %s', 'mec'), $singular_label),
                'add_new_item' => sprintf(esc_html__('Add %s', 'mec'), $singular_label),
                'not_found' => sprintf(esc_html__('No %s found!', 'mec'), strtolower($plural_label)),
                'all_items' => $plural_label,
                'edit_item' => sprintf(esc_html__('Edit %s', 'mec'), $plural_label),
                'not_found_in_trash' => sprintf(esc_html__('No %s found in Trash!', 'mec'), strtolower($singular_label))
            ),
            'public' => true,
            'show_ui'=> current_user_can($capability),
            'show_in_menu' => false,
            'show_in_admin_bar' => false,
            'show_in_nav_menus' => false,
            'has_archive' => false,
            'exclude_from_search' => true,
            'publicly_queryable' => true,
            'supports' => array('title', 'editor'),
            'capabilities' => array(
                'read' => $capability,
                'read_post' => $capability,
                'read_private_posts' => $capability,
                'create_post' => $capability,
                'create_posts' => $capability,
                'edit_post' => $capability,
                'edit_posts' => $capability,
                'edit_private_posts' => $capability,
                'edit_published_posts' => $capability,
                'edit_others_posts' => $capability,
                'publish_posts' => $capability,
                'delete_post' => $capability,
                'delete_posts' => $capability,
                'delete_private_posts' => $capability,
                'delete_published_posts' => $capability,
                'delete_others_posts' => $capability,
            ),
        ));
    }

    /**
     * @param $template
     * @return mixed|string
     */
    public function include_cert_template($template)
    {
        // Get global post
        global $post;

        // Certificate Post
        if($post && isset($post->post_type) && $post->post_type === $this->main->get_certificate_post_type())
        {
            $template = $this->main->get_plugin_path().'app'.DS.'features'.DS.'certificates'.DS.'template.php';
        }

        return $template;
    }

    /**
     * @return array
     */
    private function get_request()
    {
        $ex = explode('-', $_GET['key'] ?? ''); // [attendee_id]-[mec-booking-id]-[transaction-id]-[ticket-id]

        return [
            $ex[0] ?? null,
            $ex[1] ?? null,
            $ex[2] ?? null,
            $ex[3] ?? null
        ];
    }

    /**
     * @return array|WP_Post|null
     */
    private function get_requested_event()
    {
        $booking = $this->get_requested_booking();

        return get_post($booking->event_id);
    }

    /**
     * @return mixed
     */
    private function get_requested_booking()
    {
        list(
            $attendee_id,
            $mec_booking_id,
            $transaction_id,
            $ticket_id
        ) = $this->get_request();

        return $this->getDB()->select("SELECT * FROM `#__mec_bookings` WHERE `id`='".esc_sql($mec_booking_id)."'", 'loadObject');
    }

    /**
     * @return mixed
     */
    private function get_requested_attendee()
    {
        list(
            $attendee_id,
            $mec_booking_id,
            $transaction_id,
            $ticket_id
        ) = $this->get_request();

        return $this->getDB()->select("SELECT * FROM `#__mec_booking_attendees` WHERE `id`='".esc_sql($attendee_id)."'", 'loadObject');
    }

    /**
     * @return string
     */
    public function shortcode_event_title()
    {
        $event = $this->get_requested_event();
        
        return $event ? $event->post_title : 'N/A';
    }

    /**
     * @return string
     */
    public function shortcode_event_date()
    {
        $booking = $this->get_requested_booking();
        $date_format = get_option('date_format');

        return $booking ? (string) wp_date($date_format, strtotime($booking->date)) : 'N/A';
    }

    /**
     * @return mixed
     */
    public function shortcode_attendee_id()
    {
        list(
            $attendee_id,
            $mec_booking_id,
            $transaction_id,
            $ticket_id
        ) = $this->get_request();

        return $attendee_id;
    }

    /**
     * @return string
     */
    public function shortcode_attendee_name()
    {
        $attendee = $this->get_requested_attendee();
        if($attendee)
        {
            $user = $this->getUser()->get($attendee->user_id);
            return $user->first_name . ' ' . $user->last_name;
        }

        return 'N/A';
    }

    /**
     * @return mixed
     */
    public function shortcode_transaction_id()
    {
        list(
            $attendee_id,
            $mec_booking_id,
            $transaction_id,
            $ticket_id
        ) = $this->get_request();

        return $transaction_id;
    }

    /**
     * @return mixed
     */
    public function shortcode_ticket_id()
    {
        list(
            $attendee_id,
            $mec_booking_id,
            $transaction_id,
            $ticket_id
        ) = $this->get_request();

        return $ticket_id;
    }

    /**
     * @return mixed
     */
    public function shortcode_ticket_name()
    {
        list(
            $attendee_id,
            $mec_booking_id,
            $transaction_id,
            $ticket_id
        ) = $this->get_request();

        $event = $this->get_requested_event();

        $event_tickets = get_post_meta($event->ID, 'mec_tickets', true);
        if(!is_array($event_tickets)) $event_tickets = [];

        return isset($event_tickets[$ticket_id]) ? $event_tickets[$ticket_id]['name'] : 'N/A';
    }

    public function send_certificates()
    {
        // Current User is not Permitted
        if(!current_user_can('manage_options')) $this->main->response(['success' => 0, 'code' => 'NO_ACCESS']);

        $template = isset($_POST['template']) ? sanitize_text_field($_POST['template']) : 0;
        $attendee_ids = isset($_POST['attendee_ids']) ? sanitize_text_field($_POST['attendee_ids']) : NULL;
        $attendee_ids = trim($attendee_ids, ', ');

        $attendees = explode(',', $attendee_ids);

        // Invalid Request
        if(!count($attendees) || !trim($template)) $this->main->response(['success' => 0, 'code' => 'INVALID_REQUEST']);

        // Notifications
        $notifications = $this->getNotifications();

        // Send Certificates
        foreach($attendees as $attendee)
        {
            $notifications->certificate_send($attendee, $template);
        }

        echo json_encode(['success' => 1, 'message' => esc_html__('Certificates sent successfully.', 'mec')]);
        exit;
    }
}