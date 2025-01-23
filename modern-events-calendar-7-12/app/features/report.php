<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_report extends MEC_base
{
    /**
     * @var MEC_factory
     */
    private $factory;

    /**
     * @var MEC_db
     */
    private $db;

    /**
     * @var MEC_main
     */
    private $main;

    private $settings;
    private $ml_settings;

    /**
     * Constructor method
     * @author Webnus <info@webnus.net>
     */
    public function __construct()
    {
        // Import MEC Factory
        $this->factory = $this->getFactory();

        // Import MEC DB
        $this->db = $this->getDB();

        // Import MEC Main
        $this->main = $this->getMain();

        // MEC Settings
        $this->settings = $this->main->get_settings();

        // MEC Multilingual Settings
        $this->ml_settings = $this->main->get_ml_settings();
    }
    
    /**
     * Initialize search feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        $this->factory->action('admin_menu', [$this, 'menu'], 11);

        // Close Custom Text Notification
        $this->factory->action('wp_ajax_report_event_dates', [$this, 'report_event_dates']);

        // Event Attendees
        $this->factory->action('wp_ajax_mec_attendees', [$this, 'attendees']);

        // Selective Email
        $this->factory->action('wp_ajax_mec_mass_email', [$this, 'mass_email']);

        // Mass Action
        $this->factory->action('wp_ajax_mec_report_mass', [$this, 'mass_actions']);
    }

    public function menu()
    {
        if(isset($this->settings['booking_status']) && $this->settings['booking_status'])
        {
            add_submenu_page('mec-intro', esc_html__('MEC - Report', 'mec'), esc_html__('Report', 'mec'), 'mec_report', 'MEC-report', [$this, 'report']);
        }
    }

    /**
     * Show report page
     * @author Webnus <info@webnus.net>
     * @return void
     */
    public function report()
    {
        $path = MEC::import('app.features.report.tpl', true, true);

        ob_start();
        include $path;
        do_action('mec_display_report_page', $path);
        echo MEC_kses::full(ob_get_clean());
    }

    /* Report Event Dates */
    public function report_event_dates()
    {
        // Current User is not Permitted
        if(!current_user_can('mec_report')) $this->main->response(['success'=>0, 'code'=>'ADMIN_ONLY']);
        if(!wp_verify_nonce(sanitize_text_field($_REQUEST['nonce']), 'mec_settings_nonce')) exit();

        $event_id = sanitize_text_field($_POST['event_id']);

        $booking_options = get_post_meta($event_id, 'mec_booking', true);
        $bookings_all_occurrences = $booking_options['bookings_all_occurrences'] ?? 0;

        if($event_id != 'none')
        {
            $dates = $this->db->select("SELECT `tstart`, `tend` FROM `#__mec_dates` WHERE `post_id`='".$event_id."' LIMIT 100");
            $occurrence = count($dates) ? reset($dates)->tstart : '';

            $date_format = isset($this->ml_settings['booking_date_format1']) && trim($this->ml_settings['booking_date_format1'])
                ? $this->ml_settings['booking_date_format1']
                : 'Y-m-d';

            if(get_post_meta($event_id, 'mec_repeat_type', true) === 'custom_days') $date_format .= ' '.get_option('time_format');

            echo '<select name="mec-report-event-dates" class="mec-reports-selectbox mec-reports-selectbox-dates" onchange="mec_event_attendees('.esc_attr($event_id).', this.value);">';
            echo '<option value="none">'.esc_html__("Select Date" , "mec").'</option>';

            if($bookings_all_occurrences)
            {
                echo '<option value="all">'.esc_html__("All" , "mec").'</option>';
            }

            foreach($dates as $date)
            {
                $start = [
                    'date' => date('Y-m-d', $date->tstart),
                    'hour' => date('h', $date->tstart),
                    'minutes' => date('i', $date->tstart),
                    'ampm' => date('A', $date->tstart),
                ];

                $end = [
                    'date' => date('Y-m-d', $date->tend),
                    'hour' => date('h', $date->tend),
                    'minutes' => date('i', $date->tend),
                    'ampm' => date('A', $date->tend),
                ];

                echo '<option value="'.esc_attr($date->tstart).'" '.($occurrence == $date->tstart ? 'class="selected-day"' : '').'>'.strip_tags($this->main->date_label($start, $end, $date_format, ' - ', false)).'</option>';
            }

            echo '</select>';
        }
        else
        {
            echo '';
        }

        wp_die();
    }

    public function attendees()
    {
        $id = isset($_POST['id']) ? sanitize_text_field($_POST['id']) : 0;

        $occurrence = isset($_POST['occurrence']) ? sanitize_text_field($_POST['occurrence']) : NULL;
        $occurrence = explode(':', $occurrence)[0];

        if($occurrence == 'all') $occurrence = strtotime('+100 years');
        elseif($occurrence == 'none') $occurrence = NULL;

        $attendees = $this->main->get_event_attendees($id, $occurrence);

        $html = '';
        if(count($attendees))
        {
            $html .= $this->main->get_attendees_table($attendees, $id, $occurrence);
            $email_button = '<p>'.esc_html__('If you want to send an email, first select your attendees and then click in the button below, please.', 'mec').'</p><button data-id="'.esc_attr($id).'" onclick="mec_submit_event_email('.esc_attr($id).');">'.esc_html__('Send Email', 'mec').'</button>';

            // Certificate
            if($occurrence && isset($this->settings['certificate_status']) && $this->settings['certificate_status'])
            {
                $certificates = get_posts([
                    'post_type' => $this->main->get_certificate_post_type(),
                    'status' => 'publish',
                    'numberposts' => -1,
                    'orderby' => 'post_title',
                    'order' => 'ASC'
                ]);

                $certificate_options = '';
                foreach($certificates as $certificate)
                {
                    $certificate_options .= '<option value="'.esc_attr($certificate->ID).'">'.esc_html($certificate->post_title).'</option>';
                }

                $email_button .= '<div class="mec-report-certificate-wrap">
                    <h3>'.esc_html__('Certificate', 'mec').'</h3>
                    <select id="certificate_select" name="certificate" title="'.esc_attr__('Certificate', 'mec').'">
                        <option value="">-----</option>
                        '.$certificate_options.'
                    </select>
                    <button data-id="'.esc_attr($id).'" onclick="mec_certificate_send();">'.esc_html__('Send Certificate', 'mec').'</button>
                    <div id="mec-certificate-message"></div>
                </div>';
            }
        }
        else
        {
            $html .= '<p>'.esc_html__("No Attendees Found!", 'mec').'</p>';
            $email_button = '';
        }

        echo json_encode(['html' => $html, 'email_button' => $email_button]);
        exit;
    }

    public function mass_email()
    {
        if(!wp_verify_nonce(sanitize_text_field($_REQUEST['nonce']), 'mec_settings_nonce')) exit();

        // Current User is not Permitted
        if(!current_user_can('mec_report')) $this->main->response(array('success'=>0, 'code'=>'NO_ACCESS'));

        $mail_recipients_info = isset($_POST['mail_recipients_info']) ? trim(sanitize_text_field($_POST['mail_recipients_info']), ', ') : '';
        $mail_subject = isset($_POST['mail_subject']) ? sanitize_text_field($_POST['mail_subject']) : '';
        $mail_content = isset($_POST['mail_content']) ? MEC_kses::page($_POST['mail_content']) : '';
        $mail_copy = isset($_POST['mail_copy']) ? sanitize_text_field($_POST['mail_copy']) : 0;

        $render_recipients = array_unique(explode(',', $mail_recipients_info));
        $headers = array('Content-Type: text/html; charset=UTF-8');

        // Changing some sender email info.
        $notifications = $this->getNotifications();
        $notifications->mec_sender_email_notification_filter();

        // Send to Admin
        if($mail_copy) $render_recipients[] = 'Admin:.:'.get_option('admin_email');

        // Set Email Type to HTML
        add_filter('wp_mail_content_type', array($this->main, 'html_email_type'));

        foreach($render_recipients as $recipient)
        {
            $render_recipient = explode(':.:', $recipient);

            $to = isset($render_recipient[1]) ? trim($render_recipient[1]) : '';
            if(!trim($to)) continue;

            $message = $mail_content;
            $message = str_replace('%%name%%', (isset($render_recipient[0]) ? trim($render_recipient[0]) : ''), $message);

            $mail_arg = array(
                'to' => $to,
                'subject' => $mail_subject,
                'message' => $message,
                'headers' => $headers,
                'attachments' => array(),
            );

            $mail_arg = apply_filters('mec_before_send_mass_email', $mail_arg, 'mass_email');

            // Send the mail
            wp_mail($mail_arg['to'], html_entity_decode(stripslashes($mail_arg['subject']), ENT_HTML5), wpautop(stripslashes($mail_arg['message'])), $mail_arg['headers'], $mail_arg['attachments']);
        }

        // Remove the HTML Email filter
        remove_filter('wp_mail_content_type', array($this->main, 'html_email_type'));

        wp_die(true);
    }

    public function mass_actions()
    {
        // Invalid Request
        if(!wp_verify_nonce(sanitize_text_field($_REQUEST['_wpnonce'] ?? ''), 'mec_report_mass')) $this->main->response(['success'=>0, 'code'=>'INVALID_NONCE']);

        // Current User is not Permitted
        if(!current_user_can('mec_report')) $this->main->response(['success'=>0, 'code'=>'NO_ACCESS']);

        $task = isset($_POST['task']) ? sanitize_text_field($_POST['task']) : 'suggest';
        $events = isset($_POST['events']) && is_array($_POST['events']) ? $_POST['events'] : [];

        // Invalid Events
        if(!count($events)) $this->main->response(['success'=>0, 'code'=>'INVALID_EVENTS']);

        // Suggest New Event
        if($task === 'suggest')
        {
            // New Event to Suggest
            $new_event = isset($_POST['new_event']) ? sanitize_text_field($_POST['new_event']) : '';

            // Invalid Event
            if(!$new_event) $this->main->response(['success'=>0, 'code'=>'INVALID_EVENT']);

            // Notifications Library
            $notifications = $this->getNotifications();

            $attendees_count = 0;
            $sent = [];
            foreach($events as $id)
            {
                $attendees = $this->main->get_event_attendees($id);
                foreach($attendees as $attendee)
                {
                    $attendees_count++;

                    $email = $attendee['email'] ?? '';
                    if(!$email || in_array($email, $sent)) continue;

                    // Do not send multiple emails to same email
                    $sent[] = $email;

                    // Suggest the Event
                    $notifications->suggest_event([
                        'email' => $email,
                        'name' => $attendee['name'] ?? '',
                    ], $new_event, $attendee['book_id'] ?? '');
                }
            }

            $this->main->response(['success'=>1, 'code'=>'EMAILS_SENT', 'message' => sprintf(esc_html__('%s unique emails are sent successfully to %s attendees.', 'mec'), count($sent), $attendees_count)]);
        }

        wp_die(true);
    }
}