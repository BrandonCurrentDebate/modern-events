<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Notifications Per Event class.
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_notifications extends MEC_base
{
    public $factory;
    public $main;
    public $settings;
    public $notif_settings;

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

        // MEC Notification Settings
        $this->notif_settings = $this->main->get_notifications();
    }

    /**
     * Initialize notifications feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        // Module is disabled
        if(!isset($this->settings['notif_per_event']) || !$this->settings['notif_per_event']) return;

        $this->factory->action('mec_metabox_details', [$this, 'meta_box_notifications'], 30);
    }

    /**
     * Show notification meta box
     * @author Webnus <info@webnus.net>
     * @param $post
     */
    public function meta_box_notifications($post)
    {
        $values = get_post_meta($post->ID, 'mec_notifications', true);
        if(!is_array($values)) $values = [];

        $notifications = $this->get_notifications();
    ?>
        <div class="mec-meta-box-fields mec-event-tab-content" id="mec-notifications">
            <?php foreach($notifications as $key => $notification): if(isset($this->notif_settings[$key]) and isset($this->notif_settings[$key]['status']) and !$this->notif_settings[$key]['status']) continue; ?>
			<div class="mec-form-row">
                <h4><?php echo esc_html($notification['label']); ?></h4>
                <div class="mec-form-row">
                    <label>
                        <input type="hidden" name="mec[notifications][<?php echo esc_attr($key); ?>][status]" value="0" />
                        <input onchange="jQuery('#mec_notification_<?php echo esc_attr($key); ?>_container_toggle').toggle();" value="1" type="checkbox" name="mec[notifications][<?php echo esc_attr($key); ?>][status]" <?php if(isset($values[$key]) and isset($values[$key]['status']) and $values[$key]['status']) echo 'checked="checked"'; ?> /> <?php echo esc_html__("Modify", 'mec'); ?>
                    </label>
                </div>
                <div id="mec_notification_<?php echo esc_attr($key); ?>_container_toggle" class="<?php if(!isset($values[$key]) || !$values[$key]['status']) echo 'mec-util-hidden'; ?>">
                    <div class="mec-form-row">
                        <div class="mec-col-2">
                            <label for="mec_notifications_<?php echo esc_attr($key); ?>_subject"><?php esc_html_e('Email Subject', 'mec'); ?></label>
                        </div>
                        <div class="mec-col-10">
                            <input id="mec_notifications_<?php echo esc_attr($key); ?>_subject" type="text" name="mec[notifications][<?php echo esc_attr($key); ?>][subject]" value="<?php echo ((isset($values[$key]) and isset($values[$key]['subject']) and trim($values[$key]['subject'])) ? $values[$key]['subject'] : ((isset($this->notif_settings[$key]) and isset($this->notif_settings[$key]['subject']) and trim($this->notif_settings[$key]['subject'])) ? $this->notif_settings[$key]['subject'] : '')); ?>">
                        </div>
                    </div>
                    <div class="mec-form-row">
                        <div class="mec-col-2">
                            <label for="mec_notifications_<?php echo esc_attr($key); ?>_content"><?php esc_html_e('Email Content', 'mec'); ?></label>
                        </div>
                        <div class="mec-col-10">
                            <?php wp_editor(((isset($values[$key]) and isset($values[$key]['content']) and trim($values[$key]['content'])) ? stripslashes($values[$key]['content']) : ((isset($this->notif_settings[$key]) and isset($this->notif_settings[$key]['content']) and trim($this->notif_settings[$key]['content'])) ? stripslashes($this->notif_settings[$key]['content']) : '')), 'mec_notifications_'.esc_attr($key).'_content', array('textarea_name'=>'mec[notifications]['.$key.'][content]')); ?>
                        </div>
                    </div>

                    <?php
                        do_action('mec_display_notification_settings_for_event', $values, $key);
                    ?>
                </div>
			</div>
            <?php endforeach; ?>
            <h4><?php echo esc_html__('Placeholders', 'mec'); ?></h4>
            <?php $this->display_placeholders(); ?>
		</div>
    <?php
    }

    public function get_notifications()
    {
        $notifications = [
            'booking_notification' => [
                'label' => esc_html__('Booking Notification', 'mec')
            ],
            'booking_confirmation' => [
                'label' => esc_html__('Booking Confirmation', 'mec')
            ],
            'booking_rejection' => [
                'label' => esc_html__('Booking Rejection', 'mec')
            ],
            'email_verification' => [
                'label' => esc_html__('Email Verification', 'mec')
            ],
            'cancellation_notification' => [
                'label' => esc_html__('Booking Cancellation', 'mec')
            ],
            'booking_reminder' => [
                'label' => esc_html__('Booking Reminder', 'mec')
            ],
            'event_finished' => [
                'label' => esc_html__('Event Finished', 'mec')
            ],
            'event_soldout' => [
                'label' => esc_html__('Event Soldout', 'mec')
            ],
            'admin_notification' => [
                'label' => esc_html__('Admin Notification', 'mec')
            ],
            'certificate_send' => [
                'label' => esc_html__('Send Certificate', 'mec')
            ],
        ];

        return apply_filters('mec_event_notifications', $notifications);
    }

    public static function display_placeholders()
    {
        ?>
        <ul>
            <li><span>%%name%%</span>: <?php esc_html_e('Full name of attendee', 'mec'); ?></li>
            <li><span>%%first_name%%</span>: <?php esc_html_e('First name of attendee', 'mec'); ?></li>
            <li><span>%%last_name%%</span>: <?php esc_html_e('Last name of attendee', 'mec'); ?></li>
            <li><span>%%user_email%%</span>: <?php esc_html_e('Email of attendee', 'mec'); ?></li>
            <li><span>%%book_date%%</span>: <?php esc_html_e('Booked date of event', 'mec'); ?></li>
            <li><span>%%book_time%%</span>: <?php esc_html_e('Booked time of event', 'mec'); ?></li>
            <li><span>%%book_datetime%%</span>: <?php esc_html_e('Booked date and time of event', 'mec'); ?></li>
            <li><span>%%book_other_datetimes%%</span>: <?php esc_html_e('Other date and times of booking for multiple date booking system', 'mec'); ?></li>
            <li><span>%%book_date_next_occurrences%%</span>: <?php esc_html_e('Date of next 20 occurrences of booked event (including the booked date)', 'mec'); ?></li>
            <li><span>%%book_datetime_next_occurrences%%</span>: <?php esc_html_e('Date and Time of next 20 occurrences of booked event (including the booked date)', 'mec'); ?></li>
            <li><span>%%book_price%%</span>: <?php esc_html_e('Booking Price', 'mec'); ?></li>
            <li><span>%%book_payable%%</span>: <?php esc_html_e('Booking Payable', 'mec'); ?></li>
            <li><span>%%attendee_price%%</span>: <?php esc_html_e('Attendee Price (for booking confirmation notification)', 'mec'); ?></li>
            <li><span>%%book_order_time%%</span>: <?php esc_html_e('Date and time of booking', 'mec'); ?></li>
            <li><span>%%blog_name%%</span>: <?php esc_html_e('Your website title', 'mec'); ?></li>
            <li><span>%%blog_url%%</span>: <?php esc_html_e('Your website URL', 'mec'); ?></li>
            <li><span>%%blog_description%%</span>: <?php esc_html_e('Your website description', 'mec'); ?></li>
            <li><span>%%event_title%%</span>: <?php esc_html_e('Event title', 'mec'); ?></li>
            <li><span>%%event_description%%</span>: <?php esc_html_e('Event Description', 'mec'); ?></li>
            <li><span>%%event_tags%%</span>: <?php esc_html_e('Event Tags', 'mec'); ?></li>
            <li><span>%%event_labels%%</span>: <?php esc_html_e('Event Labels', 'mec'); ?></li>
            <li><span>%%event_categories%%</span>: <?php esc_html_e('Event Categories', 'mec'); ?></li>
            <li><span>%%event_cost%%</span>: <?php esc_html_e('Event Cost', 'mec'); ?></li>
            <li><span>%%event_link%%</span>: <?php esc_html_e('Event link', 'mec'); ?></li>
            <li><span>%%event_speaker_name%%</span>: <?php esc_html_e('Speaker name of booked event', 'mec'); ?></li>
            <li><span>%%event_organizer_name%%</span>: <?php esc_html_e('Organizer name of booked event', 'mec'); ?></li>
            <li><span>%%event_organizer_tel%%</span>: <?php esc_html_e('Organizer tel of booked event', 'mec'); ?></li>
            <li><span>%%event_organizer_email%%</span>: <?php esc_html_e('Organizer email of booked event', 'mec'); ?></li>
            <li><span>%%event_organizer_url%%</span>: <?php esc_html_e('Organizer url of booked event', 'mec'); ?></li>
            <li><span>%%event_other_organizers_name%%</span>: <?php esc_html_e('Additional organizers name of booked event', 'mec'); ?></li>
            <li><span>%%event_other_organizers_tel%%</span>: <?php esc_html_e('Additional organizers tel of booked event', 'mec'); ?></li>
            <li><span>%%event_other_organizers_email%%</span>: <?php esc_html_e('Additional organizers email of booked event', 'mec'); ?></li>
            <li><span>%%event_location_name%%</span>: <?php esc_html_e('Location name of booked event', 'mec'); ?></li>
            <li><span>%%event_location_address%%</span>: <?php esc_html_e('Location address of booked event', 'mec'); ?></li>
            <li><span>%%event_other_locations_name%%</span>: <?php esc_html_e('Additional locations name of booked event', 'mec'); ?></li>
            <li><span>%%event_other_locations_address%%</span>: <?php esc_html_e('Additional locations address of booked event', 'mec'); ?></li>
            <li><span>%%event_featured_image%%</span>: <?php esc_html_e('Featured image of booked event', 'mec'); ?></li>
            <li><span>%%event_more_info%%</span>: <?php esc_html_e('Event link', 'mec'); ?></li>
            <li><span>%%event_other_info%%</span>: <?php esc_html_e('Event more info link', 'mec'); ?></li>
            <li><span>%%online_link%%</span>: <?php esc_html_e('Event online link', 'mec'); ?></li>
            <li><span>%%attendees_full_info%%</span>: <?php esc_html_e('Full Attendees info such as booking form data, name, email etc.', 'mec'); ?></li>
            <li><span>%%all_bfixed_fields%%</span>: <?php esc_html_e('All booking fixed fields data.', 'mec'); ?></li>
            <li><span>%%booking_id%%</span>: <?php esc_html_e('Booking ID', 'mec'); ?></li>
            <li><span>%%booking_transaction_id%%</span>: <?php esc_html_e('Transaction ID of Booking', 'mec'); ?></li>
            <li><span>%%admin_link%%</span>: <?php esc_html_e('Admin booking management link.', 'mec'); ?></li>
            <li><span>%%total_attendees%%</span>: <?php esc_html_e('Total attendees of current booking', 'mec'); ?></li>
            <li><span>%%amount_tickets%%</span>: <?php esc_html_e('Amount of Booked Tickets (Total attendees of all bookings)', 'mec'); ?></li>
            <li><span>%%ticket_name%%</span>: <?php esc_html_e('Ticket name', 'mec'); ?></li>
            <li><span>%%ticket_time%%</span>: <?php esc_html_e('Ticket time', 'mec'); ?></li>
            <li><span>%%ticket_name_time%%</span>: <?php esc_html_e('Ticket name & time', 'mec'); ?></li>
            <li><span>%%ticket_private_description%%</span>: <?php esc_html_e('Ticket private description', 'mec'); ?></li>
            <li><span>%%ticket_variations%%</span>: <?php esc_html_e('Ticket Variations', 'mec'); ?></li>
            <li><span>%%payment_gateway%%</span>: <?php esc_html_e('Payment Gateway', 'mec'); ?></li>
            <li><span>%%dl_file%%</span>: <?php esc_html_e('Link to the downloadable file', 'mec'); ?></li>
            <li><span>%%google_calendar_link%%</span>: <?php esc_html_e('Add to Google Calendar', 'mec'); ?></li>
            <li><span>%%google_calendar_link_next_occurrences%%</span>: <?php esc_html_e('Add to Google Calendar Links for next 20 occurrences', 'mec'); ?></li>
            <li><span>%%event_start_date%%</span>: <?php esc_html_e('Event Start Date', 'mec'); ?></li>
            <li><span>%%event_end_date%%</span>: <?php esc_html_e('Event End Date', 'mec'); ?></li>
            <li><span>%%event_start_time%%</span>: <?php esc_html_e('Event Start Time', 'mec'); ?></li>
            <li><span>%%event_end_time%%</span>: <?php esc_html_e('Event End Time', 'mec'); ?></li>
            <li><span>%%event_timezone%%</span>: <?php esc_html_e('Event Timezone', 'mec'); ?></li>
            <li><span>%%event_start_date_local%%</span>: <?php esc_html_e('Event Local Start Date', 'mec'); ?></li>
            <li><span>%%event_end_date_local%%</span>: <?php esc_html_e('Event Local End Date', 'mec'); ?></li>
            <li><span>%%event_start_time_local%%</span>: <?php esc_html_e('Event Local Start Time', 'mec'); ?></li>
            <li><span>%%event_end_time_local%%</span>: <?php esc_html_e('Event Local End Time', 'mec'); ?></li>
            <li><span>%%event_status%%</span>: <?php esc_html_e('Status of event', 'mec'); ?></li>
            <li><span>%%event_note%%</span>: <?php esc_html_e('Event Note', 'mec'); ?></li>
            <?php do_action('mec_extra_field_notifications'); ?>
        </ul>
        <?php
    }
}