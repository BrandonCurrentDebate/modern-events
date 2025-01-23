<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC books class.
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_books extends MEC_base
{
    public $factory;
    public $main;
    public $db;
    public $book;
    public $PT;
    public $settings;
    public $ml_settings;

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

        // Import MEC DB
        $this->db = $this->getDB();

        // Import MEC Book
        $this->book = $this->getBook();

        // MEC Book Post Type Name
        $this->PT = $this->main->get_book_post_type();

        // MEC Settings
        $this->settings = $this->main->get_settings();

        // MEC Multilingual Settings
        $this->ml_settings = $this->main->get_ml_settings();
    }

    /**
     * Initialize books feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        // PRO Version is required
        if(!$this->getPRO()) return false;

        // Show booking feature only if booking module is enabled
        if(!isset($this->settings['booking_status']) or (isset($this->settings['booking_status']) and !$this->settings['booking_status'])) return false;

        $this->factory->action('init', array($this, 'register_post_type'));
        $this->factory->action('add_meta_boxes_'.$this->PT, array($this, 'remove_taxonomies_metaboxes'));
        $this->factory->action('save_post', array($this, 'save_book'), 10);
        $this->factory->action('add_meta_boxes', array($this, 'register_meta_boxes'), 1);
        $this->factory->action('mec_booking_saved_and_process_completed', array($this, 'reset_booking_cache'), 99);

        $this->factory->action('restrict_manage_posts', array($this, 'add_filters'));
        $this->factory->action('wp_ajax_mec_booking_filters_occurrence', array($this, 'add_occurrence_filter_ajax'));

        // Details Meta Box
        $this->factory->action('mec_book_metabox_details', array($this, 'meta_box_nonce'), 10);
        $this->factory->action('mec_book_metabox_details', array($this, 'meta_box_booking_form'), 10);
        $this->factory->action('mec_book_metabox_details', array($this, 'meta_box_booking_info'), 10);

        // Status Meta Box
        $this->factory->action('mec_book_metabox_status', array($this, 'meta_box_status_form'), 10);

        // Invoice Meta Box
        $this->factory->action('mec_book_metabox_status', array($this, 'meta_box_invoice'), 10);

        if(is_admin()) $this->factory->action('pre_get_posts', array($this, 'filter_query'));
        $this->factory->filter('manage_'.$this->PT.'_posts_columns', array($this, 'filter_columns'));
        $this->factory->filter('manage_edit-'.$this->PT.'_sortable_columns', array($this, 'filter_sortable_columns'));
        $this->factory->action('manage_'.$this->PT.'_posts_custom_column', array($this, 'filter_columns_content'), 10, 2);

        // Bulk Actions
        $this->factory->action('admin_footer-edit.php', array($this, 'add_bulk_actions'));
        $this->factory->action('load-edit.php', array($this, 'do_bulk_actions'));

        // Book Event form
        $this->factory->action('wp_ajax_mec_book_form', array($this, 'book'));
        $this->factory->action('wp_ajax_mec_book_form_upload_file', array($this, 'book'));

        $this->factory->action('wp_ajax_nopriv_mec_book_form', array($this, 'book'));

        // Tickets Availability
        $this->factory->action('wp_ajax_mec_tickets_availability', array($this, 'tickets_availability'));
        $this->factory->action('wp_ajax_nopriv_mec_tickets_availability', array($this, 'tickets_availability'));
        $this->factory->action('wp_ajax_mec_tickets_availability_multiple', array($this, 'tickets_availability_multiple'));
        $this->factory->action('wp_ajax_nopriv_mec_tickets_availability_multiple', array($this, 'tickets_availability_multiple'));

        // Backend Booking Form
        $this->factory->action('wp_ajax_mec_bbf_date_tickets_booking_form', array($this, 'bbf_date_tickets_booking_form'));
        $this->factory->action('wp_ajax_mec_bbf_edit_event_options', array($this, 'bbf_event_edit_options'));
        $this->factory->action('wp_ajax_mec_bbf_edit_event_add_attendee', array($this, 'bbf_edit_event_add_attendee'));
        $this->factory->action('wp_ajax_mec_bbf_edit_event_ticket_changed', array($this, 'bbf_edit_event_ticket_changed'));
        $this->factory->action('wp_ajax_mec_bbf_load_dates', array($this, 'bbf_load_dates'));

        $this->factory->action('edit_post', array($this, 'remove_scheduled'), 10, 2);

        // Booking Shortcode
        $this->factory->shortcode('mec-booking', array($this, 'shortcode'));

        // Ticket Variation Shortcode
        $this->factory->shortcode('mec-ticket-variations', [$this, 'ticket_variations_shortcode']);

        // Adjust Fees Per Gateway
        $this->factory->action('wp_ajax_mec_adjust_booking_fees', array($this, 'adjust_booking_fees'));
        $this->factory->action('wp_ajax_nopriv_mec_adjust_booking_fees', array($this, 'adjust_booking_fees'));

        // Delete Transaction Data
        $this->factory->action('before_delete_post', array($this, 'delete_transaction'));

        // Update Booking Record
        $this->factory->action('post_updated', array($this, 'record_update'), 10, 2);

        // Delete Booking Record
        $this->factory->action('before_delete_post', array($this, 'record_delete'), 10, 2);

        // Redirect Payment Thankyou Message
        $this->factory->filter('mec_booking_redirect_payment_thankyou', [$this, 'redirect_payment_thankyou'], 10, 2);

        return true;
    }

    /**
     * Registers books post type and assign it to some taxonomies
     * @author Webnus <info@webnus.net>
     */
    public function register_post_type()
    {
        $singular_label = $this->main->m('booking', esc_html__('Booking', 'mec'));
        $plural_label = $this->main->m('bookings', esc_html__('Bookings', 'mec'));

        $capability = (current_user_can('administrator') ? 'manage_options' : 'mec_bookings');
        register_post_type($this->PT,
            array(
                'labels'=>array
                (
                    'name'=>$plural_label,
                    'singular_name'=>$singular_label,
                    'add_new'=>sprintf(esc_html__('Add %s', 'mec'), $singular_label),
                    'add_new_item'=>sprintf(esc_html__('Add %s', 'mec'), $singular_label),
                    'not_found'=>sprintf(esc_html__('No %s found!', 'mec'), strtolower($plural_label)),
                    'all_items'=>$plural_label,
                    'edit_item'=>sprintf(esc_html__('Edit %s', 'mec'), $plural_label),
                    'not_found_in_trash'=>sprintf(esc_html__('No %s found in Trash!', 'mec'), strtolower($singular_label))
                ),
                'public'=>false,
                'show_ui'=>current_user_can($capability),
                'show_in_menu'=>true,
                'show_in_admin_bar'=>false,
                'has_archive'=>false,
                'exclude_from_search'=>true,
                'publicly_queryable'=>false,
                'menu_icon'=>plugin_dir_url(__FILE__ ) . '../../assets/img/mec-booking.svg',
                'menu_position'=>28,
                'supports'=>array('title', 'author'),
                'capabilities'=>array
                (
                    'read'=>$capability,
                    'read_post'=>$capability,
                    'read_private_posts'=>$capability,
                    'create_post'=>$capability,
                    'create_posts'=>$capability,
                    'edit_post'=>$capability,
                    'edit_posts'=>$capability,
                    'edit_private_posts'=>$capability,
                    'edit_published_posts'=>$capability,
                    'edit_others_posts'=>$capability,
                    'publish_posts'=>$capability,
                    'delete_post'=>$capability,
                    'delete_posts'=>$capability,
                    'delete_private_posts'=>$capability,
                    'delete_published_posts'=>$capability,
                    'delete_others_posts'=>$capability,
                ),
                'map_meta_cap'=>false
            )
        );
    }

    /**
     * Remove normal meta boxes for some taxonomies
     * @author Webnus <info@webnus.net>
     */
    public function remove_taxonomies_metaboxes()
    {
        remove_meta_box('tagsdiv-mec_coupon', $this->PT, 'side');
    }

    /**
     * Registers 2 meta boxes for book data
     * @author Webnus <info@webnus.net>
     */
    public function register_meta_boxes()
    {
        add_meta_box('mec_book_metabox_details', sprintf(esc_html__('%s Details', 'mec'), $this->main->m('booking', esc_html__('Booking', 'mec'))), array($this, 'meta_box_details'), $this->PT, 'normal', 'high');
        add_meta_box('mec_book_metabox_status', esc_html__('Status & Invoice', 'mec'), array($this, 'meta_box_status'), $this->PT, 'side', 'default');
    }

    /**
     * Show content of status meta box
     * @author Webnus <info@webnus.net>
     * @param object $post
     */
    public function meta_box_status($post)
    {
        do_action('mec_book_metabox_status', $post);
    }

    /**
     * Show confirmation form
     * @author Webnus <info@webnus.net>
     * @param $post
     */
    public function meta_box_status_form($post)
    {
        $confirmed = get_post_meta($post->ID, 'mec_confirmed', true);
        $verified = get_post_meta($post->ID, 'mec_verified', true);
        $event_id = get_post_meta($post->ID, 'mec_event_id', true);
    ?>
        <div class="mec-book-status-form">
            <div class="mec-row">
                <label for="mec_book_confirmation"><?php esc_html_e('Confirmation', 'mec'); ?></label>
                <select id="mec_book_confirmation" name="confirmation">
                    <option value="0"><?php esc_html_e('Pending', 'mec'); ?></option>
                    <option value="1" <?php echo (($confirmed == '1' or !$event_id) ? 'selected="selected"' : ''); ?>><?php esc_html_e('Confirmed', 'mec'); ?></option>
                    <option value="-1" <?php echo ($confirmed == '-1' ? 'selected="selected"' : ''); ?>><?php esc_html_e('Rejected', 'mec'); ?></option>
                </select>
            </div>
            <div class="mec-row">
                <label for="mec_book_verification"><?php esc_html_e('Verification', 'mec'); ?></label>
                <select id="mec_book_verification" name="verification">
                    <option value="0"><?php esc_html_e('Waiting', 'mec'); ?></option>
                    <option value="1" <?php echo (($verified == '1' or !$event_id) ? 'selected="selected"' : ''); ?>><?php esc_html_e('Verified', 'mec'); ?></option>
                    <option value="-1" <?php echo ($verified == '-1' ? 'selected="selected"' : ''); ?>><?php esc_html_e('Canceled', 'mec'); ?></option>
                </select>
            </div>

            <?php if($confirmed == 1 or $verified == 0): ?>
            <div class="mec-row" style="margin: 20px 0;">
                <?php if($confirmed == 1): ?>
                <div class="mec-row">
                    <label><input type="checkbox" name="resend_confirmation_email" value="1"><?php esc_html_e('Resend Confirmation Email', 'mec'); ?></label>
                </div>
                <?php endif; ?>

                <?php if($verified == 0): ?>
                <div class="mec-row">
                    <label><input type="checkbox" name="resend_verification_email" value="1"><?php esc_html_e('Resend Verification Email', 'mec'); ?></label>
                </div>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
    <?php
    }

    public function meta_box_invoice($post)
    {
        $transaction_id = get_post_meta($post->ID, 'mec_transaction_id', true);

        // Return if Transaction ID is not exists (Normally happens for new booking page)
        if(!$transaction_id) return false;

        $refunded = get_post_meta($post->ID, 'mec_refunded', true);
        $refunded_at = get_post_meta($post->ID, 'mec_refunded_at', true);
        $gateway_ref_id = get_post_meta($post->ID, 'mec_gateway_ref_id', true);

        $full_amount = get_post_meta($post->ID, 'mec_price', true);
        if(trim($full_amount) == '') $full_amount = 0;

        $full_amount = round($full_amount, 2);

        $date_format = get_option('date_format');
        $time_format = get_option('time_format');
    ?>
        <p class="mec-book-invoice">
            <?php
                if(!isset($this->settings['booking_invoice']) or (isset($this->settings['booking_invoice']) and $this->settings['booking_invoice'])) echo sprintf(esc_html__('Here, you can %s the invoice for transaction %s.', 'mec'), '<a href="'.esc_url($this->book->get_invoice_link($transaction_id)).'" target="_blank">'.esc_html__('download', 'mec').'</a>', '<strong>'.esc_html($transaction_id).'</strong>');
            ?>
        </p>

        <?php if(!trim($refunded) and trim($gateway_ref_id)): ?>
        <br>
        <div class="mec-row">
            <input type="checkbox" id="mec_book_refund_status" name="refund_status" onchange="jQuery('#mec_book_refund_options').toggleClass('w-hide');">
            <label for="mec_book_refund_status"><?php esc_html_e('Refund', 'mec'); ?></label>
            <p class="description"><?php esc_html_e('Booking get rejected automatically after refund.', 'mec'); ?></p>
        </div>
        <div class="w-hide" id="mec_book_refund_options" style="margin-top: 10px;">
            <div class="mec-row">
                <input type="checkbox" id="mec_book_refund_amount_status" name="refund_amount_status" onchange="jQuery('#mec_book_refund_amount_options').toggleClass('w-hide');">
                <label for="mec_book_refund_amount_status"><?php esc_html_e('Refund Amount', 'mec'); ?></label>
            </div>
            <div class="mec-row w-hide" id="mec_book_refund_amount_options" style="margin-top: 10px;">
                <label for="mec_book_refund_amount"><?php esc_html_e('Amount', 'mec'); ?></label>
                <input class="widefat" type="number" id="mec_book_refund_amount" name="refund_amount" min="0" max="<?php echo esc_attr($full_amount); ?>" step="0.01" value="<?php echo esc_attr($full_amount); ?>">
                <p class="description"><?php esc_html_e('Leave empty for a full refund.', 'mec'); ?></p>
            </div>
        </div>
        <?php elseif($refunded): ?>
        <div class="mec-row">
            <p class="warning-msg"><?php echo sprintf(esc_html__("The booking is refunded at %s", 'mec'), '<strong>'.date($date_format.' '.$time_format, strtotime($refunded_at)).'</strong>'); ?></p>
        </div>
        <?php endif; ?>
    <?php
    }

    /**
     * Show content of details meta box
     * @author Webnus <info@webnus.net>
     * @param object $post
     */
    public function meta_box_details($post)
    {
        do_action('mec_book_metabox_details', $post);
    }

    /**
     * Add a security nonce to the Add/Edit books page
     * @author Webnus <info@webnus.net>
     * @param object $post
     */
    public function meta_box_nonce($post)
    {
        // Add a nonce field so we can check for it later.
        wp_nonce_field('mec_book_data', 'mec_book_nonce');
    }

    /**
     * Show book form
     * @author Webnus <info@webnus.net>
     * @param $post
     * @return bool
     */
    public function meta_box_booking_form($post)
    {
        $meta = $this->main->get_post_meta($post->ID);
        $event_id = (isset($meta['mec_event_id']) and $meta['mec_event_id']) ? $meta['mec_event_id'] : 0;

        // The booking is saved so we will skip this form and show booking info instead.
        if($event_id) return false;

        // Events
        $events = $this->main->get_events();
        ?>
        <div class="info-msg"><?php esc_html_e('Creates a new booking under "Pay Locally" gateway.', 'mec'); ?></div>
        <div class="mec-book-form">
            <h3><?php echo sprintf(esc_html__('%s Form', 'mec'), $this->main->m('booking', esc_html__('Booking', 'mec'))); ?></h3>
            <div class="mec-form-row" style="padding-bottom: 5px;">
                <div class="mec-col-2">
                    <label for="mec_book_form_event_id"><?php esc_html_e('Event', 'mec'); ?></label>
                </div>
                <div class="mec-col-6">
                    <select id="mec_book_form_event_id" class="widefat" name="mec_event_id">
                        <option value="">-----</option>
                        <?php foreach($events as $event): ?>
                        <option value="<?php echo esc_attr($event->ID); ?>"><?php echo esc_html($event->post_title); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div class="mec-form-row" style="padding-bottom: 5px;">
                <div class="mec-col-2">
                    <label for="mec_book_form_num_attendees"><?php esc_html_e('Number of Attendees', 'mec'); ?></label>
                </div>
                <div class="mec-col-6">
                    <input type="number" min="1" step="1" max="100" id="mec_book_form_num_attendees" class="widefat" name="mec_num_attendees" value="1">
                </div>
            </div>
            <hr>
            <div id="mec_date_tickets_booking_form_container">
            </div>
            <input type="hidden" name="mec_is_new_booking" value="1" />
        </div>
        <script>
        jQuery(document).ready(function()
        {
            jQuery('#mec_book_form_event_id').on('change', function()
            {
                var event_id = this.value;
                var num_attendees = jQuery('#mec_book_form_num_attendees').val();

                generate_booking_form(event_id, num_attendees);
            });

            jQuery('#mec_book_form_num_attendees').on('change', function()
            {
                var event_id = jQuery('#mec_book_form_event_id').val();
                var num_attendees = this.value;

                generate_booking_form(event_id, num_attendees);
            });
        });

        function generate_booking_form(event_id, num_attendees)
        {
            // Container
            var $container = jQuery('#mec_date_tickets_booking_form_container');

            // Empty
            $container.html('');

            if(!event_id) return;

            jQuery.ajax(
            {
                url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                data: "action=mec_bbf_date_tickets_booking_form&event_id="+event_id+'&num_attendees='+num_attendees,
                dataType: "json",
                type: "GET",
                success: function(response)
                {
                    $container.html(response.output);

                    mec_bbf_listeners();

                    jQuery(document).trigger('mec_bbf_date_tickets_booking_form_success');
                },
                error: function()
                {
                    $container.html('');
                }
            });
        }

        function mec_edit_booking_ticket_changed(ticket_id, attendee_id)
        {
            let event_id = jQuery('#mec_book_form_event_id').val();
            jQuery.ajax(
            {
                url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                data: "action=mec_bbf_edit_event_ticket_changed&booking_id=<?php echo $post->ID; ?>&event_id="+event_id+"&ticket_id="+ticket_id+"&attendee_id="+attendee_id+"&type=add",
                dataType: "json",
                type: "GET",
                success: function(response)
                {
                    if(response.success === 1)
                    {
                        jQuery('#mec_book_ticket_variations_'+attendee_id).html(response.output);
                    }
                    else
                    {
                        jQuery('#mec_book_edit_form_event_message').html(response.output);
                    }

                    jQuery(document).trigger('mec_bbf_edit_event_ticket_changed_success');
                },
                error: function()
                {
                }
            });
        }

        function mec_bbf_listeners()
        {
            // Container
            let $container = jQuery('#mec_date_tickets_booking_form_container');

            let $prev = $container.find(jQuery('.mec-add-booking-prev-dates-button'));
            $prev.off('click').on('click', function()
            {
                let start = $prev.data('start');
                mec_bbf_load_dates(start, 'prev');
            });

            let $next = $container.find(jQuery('.mec-add-booking-next-dates-button'));
            $next.off('click').on('click', function()
            {
                let start = $next.data('start');
                mec_bbf_load_dates(start, 'next');
            });
        }

        function mec_bbf_load_dates(start, type)
        {
            let event_id = jQuery('#mec_book_form_event_id').val();
            let $dropdown = jQuery('#mec_book_form_date');

            // Disable Dropdown
            $dropdown.attr('disabled', 'disabled');

            jQuery.ajax(
            {
                url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                data: "action=mec_bbf_load_dates&booking_id=<?php echo $post->ID; ?>&event_id="+event_id+"&start="+start+"&type="+type,
                dataType: "json",
                type: "GET",
                success: function(response)
                {
                    if(response.success === 1)
                    {
                        jQuery('#mec_bbf_dates_wrapper').html(response.output);

                        mec_bbf_listeners();
                    }
                    else
                    {
                        jQuery('#mec_book_edit_form_event_message').html(response.output);
                    }

                    jQuery(document).trigger('mec_bbf_load_dates_success');
                    $dropdown.removeAttr('disabled');
                },
                error: function() {}
            });
        }
        </script>
        <?php
    }

    /**
     * Show book details
     * @param object $post
     * @author Webnus <info@webnus.net>
     * @return boolean
     */
    public function meta_box_booking_info($post)
    {
        $meta = $this->main->get_post_meta($post->ID);
        $event_id = (isset($meta['mec_event_id']) and $meta['mec_event_id']) ? $meta['mec_event_id'] : 0;

        // The booking is not saved so, we will skip this and show booking form instead.
        if(!$event_id) return false;

        $tickets = get_post_meta($event_id, 'mec_tickets', true);
        if(!is_array($tickets)) $tickets = [];

        $date_format = (isset($this->ml_settings['booking_date_format1']) and trim($this->ml_settings['booking_date_format1'])) ? $this->ml_settings['booking_date_format1'] : 'Y-m-d';
        $time_format = get_option('time_format');

        $dates = isset($meta['mec_date']) ? explode(':', $meta['mec_date']) : [];
        if(is_numeric($dates[0]) and is_numeric($dates[1]))
        {
            $start_datetime = $this->main->date_i18n($date_format.' '.$time_format, $dates[0]);
            $end_datetime = $this->main->date_i18n($date_format.' '.$time_format, $dates[1]);
        }
        else
        {
            $start_datetime = $dates[0];
            $end_datetime = $dates[1];
        }

        // Multiple Dates
        $all_dates = ((isset($meta['mec_all_dates']) and is_array($meta['mec_all_dates'])) ? $meta['mec_all_dates'] : array());
        $other_dates = ((isset($meta['mec_other_dates']) and is_array($meta['mec_other_dates'])) ? $meta['mec_other_dates'] : array());

        $attendees = $meta['mec_attendees'] ?? (isset($meta['mec_attendee']) ? array($meta['mec_attendee']) : array());

        $reg_fields = $this->main->get_reg_fields($event_id);
        if(is_array($reg_fields) and isset($reg_fields[':i:'])) unset($reg_fields[':i:']);
        if(is_array($reg_fields) and isset($reg_fields[':fi:'])) unset($reg_fields[':fi:']);

        $bfixed_fields = $this->main->get_bfixed_fields($event_id);
        if(is_array($bfixed_fields) and isset($bfixed_fields[':i:'])) unset($bfixed_fields[':i:']);
        if(is_array($bfixed_fields) and isset($bfixed_fields[':fi:'])) unset($bfixed_fields[':fi:']);

        $status = get_post_meta($post->ID, 'mec_verified', true);
        $coupon_code = (isset($meta['mec_coupon_code']) and trim($meta['mec_coupon_code'])) ? $meta['mec_coupon_code'] : '';

        $transaction_id = get_post_meta($post->ID, 'mec_transaction_id', true);
        $transaction = $this->book->get_transaction($transaction_id);

        $requested_event_id = $transaction['translated_event_id'] ?? $event_id;

        $event_booking_options = get_post_meta($event_id, 'mec_booking', true);
        if(!is_array($event_booking_options)) $event_booking_options = [];

        $book_all_occurrences = 0;
        if(isset($event_booking_options['bookings_all_occurrences'])) $book_all_occurrences = (int) $event_booking_options['bookings_all_occurrences'];

        $maximum_dates = ((isset($this->settings['booking_maximum_dates']) and trim($this->settings['booking_maximum_dates'])) ? $this->settings['booking_maximum_dates'] : 6);

        // Apply Maximum of 100
        $maximum_dates = min($maximum_dates, 100);
    ?>
        <div class="mec-book-details">
            <div class="mec-form-row">
                <div class="mec-col-10"><h3><?php esc_html_e('Payment', 'mec'); ?></h3></div>
                <div class="mec-col-2" style="text-align: right;"><a href="#mec_booking_edit_heading" class="button"><?php esc_html_e('Go to Edit Form', 'mec'); ?></a></div>
            </div>
            <div class="mec-row">
                <strong><?php esc_html_e('Price', 'mec'); ?>: </strong>
                <span><?php echo esc_html($this->main->render_price(($meta['mec_price'] ?: 0), $requested_event_id)); ?></span>
            </div>
            <div class="mec-row">
                <strong><?php esc_html_e('Paid Amount', 'mec'); ?>: </strong>
                <span><?php echo esc_html($this->main->render_price(($meta['mec_payable'] ?: 0), $requested_event_id)); ?></span>
            </div>
            <div class="mec-row">
                <strong><?php esc_html_e('Gateway', 'mec'); ?>: </strong>
                <span>
                    <?php
                        $woo_order_id = get_post_meta($post->ID, 'mec_order_id', true);
                        echo ((isset($meta['mec_gateway_label']) and trim($meta['mec_gateway_label'])) ? esc_html__($meta['mec_gateway_label'], 'mec') : esc_html__('Unknown', 'mec')).' '.((class_exists('WooCommerce') and trim($woo_order_id)) ? '<a href="'.esc_url(admin_url("post.php?post={$woo_order_id}&action=edit")).'" target="_blank">'.esc_html($woo_order_id).'</a>' : '');
                    ?>
                </span>
            </div>
            <div class="mec-row">
                <strong><?php esc_html_e('Transaction ID', 'mec'); ?>: </strong>
                <span><?php echo ((isset($transaction['gateway_transaction_id']) and trim($transaction['gateway_transaction_id'])) ? $transaction['gateway_transaction_id'] : $transaction_id); ?></span>
            </div>

            <?php if(trim($coupon_code)): ?>
            <div class="mec-row">
                <strong><?php esc_html_e('Coupon Code', 'mec'); ?>: </strong>
                <span><code><?php echo esc_html($coupon_code); ?></code></span>
            </div>
            <?php endif; ?>

            <h3><?php echo esc_html($this->main->m('booking', esc_html__('Booking', 'mec'))); ?></h3>
            <div class="mec-row">
                <strong><?php esc_html_e('Event', 'mec'); ?>: </strong>
                <span><?php echo ($event_id ? '<a href="'.get_permalink($event_id).'">'.get_the_title($event_id).'</a>' : esc_html__('Unknown', 'mec')); ?></span>
            </div>

            <?php if(count($all_dates)): ?>
            <div class="mec-row">
                <strong><?php esc_html_e('Date & Times', 'mec'); ?>: </strong>
                <div>
                    <?php foreach($all_dates as $one_date): $other_timestamps = explode(':', $one_date); ?>
                    <div><?php echo ((isset($other_timestamps[0]) and isset($other_timestamps[1])) ? sprintf(esc_html__('%s to %s', 'mec'), $this->main->date_i18n($date_format.' '.$time_format, $other_timestamps[0]), $this->main->date_i18n($date_format.' '.$time_format, $other_timestamps[1])) : esc_html__('Unknown', 'mec')); ?></div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php else: ?>
            <div class="mec-row">
                <strong><?php esc_html_e('Date & Time', 'mec'); ?>: </strong>

                <?php if($book_all_occurrences): $next_occurrences = $this->getRender()->dates($event_id, NULL, $maximum_dates, date('Y-m-d', strtotime('-1 day', strtotime($start_datetime)))); ?>
                <div class="mec-next-occ-booking-p">
                    <?php esc_html_e('This is a booking for all occurrences. Some of them are listed below but there might be more.', 'mec'); ?>
                    <div>
                        <?php foreach($next_occurrences as $next_occurrence) echo MEC_kses::element($this->main->date_label($next_occurrence['start'], $next_occurrence['end'], $date_format.' '.$time_format, ' - ', false, 0, $event_id))."<br>"; ?>
                    </div>
                </div>
                <?php else: ?>
                <span><?php echo ((isset($dates[0]) and isset($dates[1])) ? sprintf(esc_html__('%s to %s', 'mec'), $start_datetime, $end_datetime) : esc_html__('Unknown', 'mec')); ?></span>
                <?php endif; ?>
            </div>
            <?php endif; ?>

            <?php if($status == '-1'): ?>
            <div class="mec-row">
                <strong><?php esc_html_e('Cancellation Date', 'mec'); ?>: </strong>
                <span>
                    <?php
                        $mec_cancellation_date = get_post_meta($post->ID, 'mec_cancelled_date', true);
                        echo trim($mec_cancellation_date) ? $mec_cancellation_date : esc_html__('Unknown', 'mec');
                    ?>
                </span>
            </div>
            <?php endif; ?>

            <div class="mec-row">
                <strong><?php esc_html_e('Total Attendees', 'mec'); ?>: </strong>
                <span><?php echo esc_html($this->book->get_total_attendees($post->ID)); ?></span>
            </div>

            <?php if(is_array($bfixed_fields) and count($bfixed_fields) and isset($transaction['fields']) and is_array($transaction['fields']) and count($transaction['fields'])): ?>
            <h3><?php echo sprintf(esc_html__('%s Fields', 'mec'), $this->main->m('booking', esc_html__('Booking', 'mec'))); ?></h3>
            <hr>

            <?php foreach($bfixed_fields as $bfixed_field_id => $bfixed_field): if(!is_numeric($bfixed_field_id)) continue; $bfixed_value = isset($transaction['fields'][$bfixed_field_id]) ? $transaction['fields'][$bfixed_field_id] : NULL; if(!$bfixed_value) continue; $bfixed_type = isset($bfixed_field['type']) ? $bfixed_field['type'] : NULL; $bfixed_label = isset($bfixed_field['label']) ? $bfixed_field['label'] : ''; ?>
                <?php if($bfixed_type == 'agreement'): ?>
                    <div class="mec-row">
                        <strong><?php echo sprintf(esc_html__($bfixed_label, 'mec'), '<a href="'.get_the_permalink($bfixed_field['page']).'">'.get_the_title($bfixed_field['page']).'</a>'); ?>: </strong>
                        <span><?php echo ($bfixed_value == '1' ? esc_html__('Yes', 'mec') : esc_html__('No', 'mec')); ?></span>
                    </div>
                <?php else: ?>
                    <div class="mec-row">
                        <strong><?php esc_html_e($bfixed_label, 'mec'); ?>: </strong>
                        <span><?php echo (is_array($bfixed_value) ? stripslashes(implode(',', $bfixed_value)) : stripslashes($bfixed_value)); ?></span>
                    </div>
                <?php endif; ?>
            <?php endforeach; ?>
            <?php endif; ?>

            <?php if(!empty($attendees['attachments'])): ?>
            <h3><?php esc_html_e('Attachments', 'mec'); ?></h3>
            <hr>
            <?php foreach($attendees['attachments'] as $attachment): ?>
            <div class="mec-attendee">
                <?php if(!isset($attachment['error']) && $attachment['response'] === 'SUCCESS'): ?>
                    <?php
                        @$a = getimagesize($attachment['url']);
                        $image_type = (is_array($a) and isset($a[2])) ? $a[2] : '';
                        if(in_array($image_type, array(IMAGETYPE_GIF, IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_BMP))):
                    ?>
                        <a href="<?php echo esc_url($attachment['url']); ?>" target="_blank">
                            <img src="<?php echo esc_url($attachment['url']); ?>" alt="<?php echo esc_attr($attachment['filename']); ?>" title="<?php echo esc_attr($attachment['filename']); ?>" style="max-width:250px;float: left;margin: 5px;">
                        </a>
                    <?php else: ?>
                        <a href="<?php echo esc_url($attachment['url']); ?>" target="_blank"><?php echo esc_html($attachment['filename']); ?></a>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
            <div class="clear"></div>
            <?php endif; ?>

            <h3><?php esc_html_e('Attendees', 'mec'); ?></h3>
            <?php foreach($attendees as $key => $attendee): $reg_form = $attendee['reg'] ?? []; ?>
            <?php
                if($key === 'attachments') continue;
                if(isset($attendee[0]['MEC_TYPE_OF_DATA'])) continue;
            ?>
            <hr>
            <div class="mec-attendee">
                <h4><strong><?php echo ((isset($attendee['name']) and trim($attendee['name'])) ? $attendee['name'] : '---'); ?></strong></h4>
                <div class="mec-row">
                    <strong><?php esc_html_e('Email', 'mec'); ?>: </strong>
                    <span><?php echo ((isset($attendee['email']) and trim($attendee['email'])) ? $attendee['email'] : '---'); ?></span>
                </div>
                <div class="mec-row">
                    <strong><?php echo esc_html($this->main->m('ticket', esc_html__('Ticket', 'mec'))); ?>: </strong>
                    <span><?php echo ((isset($attendee['id']) and isset($tickets[$attendee['id']]['name'])) ? $tickets[$attendee['id']]['name'] : esc_html__('Unknown', 'mec')); ?></span>
                </div>
                <?php
                // Ticket Variations
                if(isset($attendee['variations']) and is_array($attendee['variations']) and count($attendee['variations']))
                {
                    $ticket_variations = $this->main->ticket_variations($event_id, $attendee['id']);
                    foreach($attendee['variations'] as $variation_id=>$variation_count)
                    {
                        if(!$variation_count or ($variation_count and $variation_count < 0)) continue;

                        $variation_title = (isset($ticket_variations[$variation_id]) and isset($ticket_variations[$variation_id]['title'])) ? $ticket_variations[$variation_id]['title'] : '';
                        if(!trim($variation_title)) continue;

                        echo '<div class="mec-row">
                            <span>+ '.esc_html($variation_title).'</span>
                            <span>('.esc_html($variation_count).')</span>
                        </div>';
                    }
                }
                ?>
                <?php
                $reg_fields = apply_filters('mec_booking_reg_form', $reg_fields, $event_id, $post);
                if(!empty($reg_form)): foreach($reg_form as $field_id=> $value): $label = isset($reg_fields[$field_id]) ? $reg_fields[$field_id]['label'] : ''; $type = isset($reg_fields[$field_id]) ? $reg_fields[$field_id]['type'] : ''; ?>
                    <?php if($type == 'agreement'): ?>
                        <div class="mec-row">
                            <strong><?php echo sprintf(esc_html__($label, 'mec'), '<a href="'.get_the_permalink($reg_fields[$field_id]['page']).'">'.get_the_title($reg_fields[$field_id]['page']).'</a>'); ?>: </strong>
                            <span><?php echo ($value == '1' ? esc_html__('Yes', 'mec') : esc_html__('No', 'mec')); ?></span>
                        </div>
                    <?php else: ?>
                        <div class="mec-row">
                            <strong><?php esc_html_e($label, 'mec'); ?>: </strong>
                            <span><?php echo (is_string($value) ? stripslashes($value) : (is_array($value) ? stripslashes(implode(', ', $value)) : '---')); ?></span>
                        </div>
                    <?php endif; ?>
                <?php endforeach; endif; ?>

                <?php do_action( 'mec_admin_book_attendee_details', $attendee, $key, $transaction, $post->ID ); ?>

            </div>
            <?php endforeach; ?>
            <h3><?php esc_html_e('Billing', 'mec'); ?></h3>
            <hr>
            <div class="mec-billing">
                <?php
                    if(isset($transaction['price_details']) and isset($transaction['price_details']['details']))
                    {
                        foreach($transaction['price_details']['details'] as $price_row)
                        {
                            echo '<div><strong>'.esc_html($price_row['description']).":</strong> ".esc_html($this->main->render_price($price_row['amount'], $requested_event_id)).'</div>';
                        }

                        if(trim($coupon_code)) echo '<div><strong>'.esc_html__('Coupon Code', 'mec').':</strong> <code>'.esc_html($coupon_code).'</code></div>';
                        echo '<div><strong>'.esc_html__('Total', 'mec').':</strong> '.esc_html($this->main->render_price($transaction['price'], $requested_event_id)).'</div>';
                        echo '<div><strong>'.esc_html__('Paid', 'mec').':</strong> '.esc_html($this->main->render_price($transaction['payable'], $requested_event_id)).'</div>';
                    }
                ?>
            </div>
            <?php do_action('mec_admin_book_detail', $post->ID); ?>
        </div>

        <?php
        // Events
        $events = $this->main->get_events();

        $first_booked_timestamps = isset($meta['mec_all_dates'], $meta['mec_all_dates'][0]) ? explode(':', $meta['mec_all_dates'][0]) : explode(':', $meta['mec_date']);
        $now = current_time('timestamp');

        $repeat_type = get_post_meta($event_id, 'mec_repeat_type', true);

        if($repeat_type !== 'weekly') $occurrences_start_timestamp = min($now, $first_booked_timestamps[0]);
        else $occurrences_start_timestamp = $first_booked_timestamps[0];

        $occurrences_start_timestamp = $occurrences_start_timestamp - (3600*24);

        $render = $this->getRender();
        $occurrences = $render->dates($event_id, NULL, 100, date('Y-m-d H:i:s', $occurrences_start_timestamp));

        $date_format = (isset($this->ml_settings['booking_date_format1']) and trim($this->ml_settings['booking_date_format1'])) ? $this->ml_settings['booking_date_format1'] : 'Y-m-d';

        $repeat_type = get_post_meta($event_id, 'mec_repeat_type', true);
        if($repeat_type === 'custom_days') $date_format .= ' '.get_option('time_format');
        ?>
        <div class="mec-book-edit">
            <h1 id="mec_booking_edit_heading"><?php sprintf(esc_html__('Edit %s', 'mec'), $this->main->m('booking', esc_html__('Booking', 'mec'))); ?></h1>
            <div class="info-msg"><?php esc_html_e('Do not edit the booking unless it is really needed!', 'mec'); ?></div>

            <input type="hidden" name="mec_booking_edit_status" value="0">
            <input type="checkbox" name="mec_booking_edit_status" id="mec_booking_edit_status" value="1" onchange="jQuery('#mec_book_edit_form').toggleClass('mec-util-hidden');">
            <label for="mec_booking_edit_status"><?php esc_html_e('I need to edit the details of a booking', 'mec'); ?></label>

            <div id="mec_book_edit_form" class="mec-book-form mec-util-hidden" style="margin-top: 30px;">
                <div class="mec-form-row">
                    <div class="mec-col-2">
                        <label for="mec_book_form_event_id"><?php esc_html_e('Event', 'mec'); ?></label>
                    </div>
                    <div class="mec-col-6">
                        <select id="mec_book_form_event_id" class="widefat" name="mec_event_id">
                            <option value="">-----</option>
                            <?php foreach($events as $event): ?>
                            <option value="<?php echo esc_attr($event->ID); ?>" <?php echo ($event_id == $event->ID ? 'selected="selected"' : ''); ?>><?php echo esc_html($event->post_title); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div id="mec_book_edit_form_event_message">
                </div>
                <div id="mec_book_edit_form_event_options">
                    <div class="mec-form-row">
                        <div class="mec-col-2">
                            <label for="mec_book_form_date"><?php esc_html_e('Date', 'mec'); ?></label>
                        </div>
                        <div class="mec-col-6" id="mec_edit_event_date_options_wrapper">
                            <?php if(count($other_dates)): ?>
                            <ul class="mec-booking-edit-multiple-dates-wrapper">
                                <?php foreach($occurrences as $occurrence): $occ_timestamp = $this->book->timestamp($occurrence['start'], $occurrence['end']); ?>
                                <li>
                                    <label>
                                        <input type="checkbox" name="mec_date[]" value="<?php echo esc_attr($occ_timestamp); ?>" <?php echo (in_array($occ_timestamp, $all_dates) ? 'checked="checked"' : ''); ?>>
                                        <?php echo strip_tags($this->main->date_label($occurrence['start'], $occurrence['end'], $date_format, ' - ', false)); ?>
                                    </label>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                            <?php else: ?>
                            <select id="mec_book_form_date" class="widefat mec-booking-edit-form-dates" name="mec_date">
                                <option value="">-----</option>
                                <?php foreach($occurrences as $occurrence): $occ_timestamp = $this->book->timestamp($occurrence['start'], $occurrence['end']); ?>
                                <option value="<?php echo esc_attr($occ_timestamp); ?>" <?php echo (($meta['mec_date'] == $occ_timestamp or $meta['mec_date'] == $occurrence['start']['date'].':'.$occurrence['end']['date']) ? 'selected="selected"' : ''); ?>>
                                    <?php echo strip_tags($this->main->date_label($occurrence['start'], $occurrence['end'], $date_format, ' - ', false)); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                            <?php endif; ?>
                        </div>
                    </div>

                    <?php if(isset($this->settings['coupons_status']) and $this->settings['coupons_status']): ?>
                    <div id="mec_date_tickets_booking_form_coupon">
                        <div class="mec-form-row">
                            <div class="mec-col-2">
                                <label for="mec_book_form_coupon"><?php esc_html_e('Coupon', 'mec'); ?></label>
                            </div>
                            <div class="mec-col-6">
                                <input type="text" id="mec_book_form_coupon" name="mec_coupon" value="<?php echo esc_attr($coupon_code); ?>" class="widefat">
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>

                    <div class="mec-form-row">
                        <div class="mec-col-8" style="text-align: right;">
                            <button type="button" class="button mec-add-attendee"><?php esc_html_e('Add Attendee', 'mec'); ?></button>
                        </div>
                    </div>

                    <?php if(count($bfixed_fields)): ?>
                    <div id="mec_date_tickets_booking_form_bfixed_fields">
                        <h3><?php echo sprintf(esc_html__('%s Fields', 'mec'), $this->main->m('booking', esc_html__('Booking', 'mec'))); ?></h3>
                        <hr>
                        <div id="mec_date_tickets_booking_form_bfixed_list">
                            <?php foreach($bfixed_fields as $bfixed_field_id=>$bfixed_field): if(!is_numeric($bfixed_field_id) or !isset($bfixed_field['type']) or (isset($bfixed_field['type']) and !trim($bfixed_field['type']))) continue; $bfixed_value = isset($transaction['fields'][$bfixed_field_id]) ? $transaction['fields'][$bfixed_field_id] : NULL; ?>
                            <div class="mec-form-row mec-book-bfixed-field-<?php echo esc_attr($bfixed_field['type']); ?> <?php echo ((isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) ? 'mec-reg-mandatory' : ''); ?>" data-field-id="<?php echo esc_attr($bfixed_field_id); ?>">
                                <div class="mec-col-2">
                                    <?php if(isset($bfixed_field['label']) and $bfixed_field['type'] != 'agreement' &&  $bfixed_field['type'] != 'name' && $bfixed_field['type'] != 'mec_email'): ?><label for="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>"><?php esc_html_e($bfixed_field['label'], 'mec'); ?><?php echo ((isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) ? '<span class="wbmec-mandatory">*</span>' : ''); ?></label><?php endif; ?>
                                </div>
                                <div class="mec-col-6">

                                    <?php /** Text **/ if($bfixed_field['type'] == 'text'): ?>
                                    <input class="widefat" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>" type="text" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" value="<?php echo esc_attr($bfixed_value); ?>" placeholder="<?php if(isset($bfixed_field['placeholder']) and $bfixed_field['placeholder']) {_e($bfixed_field['placeholder'], 'mec');} else {_e($bfixed_field['label'], 'mec');} ?>" <?php if(isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) echo 'required'; ?> />

                                    <?php /** Date **/ elseif($bfixed_field['type'] == 'date'): ?>
                                    <input class="widefat" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>" type="date" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" value="<?php echo esc_attr($bfixed_value); ?>" placeholder="<?php if(isset($bfixed_field['placeholder']) and $bfixed_field['placeholder']) {_e($bfixed_field['placeholder'], 'mec');} else {_e($bfixed_field['label'], 'mec');} ?>" <?php if(isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) echo 'required'; ?> min="<?php echo esc_attr(date_i18n('Y-m-d', strtotime('-100 years'))); ?>" max="<?php echo esc_attr(date_i18n('Y-m-d', strtotime('+100 years'))); ?>" />

                                    <?php /** Email **/ elseif($bfixed_field['type'] == 'email'): ?>
                                    <input class="widefat" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>" type="email" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" value="<?php echo esc_attr($bfixed_value); ?>" placeholder="<?php if(isset($bfixed_field['placeholder']) and $bfixed_field['placeholder']) {_e($bfixed_field['placeholder'], 'mec');} else {_e($bfixed_field['label'], 'mec');} ?>" <?php if(isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) echo 'required'; ?> />

                                    <?php /** Tel **/ elseif($bfixed_field['type'] == 'tel'): ?>
                                    <input class="widefat" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>" oninput="this.value=this.value.replace(/(?![0-9])./gmi,'')" type="tel" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" value="<?php echo esc_attr($bfixed_value); ?>" placeholder="<?php if(isset($bfixed_field['placeholder']) and $bfixed_field['placeholder']) {_e($bfixed_field['placeholder'], 'mec');} else {_e($bfixed_field['label'], 'mec');} ?>" <?php if(isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) echo 'required'; ?> />

                                    <?php /** Textarea **/ elseif($bfixed_field['type'] == 'textarea'): ?>
                                    <textarea class="widefat" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" placeholder="<?php if(isset($bfixed_field['placeholder']) and $bfixed_field['placeholder']) {_e($bfixed_field['placeholder'], 'mec');} else {_e($bfixed_field['label'], 'mec');} ?>" <?php if(isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) echo 'required'; ?>><?php echo esc_textarea($bfixed_value); ?></textarea>

                                    <?php /** Dropdown **/ elseif($bfixed_field['type'] == 'select'): ?>
                                    <select class="widefat" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" placeholder="<?php if(isset($bfixed_field['placeholder']) and $bfixed_field['placeholder']) {_e($bfixed_field['placeholder'], 'mec');} else {_e($bfixed_field['label'], 'mec');} ?>" <?php if(isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) echo 'required'; ?>>
                                        <?php foreach($bfixed_field['options'] as $bfixed_field_option): ?>
                                        <option value="<?php esc_attr_e($bfixed_field_option['label'], 'mec'); ?>" <?php echo ($bfixed_value == $bfixed_field_option['label'] ? 'selected="selected"' : ''); ?>><?php esc_html_e($bfixed_field_option['label'], 'mec'); ?></option>
                                        <?php endforeach; ?>
                                    </select>

                                    <?php /** Radio **/ elseif($bfixed_field['type'] == 'radio'): ?>
                                    <?php foreach($bfixed_field['options'] as $bfixed_field_option): ?>
                                    <label for="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id.'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label']))); ?>">
                                        <input type="radio" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id.'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label']))); ?>" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" value="<?php esc_attr_e(stripslashes($bfixed_field_option['label']), 'mec'); ?>" <?php echo (($bfixed_value == stripslashes($bfixed_field_option['label'])) ? 'checked="checked"' : ''); ?> />
                                        <?php esc_html_e(stripslashes($bfixed_field_option['label']), 'mec'); ?>
                                    </label>
                                    <?php endforeach; ?>

                                    <?php /** Checkbox **/ elseif($bfixed_field['type'] == 'checkbox'): ?>
                                    <?php foreach($bfixed_field['options'] as $bfixed_field_option): ?>
                                    <label for="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id.'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label']))); ?>">
                                        <input type="checkbox" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id.'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label']))); ?>" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>][]" value="<?php esc_html_e($bfixed_field_option['label'], 'mec'); ?>" <?php echo (($bfixed_value and in_array($bfixed_field_option['label'], $bfixed_value)) ? 'checked="checked"' : ''); ?> />
                                        <?php esc_html_e($bfixed_field_option['label'], 'mec'); ?>
                                    </label>
                                    <?php endforeach; ?>

                                    <?php /** Agreement **/ elseif($bfixed_field['type'] == 'agreement'): ?>
                                    <label for="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>">
                                        <input type="checkbox" id="mec_book_bfixed_field_reg<?php echo esc_attr($bfixed_field_id); ?>" name="mec_fields[<?php echo esc_attr($bfixed_field_id); ?>]" value="1" <?php echo (($bfixed_value == 1) ? 'checked="checked"' : ''); ?> />
                                        <?php echo ((isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']) ? '<span class="wbmec-mandatory">*</span>' : ''); ?>
                                        <?php echo sprintf(esc_html__(stripslashes($bfixed_field['label']), 'mec'), '<a href="'.get_the_permalink($bfixed_field['page']).'" target="_blank">'.get_the_title($bfixed_field['page']).'</a>'); ?>
                                    </label>
                                    <?php endif; ?>

                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>

                    <div id="mec_date_tickets_booking_form_attendees">
                        <h3><?php esc_html_e('Attendees', 'mec'); ?></h3>
                        <div id="mec_date_tickets_booking_form_attendees_list">
                            <?php $i = 0; foreach($attendees as $key => $attendee): $i = max($i, (int) $key); $attachments = (isset($attendees['attachments']) and is_array($attendees['attachments'])) ? $attendees['attachments'] : NULL; ?>
                                <?php
                                    if($key === 'attachments') continue;
                                    if(isset($attendee[0]['MEC_TYPE_OF_DATA'])) continue;
                                ?>
                                <div class="mec-attendee" id="mec_attendee<?php echo esc_attr($key); ?>">
                                    <hr>
                                    <div class="mec-form-row">
                                        <div class="mec-col-8" style="text-align: right;">
                                            <button type="button" class="button mec-remove-attendee" data-key="<?php echo esc_attr($key); ?>"><?php esc_html_e('Remove Attendee', 'mec'); ?></button>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-2">
                                            <label for="att_<?php echo esc_attr($key); ?>_name"><?php esc_html_e('Name', 'mec'); ?></label>
                                        </div>
                                        <div class="mec-col-6">
                                            <input type="text" value="<?php echo ((isset($attendee['name']) and trim($attendee['name'])) ? $attendee['name'] : ''); ?>" id="att_<?php echo esc_attr($key); ?>_name" name="mec_att[<?php echo esc_attr($key); ?>][name]" placeholder="<?php esc_attr_e('Name', 'mec'); ?>" class="widefat">
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-2">
                                            <label for="att_<?php echo esc_attr($key); ?>_email"><?php esc_html_e('Email', 'mec'); ?></label>
                                        </div>
                                        <div class="mec-col-6">
                                            <input type="email" value="<?php echo ((isset($attendee['email']) and trim($attendee['email'])) ? $attendee['email'] : ''); ?>" id="att_<?php echo esc_attr($key); ?>_email" name="mec_att[<?php echo esc_attr($key); ?>][email]" placeholder="<?php esc_attr_e('Email', 'mec'); ?>" class="widefat">
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-2">
                                            <label for="att_<?php echo esc_attr($key); ?>_ticket"><?php echo esc_html($this->main->m('ticket', esc_html__('Ticket', 'mec'))); ?></label>
                                        </div>
                                        <div class="mec-col-6">
                                            <select id="att_<?php echo esc_attr($key); ?>_ticket" name="mec_att[<?php echo esc_attr($key); ?>][id]" class="widefat mec-booking-edit-form-tickets" onchange="mec_edit_booking_ticket_changed(this.value, '<?php echo esc_attr($key); ?>');">
                                                <?php foreach($tickets as $t_id => $ticket): ?>
                                                    <option value="<?php echo esc_attr($t_id); ?>" <?php echo ($t_id == $attendee['id'] ? 'selected="selected"' : ''); ?>><?php echo esc_html($ticket['name']); ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                    </div>
                                    <?php if(count($reg_fields)): ?>
                                        <div class="mec-book-reg-fields" data-key="<?php echo esc_attr($key); ?>">
                                            <?php foreach($reg_fields as $reg_field_id=>$reg_field): if(!is_numeric($reg_field_id) or !isset($reg_field['type']) or (isset($reg_field['type']) and !trim($reg_field['type']))) continue; ?>
                                            <div class="mec-form-row mec-book-reg-field-<?php echo esc_attr($reg_field['type']); ?> <?php echo ((isset($reg_field['mandatory']) and $reg_field['mandatory']) ? 'mec-reg-mandatory' : ''); ?>" data-field-id="<?php echo esc_attr($reg_field_id); ?>">
                                                <div class="mec-col-2">
                                                    <?php if(isset($reg_field['label']) and $reg_field['type'] != 'agreement' &&  $reg_field['type'] != 'name' && $reg_field['type'] != 'mec_email' ): ?><label for="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>"><?php esc_html_e($reg_field['label'], 'mec'); ?><?php echo ((isset($reg_field['mandatory']) and $reg_field['mandatory']) ? '<span class="wbmec-mandatory">*</span>' : ''); ?></label><?php endif; ?>
                                                </div>
                                                <div class="mec-col-6">

                                                    <?php /** Text **/ if($reg_field['type'] == 'text'): ?>
                                                    <input class="widefat" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" type="text" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" value="<?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id])) ? $attendee['reg'][$reg_field_id] : ''); ?>" placeholder="<?php if(isset($reg_field['placeholder']) and $reg_field['placeholder']) {_e($reg_field['placeholder'], 'mec');} else {_e($reg_field['label'], 'mec');} ?>" <?php if(isset($reg_field['mandatory']) and $reg_field['mandatory']) echo 'required'; ?> />

                                                    <?php /** Date **/ elseif($reg_field['type'] == 'date'): ?>
                                                    <input class="widefat" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" type="date" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" value="<?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id])) ? $attendee['reg'][$reg_field_id] : ''); ?>" placeholder="<?php if(isset($reg_field['placeholder']) and $reg_field['placeholder']) {_e($reg_field['placeholder'], 'mec');} else {_e($reg_field['label'], 'mec');} ?>" <?php if(isset($reg_field['mandatory']) and $reg_field['mandatory']) echo 'required'; ?> min="<?php echo esc_attr(date_i18n('Y-m-d', strtotime('-100 years'))); ?>" max="<?php echo esc_attr(date_i18n('Y-m-d', strtotime('+100 years'))); ?>" />

                                                    <?php /** Email **/ elseif($reg_field['type'] == 'email'): ?>
                                                    <input class="widefat" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" type="email" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" value="<?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id])) ? $attendee['reg'][$reg_field_id] : ''); ?>" placeholder="<?php if(isset($reg_field['placeholder']) and $reg_field['placeholder']) {_e($reg_field['placeholder'], 'mec');} else {_e($reg_field['label'], 'mec');} ?>" <?php if(isset($reg_field['mandatory']) and $reg_field['mandatory']) echo 'required'; ?> />

                                                    <?php /** Tel **/ elseif($reg_field['type'] == 'tel'): ?>
                                                    <input class="widefat" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" oninput="this.value=this.value.replace(/(?![0-9])./gmi,'')" type="tel" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" value="<?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id])) ? $attendee['reg'][$reg_field_id] : ''); ?>" placeholder="<?php if(isset($reg_field['placeholder']) and $reg_field['placeholder']) {_e($reg_field['placeholder'], 'mec');} else {_e($reg_field['label'], 'mec');} ?>" <?php if(isset($reg_field['mandatory']) and $reg_field['mandatory']) echo 'required'; ?> />

                                                    <?php /** File **/ elseif($reg_field['type'] == 'file'): ?>
                                                    <button type="button" class="mec-choose-file" data-for="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>"><?php echo esc_html__('Select File', 'mec'); ?></button><input type="hidden" class="widefat" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" value="" />
                                                    <?php if($attachments and is_array($attachments)): foreach($attachments as $attachment): ?><a href="<?php echo esc_url($attachment['url']); ?>" target="_blank"><?php echo esc_html($attachment['filename']); ?></a> <?php endforeach; endif; ?>

                                                    <?php /** Textarea **/ elseif($reg_field['type'] == 'textarea'): ?>
                                                    <textarea class="widefat" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" placeholder="<?php if(isset($reg_field['placeholder']) and $reg_field['placeholder']) {_e($reg_field['placeholder'], 'mec');} else {_e($reg_field['label'], 'mec');} ?>" <?php if(isset($reg_field['mandatory']) and $reg_field['mandatory']) echo 'required'; ?>><?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id])) ? $attendee['reg'][$reg_field_id] : ''); ?></textarea>

                                                    <?php /** Dropdown **/ elseif($reg_field['type'] == 'select'): ?>
                                                    <select class="widefat" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" placeholder="<?php if(isset($reg_field['placeholder']) and $reg_field['placeholder']) {_e($reg_field['placeholder'], 'mec');} else {_e($reg_field['label'], 'mec');} ?>" <?php if(isset($reg_field['mandatory']) and $reg_field['mandatory']) echo 'required'; ?>>
                                                        <?php foreach($reg_field['options'] as $reg_field_option): ?>
                                                            <option value="<?php esc_attr_e($reg_field_option['label'], 'mec'); ?>" <?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id]) and $attendee['reg'][$reg_field_id] == $reg_field_option['label']) ? 'selected="selected"' : ''); ?>><?php esc_html_e($reg_field_option['label'], 'mec'); ?></option>
                                                        <?php endforeach; ?>
                                                    </select>

                                                    <?php /** Radio **/ elseif($reg_field['type'] == 'radio'): ?>
                                                    <?php foreach($reg_field['options'] as $reg_field_option): ?>
                                                        <label for="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id.'_'.strtolower(str_replace(' ', '_', $reg_field_option['label']))); ?>">
                                                            <input type="radio" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id.'_'.strtolower(str_replace(' ', '_', $reg_field_option['label']))); ?>" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" value="<?php esc_attr_e(stripslashes($reg_field_option['label']), 'mec'); ?>" <?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id]) and $attendee['reg'][$reg_field_id] == stripslashes($reg_field_option['label'])) ? 'checked="checked"' : ''); ?> />
                                                            <?php esc_html_e(stripslashes($reg_field_option['label']), 'mec'); ?>
                                                        </label>
                                                    <?php endforeach; ?>

                                                    <?php /** Checkbox **/ elseif($reg_field['type'] == 'checkbox'): ?>
                                                    <?php foreach($reg_field['options'] as $reg_field_option): ?>
                                                        <label for="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id.'_'.strtolower(str_replace(' ', '_', $reg_field_option['label']))); ?>">
                                                            <input type="checkbox" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id.'_'.strtolower(str_replace(' ', '_', $reg_field_option['label']))); ?>" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>][]" value="<?php esc_html_e($reg_field_option['label'], 'mec'); ?>" <?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id]) and in_array($reg_field_option['label'], $attendee['reg'][$reg_field_id])) ? 'checked="checked"' : ''); ?> />
                                                            <?php esc_html_e($reg_field_option['label'], 'mec'); ?>
                                                        </label>
                                                    <?php endforeach; ?>

                                                    <?php /** Agreement **/ elseif($reg_field['type'] == 'agreement'): ?>
                                                    <label for="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>">
                                                        <input type="checkbox" id="mec_book_reg_field_reg<?php echo esc_attr($key.'_'.$reg_field_id); ?>" name="mec_att[<?php echo esc_attr($key); ?>][reg][<?php echo esc_attr($reg_field_id); ?>]" value="1" <?php echo ((isset($attendee['reg']) and isset($attendee['reg'][$reg_field_id]) and $attendee['reg'][$reg_field_id] == 1) ? 'checked="checked"' : ''); ?> />
                                                        <?php echo ((isset($reg_field['mandatory']) and $reg_field['mandatory']) ? '<span class="wbmec-mandatory">*</span>' : ''); ?>
                                                        <?php echo sprintf(esc_html__(stripslashes($reg_field['label']), 'mec'), '<a href="'.get_the_permalink($reg_field['page']).'" target="_blank">'.get_the_title($reg_field['page']).'</a>'); ?>
                                                    </label>
                                                    <?php endif; ?>

                                                </div>
                                            </div>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>

                                    <?php
                                        // Ticket Variations
                                        $ticket_variations = $this->main->ticket_variations($event_id, $attendee['id']);
                                    ?>
                                    <?php if(isset($this->settings['ticket_variations_status']) and $this->settings['ticket_variations_status'] and count($ticket_variations)): ?>
                                    <div class="mec-book-ticket-variations" id="mec_book_ticket_variations_<?php echo esc_attr($key); ?>" data-key="<?php echo esc_attr($key); ?>">
                                        <?php foreach($ticket_variations as $ticket_variation_id=>$ticket_variation): if(!is_numeric($ticket_variation_id) or !isset($ticket_variation['title']) or (isset($ticket_variation['title']) and !trim($ticket_variation['title']))) continue; ?>
                                        <div class="mec-form-row">
                                            <div class="mec-col-2">
                                                <label for="mec_att_<?php echo esc_attr($key); ?>_variations_<?php echo esc_attr($ticket_variation_id); ?>" class="mec-ticket-variation-name"><?php echo esc_html($ticket_variation['title']); ?></label>
                                            </div>
                                            <div class="mec-col-6">
                                                <input id="mec_att_<?php echo esc_attr($key); ?>_variations_<?php echo esc_attr($ticket_variation_id); ?>" type="number" min="0" max="<?php echo ((is_numeric($ticket_variation['max']) and $ticket_variation['max']) ? $ticket_variation['max'] : 1000); ?>" name="mec_att[<?php echo esc_attr($key); ?>][variations][<?php echo esc_attr($ticket_variation_id); ?>]" value="<?php echo (isset($attendee['variations']) and isset($attendee['variations'][$ticket_variation_id])) ? esc_attr($attendee['variations'][$ticket_variation_id]) : 0; ?>">
                                            </div>
                                        </div>
                                        <?php endforeach; ?>
                                    </div>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <input type="hidden" id="mec_booking_edit_new_key" value="<?php echo ($i+1); ?>">
                    </div>
                </div>
                <?php do_action( 'mec_admin_book_edit_form_end', $post->ID, $transaction ) ?>
            </div>
        </div>
        <script>
        function mec_init_booking_media_file()
        {
            jQuery('.mec-choose-file').off('click').on('click', function(event)
            {
                event.preventDefault();

                var _for = jQuery(this).data('for');

                var frame;
                if(frame)
                {
                    frame.open();
                    return;
                }

                frame = wp.media();
                frame.on('select', function()
                {
                    // Grab the selected attachment.
                    var attachment = frame.state().get('selection').first();

                    jQuery('#'+_for).val(attachment.id);
                    frame.close();
                });

                frame.open();
            });
        }

        function mec_toggle_required()
        {
            var status = jQuery('#mec_booking_edit_status').is(':checked');

            if(!status) jQuery('#mec_date_tickets_booking_form_attendees').find(jQuery(':input[required]')).attr('data-should-require', '1').removeAttr('required');
            else jQuery('#mec_date_tickets_booking_form_attendees').find(jQuery(':input[data-should-require="1"]')).attr('required', 'required');
        }

        function mec_edit_booking_ticket_changed(ticket_id, attendee_id)
        {
            var event_id = jQuery('#mec_book_form_event_id').val();
            jQuery.ajax(
            {
                url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                data: "action=mec_bbf_edit_event_ticket_changed&booking_id=<?php echo $post->ID; ?>&event_id="+event_id+"&ticket_id="+ticket_id+"&attendee_id="+attendee_id,
                dataType: "json",
                type: "GET",
                success: function(response)
                {
                    if(response.success === 1)
                    {
                        jQuery('#mec_book_ticket_variations_'+attendee_id).html(response.output);
                    }
                    else
                    {
                        jQuery('#mec_book_edit_form_event_message').html(response.output);
                    }
                },
                error: function()
                {
                }
            });
        }

        jQuery(document).ready(function()
        {
            // Init File Media
            mec_init_booking_media_file();

            jQuery(document).on('click', '.mec-remove-attendee', function()
            {
                var key = jQuery(this).data('key');
                jQuery('#mec_attendee'+key).remove();

                jQuery(document).trigger('mec_book_removed_attendee');
            });

            jQuery('.mec-add-attendee').on('click', function()
            {
                var key = jQuery('#mec_booking_edit_new_key').val();
                var event_id = jQuery('#mec_book_form_event_id').val();

                jQuery('#mec_book_edit_form_event_message').html('');

                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    data: "action=mec_bbf_edit_event_add_attendee&event_id="+event_id+"&key="+key,
                    dataType: "json",
                    type: "GET",
                    success: function(response)
                    {
                        if(response.success === 1)
                        {
                            jQuery('#mec_date_tickets_booking_form_attendees_list').append(response.output);
                            jQuery('#mec_booking_edit_new_key').val(parseInt(key)+1);

                            jQuery('html, body').animate(
                            {
                                scrollTop: jQuery("#mec_attendee"+key).offset().top
                            }, 500);

                            // Init File Media
                            mec_init_booking_media_file();

                            jQuery(document).trigger('mec_book_added_attendee');
                        }
                        else
                        {
                            jQuery('#mec_book_edit_form_event_message').html(response.output);
                        }
                    },
                    error: function()
                    {
                    }
                });
            });

            jQuery('#mec_book_form_event_id').on('change', function()
            {
                var event_id = this.value;
                jQuery('#mec_book_edit_form_event_message').html('');

                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    data: "action=mec_bbf_edit_event_options&event_id="+event_id+"&booking_id=<?php echo $post->ID; ?>",
                    dataType: "json",
                    type: "GET",
                    success: function(response)
                    {
                        if(response.success === 1)
                        {
                            jQuery('#mec_edit_event_date_options_wrapper').html(response.dates);
                            jQuery('.mec-booking-edit-form-tickets').html(response.tickets);

                            jQuery(".mec-book-ticket-variations").each(function()
                            {
                                var key = jQuery(this).data('key');
                                jQuery(this).html(response.variations.replace(/:key:/g, key));
                            });

                            jQuery(".mec-book-reg-fields").each(function()
                            {
                                var key = jQuery(this).data('key');
                                jQuery(this).html(response.reg_fields.replace(/:key:/g, key));
                            });

                            jQuery('#mec_book_edit_form_event_options').show();

                            // Init File Media
                            mec_init_booking_media_file();
                        }
                        else
                        {
                            jQuery('#mec_book_edit_form_event_message').html(response.output);
                            jQuery('#mec_book_edit_form_event_options').hide();
                        }

                        jQuery(document).trigger('mec_bbf_edit_event_options',[ response ]);
                    },
                    error: function()
                    {
                    }
                });
            });

            jQuery('#mec_booking_edit_status').on('change', function()
            {
                mec_toggle_required();
            });

            mec_toggle_required();
        });
        </script>
    <?php
    }

    /**
     * Filters columns of book feature
     * @author Webnus <info@webnus.net>
     * @param array $columns
     * @return array
     */
    public function filter_columns($columns)
    {
        unset($columns['title']);
        unset($columns['date']);
        unset($columns['author']);

        $columns['id'] = esc_html__('ID', 'mec');
        $columns['event_id'] = esc_html__('Event ID', 'mec');
        $columns['title'] = esc_html__('Title', 'mec');
        $columns['attendees'] = esc_html__('Attendees', 'mec');
        $columns['event'] = esc_html__('Event', 'mec');
        $columns['price'] = esc_html__('Price', 'mec');
        $columns['paid'] = esc_html__('Paid', 'mec');
        $columns['confirmation'] = esc_html__('Confirmation', 'mec');
        $columns['verification'] = esc_html__('Verification', 'mec');
        $columns['transaction'] = esc_html__('Transaction ID', 'mec');
        $columns['bdate'] = esc_html__('Book Date', 'mec');
        $columns['order_time'] = esc_html__('Order Time', 'mec');
        $columns['mec_booking_location'] = esc_html__('Location', 'mec');

        return $columns;
    }

    /**
     * Filters sortable columns of book feature
     * @author Webnus <info@webnus.net>
     * @param array $columns
     * @return array
     */
    public function filter_sortable_columns($columns)
    {
        $columns['id'] = 'id';
        $columns['event_id'] = 'event_id';
        $columns['price'] = 'price';
        $columns['paid'] = 'paid';
        $columns['confirmation'] = 'confirmation';
        $columns['verification'] = 'verification';
        $columns['bdate'] = 'date';
        $columns['order_time'] = 'order_time';
        $columns['mec_booking_location'] = 'mec_booking_location';

        return $columns;
    }

    /**
     * Filters columns content of book feature
     * @author Webnus <info@webnus.net>
     * @param string $column_name
     * @param int $post_id
     * @return string
     */
    public function filter_columns_content($column_name, $post_id)
    {
        if($column_name == 'event')
        {
            $event_id = get_post_meta($post_id, 'mec_event_id', true);

            $title = get_the_title($event_id);
            $tickets = get_post_meta($event_id, 'mec_tickets', true);

            $ticket_ids_str = get_post_meta($post_id, 'mec_ticket_id', true);
            $ticket_ids = explode(',', trim($ticket_ids_str, ', '));

            echo ($event_id ? '<a href="'.esc_url($this->main->remove_qs_var('paged', $this->main->add_qs_var('mec_event_id', $event_id))).'">'.$title.'</a>' : '');
            foreach($ticket_ids as $ticket_id)
            {
                echo (isset($tickets[$ticket_id]['name']) ? ' - <a title="'.esc_attr($this->main->m('ticket', esc_attr__('Ticket', 'mec'))).'" href="'.esc_url($this->main->add_qs_vars(array('mec_ticket_id'=>$ticket_id, 'mec_event_id'=>$event_id))).'">'.esc_html($tickets[$ticket_id]['name']).'</a>' : '');
            }
        }
        elseif($column_name == 'event_id')
        {
            echo get_post_meta($post_id, 'mec_event_id', true);
        }
        elseif($column_name == 'attendees')
        {
            $attendees = $this->book->get_attendees($post_id);

            $unique_attendees = [];
            foreach($attendees as $attendee)
            {
                if(!isset($unique_attendees[$attendee['email']])) $unique_attendees[$attendee['email']] = $attendee;
                else $unique_attendees[$attendee['email']]['count'] += 1;
            }

            echo '<strong>'.count($attendees).'</strong>';
            echo '<div class="mec-booking-attendees-tooltip">';
            echo '<ul>';

            foreach($unique_attendees as $unique_attendee)
            {
                echo '<li>';
                echo '<div class="mec-booking-attendees-tooltip-name">'.esc_html($unique_attendee['name']).((isset($unique_attendee['count']) and $unique_attendee['count'] > 1) ? ' ('.esc_html($unique_attendee['count']).')' : '').'</div>';
                echo '<div class="mec-booking-attendees-tooltip-email"><a href="mailto:'.esc_attr($unique_attendee['email']).'">'.esc_html($unique_attendee['email']).'</a></div>';
                echo '</li>';
            }

            echo '</ul>';
            echo '</div>';
        }
        elseif($column_name == 'price')
        {
            $price = get_post_meta($post_id, 'mec_price', true);
            $transaction_id = get_post_meta($post_id, 'mec_transaction_id', true);
            $transaction = $this->book->get_transaction($transaction_id);

            $event_id = $transaction['event_id'] ?? NULL;
            $requested_event_id = $transaction['translated_event_id'] ?? $event_id;

            echo esc_html($this->main->render_price(($price ?: 0), $requested_event_id));
            echo ' '.get_post_meta($post_id, 'mec_gateway_label', true);
        }
        elseif($column_name == 'paid')
        {
            $paid = get_post_meta($post_id, 'mec_payable', true);
            $transaction_id = get_post_meta($post_id, 'mec_transaction_id', true);
            $transaction = $this->book->get_transaction($transaction_id);

            $event_id = $transaction['event_id'] ?? NULL;
            $requested_event_id = $transaction['translated_event_id'] ?? $event_id;

            $paid = apply_filters('mec_book_column_paid', $paid, $post_id, $event_id);

            echo esc_html($this->main->render_price(($paid ?: 0), $requested_event_id));
        }
        elseif($column_name == 'confirmation')
        {
            $confirmed = get_post_meta($post_id, 'mec_confirmed', true);

            echo '<a href="'.esc_url($this->main->add_qs_var('mec_confirmed', $confirmed)).'">'.esc_html($this->main->get_confirmation_label($confirmed)).'</a>';
        }
        elseif($column_name == 'verification')
        {
            $verified = get_post_meta($post_id, 'mec_verified', true);

            echo '<a href="'.esc_url($this->main->add_qs_var('mec_verified', $verified)).'">'.esc_html($this->main->get_verification_label($verified)).'</a>';
        }
        elseif($column_name == 'transaction')
        {
            $transaction_id = get_post_meta($post_id, 'mec_transaction_id', true);
            echo '<a href="'.esc_url($this->main->add_qs_var('mec_transaction_id', $transaction_id)).'">'.esc_html($transaction_id).'</a>';
        }
        elseif($column_name == 'bdate')
        {
            echo '<a href="'.esc_url($this->main->add_qs_var('m', date('Ymd', get_post_time('U', false, $post_id)))).'">'.get_the_date('', $post_id).'</a>';
        }
        elseif($column_name == 'id')
        {
            echo esc_html($post_id);
        }
        elseif($column_name == 'order_time')
        {
            echo get_post_meta($post_id, 'mec_booking_time', true);
        }
        elseif($column_name == 'mec_booking_location')
        {
            $event_id = get_post_meta($post_id, 'mec_event_id', true);
            $timestamps = explode(':', get_post_meta($post_id, 'mec_date', true));

            $location_id = $this->main->get_master_location_id($event_id, $timestamps[0]);
            $location = get_term_by( 'id', $location_id, 'mec_location' );
            echo isset($location->name) ? esc_html($location->name) : '';
        }
    }

    /**
     * @param WP_Query $query
     */
    public function filter_query($query)
    {
        if(!is_admin() or !$query->is_main_query() or $query->get('post_type') != $this->PT) return;

        $orderby = $query->get('orderby');

        if($orderby == 'event_id')
        {
            $query->set('meta_key', 'mec_event_id');
            $query->set('orderby', 'mec_event_id');
        }
        elseif($orderby == 'booker')
        {
            $query->set('orderby', 'user_id');
        }
        elseif($orderby == 'price')
        {
            $query->set('meta_key', 'mec_price');
            $query->set('orderby', 'mec_price');
        }
        elseif($orderby == 'paid')
        {
            $query->set('meta_key', 'mec_payable');
            $query->set('orderby', 'mec_payable');
        }
        elseif($orderby == 'confirmation')
        {
            $query->set('meta_key', 'mec_confirmed');
            $query->set('orderby', 'mec_confirmed');
        }
        elseif($orderby == 'verification')
        {
            $query->set('meta_key', 'mec_verified');
            $query->set('orderby', 'mec_verified');
        }
        elseif($orderby == 'order_time')
        {
            $query->set('meta_key', 'mec_booking_time');
            $query->set('orderby', 'mec_booking_time');
        }
        elseif($orderby == 'id' or trim($orderby) == '')
        {
            $query->set('orderby', 'ID');
        }

        // Meta Query
        $meta_query = [];

        // Filter by Event ID
        if(isset($_REQUEST['mec_event_id']) and trim($_REQUEST['mec_event_id']))
        {
            $meta_query[] = array(
                'key'=>'mec_event_id',
                'value'=>sanitize_text_field($_REQUEST['mec_event_id']),
                'compare'=>'=',
                'type'=>'numeric'
            );
        }

        // Filter by Occurrence
        if(isset($_REQUEST['mec_occurrence']) and trim($_REQUEST['mec_occurrence']))
        {
            $date_query = array(
                array(
                    'year'=>date('Y', sanitize_text_field($_REQUEST['mec_occurrence'])),
                    'monthnum'=>date('m', sanitize_text_field($_REQUEST['mec_occurrence'])),
                    'day'=>date('d', sanitize_text_field($_REQUEST['mec_occurrence'])),
                    'hour'=>date('H', sanitize_text_field($_REQUEST['mec_occurrence'])),
                    'minute'=>date('i', sanitize_text_field($_REQUEST['mec_occurrence'])),
                ),
            );

            $query->set('date_query', $date_query);
        }

        // Filter by Ticket ID
        if(isset($_REQUEST['mec_ticket_id']) and trim($_REQUEST['mec_ticket_id']))
        {
            $meta_query[] = array(
                'key'=>'mec_ticket_id',
                'value'=>','.sanitize_text_field($_REQUEST['mec_ticket_id']).',',
                'compare'=>'LIKE'
            );
        }

        // Filter by Ticket Name
        if(isset($_REQUEST['mec_ticket_name']) and trim($_REQUEST['mec_ticket_name']))
        {
            $mec_ticket_end = explode(':..:', sanitize_text_field($_REQUEST['mec_ticket_name']));
            $meta_query[] = array(
                'relation' => 'AND',
                array(
                    'key'     => 'mec_ticket_id',
                    'value'   => sanitize_text_field(end($mec_ticket_end)),
                    'compare' => 'LIKE',
                ),
                array(
                    'key'     => 'mec_event_id',
                    'value'   => current(explode(':..:', sanitize_text_field($_REQUEST['mec_ticket_name']))),
                    'type'    => 'numeric',
                    'compare' => '=',
                )
            );
        }

        // Filter by Transaction ID
        if(isset($_REQUEST['mec_transaction_id']) and trim($_REQUEST['mec_transaction_id']))
        {
            $meta_query[] = array(
                'key'=>'mec_transaction_id',
                'value'=>sanitize_text_field($_REQUEST['mec_transaction_id']),
                'compare'=>'='
            );
        }

        // Filter by Confirmation
        if(isset($_REQUEST['mec_confirmed']) and trim($_REQUEST['mec_confirmed']) != '')
        {
            $meta_query[] = array(
                'key'=>'mec_confirmed',
                'value'=>sanitize_text_field($_REQUEST['mec_confirmed']),
                'compare'=>'=',
                'type'=>'numeric'
            );
        }

        // Filter by Verification
        if(isset($_REQUEST['mec_verified']) and trim($_REQUEST['mec_verified']) != '')
        {
            $meta_query[] = array(
                'key'=>'mec_verified',
                'value'=>sanitize_text_field($_REQUEST['mec_verified']),
                'compare'=>'=',
                'type'=>'numeric'
            );
        }

        // Filter by ID
        if(isset($_REQUEST['id']) and trim($_REQUEST['id']) != '')
        {
            $meta_query[] = array(
                'orderby' => 'ID'
            );
        }

        // Filter by Order Date
        if(isset($_REQUEST['mec_order_date']) and trim($_REQUEST['mec_order_date']) != '')
        {
            $type = sanitize_text_field($_REQUEST['mec_order_date']);

            $min = current_time('Y-m-d');
            $max = date('Y-m-d', strtotime('Tomorrow'));

            if($type == 'yesterday')
            {
                $min = date('Y-m-d', strtotime('Yesterday'));
                $max = current_time('Y-m-d');
            }
            elseif($type == 'current_month')
            {
                $min = current_time('Y-m-01');
            }
            elseif($type == 'last_month')
            {
                $min = date('Y-m-01', strtotime('Last Month'));
                $max = date('Y-m-t', strtotime('Last Month'));
            }
            elseif($type == 'current_year')
            {
                $min = current_time('Y-01-01');
            }
            elseif($type == 'last_year')
            {
                $min = date('Y-01-01', strtotime('Last Year'));
                $max = date('Y-12-31', strtotime('Last Year'));
            }

            $meta_query[] = array(
                'key'=>'mec_booking_time',
                'value'=>array($min, $max),
                'compare'=>'BETWEEN',
                'type'=>'DATETIME'
            );
        }

        // Filter by Location
        if(isset($_REQUEST['mec_booking_location']) and trim($_REQUEST['mec_booking_location']) != '')
        {
            $meta_query[] = array(
                'key'=>'mec_booking_location',
                'value'=>sanitize_text_field($_REQUEST['mec_booking_location']),
                'compare'=>'=',
                'type'=>'numeric'
            );
        }

        if(count($meta_query)) $query->set('meta_query', $meta_query);
    }

    public function add_filters($post_type)
    {
        if($post_type != $this->PT) return;

        $query = new WP_Query(array(
            'post_type' => $this->main->get_main_post_type(),
            'posts_per_page' => -1,
            'post_status' => array('publish')
        ));

        $mec_event_id = isset($_REQUEST['mec_event_id']) ? sanitize_text_field($_REQUEST['mec_event_id']) : '';

        echo '<span class="input-field"><select name="mec_event_id" id="mec_filter_event_id" class="mec-select2">';
        echo '<option value="">'.esc_html__('Event', 'mec').'</option>';

        if($query->have_posts())
        {
            while($query->have_posts())
            {
                $query->the_post();

                $ID = get_the_ID();
                if($this->main->get_original_event($ID) !== $ID) $ID = $this->main->get_original_event($ID);

                echo '<option value="'.esc_attr($ID).'" '.($mec_event_id == $ID ? 'selected="selected"' : '').'>' . get_the_title() . '</option>';
            }
        }

        echo '</select></span>';

        echo "<script>
        jQuery(document).ready(function($)
        {
            $('#mec_filter_event_id').select2();
            $('[name=\"mec_ticket_name\"]').select2();
            jQuery('#mec_filter_event_id').on('change', function()
            {
                jQuery('#mec_filter_occurrence').remove();

                var event_id = jQuery(this).val();
                jQuery.ajax(
                {
                    type: 'POST',
                    url: ajaxurl,
                    data: 'action=mec_booking_filters_occurrence&event_id='+event_id,
                    dataType: 'json',
                    success: function(data)
                    {
                        jQuery('#mec_filter_event_id').after(data.html);
                    },
                    error: function(jqXHR, textStatus, errorThrown)
                    {
                    }
                });
            });
        });
        </script>";

        if($mec_event_id) echo $this->add_occurrence_filter($mec_event_id);

        $tickets = $this->db->select("SELECT `post_id`, `meta_value` FROM `#__postmeta` WHERE `meta_key`='mec_tickets'", 'loadAssocList');
        if(!is_array($tickets)) $tickets = [];

        $mec_ticket_name = isset($_REQUEST['mec_ticket_name']) ? sanitize_text_field($_REQUEST['mec_ticket_name']) : '';

        echo '<span class="input-field"><select name="mec_ticket_name">';
        echo '<option value="">'.esc_html__('Ticket', 'mec').'</option>';

        foreach($tickets as $single_ticket)
        {
            $ticket_value = (is_serialized($single_ticket['meta_value'])) ? unserialize($single_ticket['meta_value']) : [];
            foreach($ticket_value as $ticket)
            {
                $rendered_tickets = [];
                if(is_array($ticket) && isset($ticket['name']) && !in_array($ticket['name'], $rendered_tickets))
                {
                    $value = $single_ticket['post_id'].':..:'.','.key($ticket_value).',';
                    echo '<option value="'.esc_attr($value).'"'.selected($value, $mec_ticket_name).'>'.(!trim($ticket['name']) ? get_the_title($single_ticket['post_id']) .  esc_html__(' - Ticket', 'mec') . intval(key($ticket_value)) : $ticket['name']) . '</option>';
                    $rendered_tickets[] = $ticket['name'];
                }

                next($ticket_value);
            }
        }

        echo '</select></span>';

        $mec_confirmed = isset($_REQUEST['mec_confirmed']) ? sanitize_text_field($_REQUEST['mec_confirmed']) : '';

        echo '<select name="mec_confirmed">';
        echo '<option value="">'.esc_html__('Confirmation', 'mec').'</option>';
        echo '<option value="1" '.($mec_confirmed == '1' ? 'selected="selected"' : '').'>'.esc_html__('Confirmed', 'mec').'</option>';
        echo '<option value="0" '.($mec_confirmed == '0' ? 'selected="selected"' : '').'>'.esc_html__('Pending', 'mec').'</option>';
        echo '<option value="-1" '.($mec_confirmed == '-1' ? 'selected="selected"' : '').'>'.esc_html__('Rejected', 'mec').'</option>';
        echo '</select>';

        $mec_verified = isset($_REQUEST['mec_verified']) ? sanitize_text_field($_REQUEST['mec_verified']) : '';

        echo '<select name="mec_verified">';
        echo '<option value="">'.esc_html__('Verification', 'mec').'</option>';
        echo '<option value="1" '.($mec_verified == '1' ? 'selected="selected"' : '').'>'.esc_html__('Verified', 'mec').'</option>';
        echo '<option value="0" '.($mec_verified == '0' ? 'selected="selected"' : '').'>'.esc_html__('Waiting', 'mec').'</option>';
        echo '<option value="-1" '.($mec_verified == '-1' ? 'selected="selected"' : '').'>'.esc_html__('Canceled', 'mec').'</option>';
        echo '</select>';

        $mec_order_date = isset($_REQUEST['mec_order_date']) ? sanitize_text_field($_REQUEST['mec_order_date']) : '';

        echo '<select name="mec_order_date">';
        echo '<option value="">'.esc_html__('Order Date', 'mec').'</option>';
        echo '<option value="today" '.($mec_order_date == 'today' ? 'selected="selected"' : '').'>'.esc_html__('Today', 'mec').'</option>';
        echo '<option value="yesterday" '.($mec_order_date == 'yesterday' ? 'selected="selected"' : '').'>'.esc_html__('Yesterday', 'mec').'</option>';
        echo '<option value="current_month" '.($mec_order_date == 'current_month' ? 'selected="selected"' : '').'>'.esc_html__('Current Month', 'mec').'</option>';
        echo '<option value="last_month" '.($mec_order_date == 'last_month' ? 'selected="selected"' : '').'>'.esc_html__('Last Month', 'mec').'</option>';
        echo '<option value="current_year" '.($mec_order_date == 'current_year' ? 'selected="selected"' : '').'>'.esc_html__('Current Year', 'mec').'</option>';
        echo '<option value="last_year" '.($mec_order_date == 'last_year' ? 'selected="selected"' : '').'>'.esc_html__('Last Year', 'mec').'</option>';
        echo '</select>';

        $locations = get_terms( 'mec_location', array('hide_empty' => true,));
        if(!is_array($locations)) $locations = [];

        $mec_booking_location = isset($_REQUEST['mec_booking_location']) ? sanitize_text_field($_REQUEST['mec_booking_location']) : '';

        echo '<select name="mec_booking_location">';
        echo '<option value="">'.esc_html__('Location', 'mec').'</option>';
        foreach ($locations as $key => $value) {
            echo '<option value="'.esc_attr($value->term_id).'" '.($mec_booking_location == $value->term_id ? 'selected="selected"' : '').'>'.esc_html($value->name).'</option>';
        }
        echo '</select>';
    }

    public function add_bulk_actions()
    {
        global $post_type;

        if($post_type == $this->PT)
        {
            ?>
            <script>
            jQuery(document).ready(function()
            {
                <?php foreach(array('pending'=>__('Pending', 'mec'), 'confirm'=>__('Confirm', 'mec'), 'reject'=>__('Reject', 'mec'), 'csv-export'=>__('CSV Export', 'mec'), 'ms-excel-export'=>__('MS Excel Export', 'mec')) as $action=>$label): ?>
                jQuery('<option>').val('<?php echo esc_js($action); ?>').text('<?php echo esc_js($label); ?>').appendTo("select[name='action']");
                jQuery('<option>').val('<?php echo esc_js($action); ?>').text('<?php echo esc_js($label); ?>').appendTo("select[name='action2']");
                <?php endforeach; ?>
            });
            </script>
            <?php
        }
    }

    public function do_bulk_actions()
    {
        $wp_list_table = _get_list_table('WP_Posts_List_Table');

        $action = $wp_list_table->current_action();
        if(!$action) return false;

        $post_type = isset($_REQUEST['post_type']) ? sanitize_text_field($_REQUEST['post_type']) : 'post';
        if($post_type != $this->PT) return false;

        check_admin_referer('bulk-posts');

        switch($action)
        {
            case 'confirm':

                $post_ids = (isset($_REQUEST['post']) and is_array($_REQUEST['post']) and count($_REQUEST['post'])) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['post'])) : [];
                foreach($post_ids as $post_id) $this->book->confirm((int) $post_id);

                break;
            case 'pending':

                $post_ids = (isset($_REQUEST['post']) and is_array($_REQUEST['post']) and count($_REQUEST['post'])) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['post'])) : [];
                foreach($post_ids as $post_id) $this->book->pending((int) $post_id);

                break;
            case 'reject':

                $post_ids = (isset($_REQUEST['post']) and is_array($_REQUEST['post']) and count($_REQUEST['post'])) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['post'])) : [];
                foreach($post_ids as $post_id) $this->book->reject((int) $post_id);

                break;

            case 'ms-excel-export':

                $filename = 'bookings-'.md5(time().mt_rand(100, 999)).'.xlsx';

                $rows = $this->csvexcel();
                $this->main->generate_download_excel($rows, $filename);

                exit;

            case 'csv-export':

                $filename = 'bookings-'.md5(time().mt_rand(100, 999)).'.csv';

                $rows = $this->csvexcel();
                $this->main->generate_download_csv($rows, $filename);

                exit;

            default: return true;
        }

        wp_redirect('edit.php?post_type='.$this->PT);
        exit;
    }

    public function csvexcel($post_ids = NULL)
    {
        if(!$post_ids) $post_ids = (isset($_REQUEST['post']) and is_array($_REQUEST['post']) and count($_REQUEST['post'])) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['post'])) : [];

        $event_ids = [];
        foreach($post_ids as $post_id) $event_ids[] = get_post_meta($post_id, 'mec_event_id', true);
        $event_ids = array_unique($event_ids);

        $main_event_id = NULL;
        if(count($event_ids) == 1) $main_event_id = $event_ids[0];

        $columns = array(
            esc_html__('ID', 'mec'),
            esc_html__('Event', 'mec'),
            esc_html__('Start Date & Time', 'mec'),
            esc_html__('End Date & Time', 'mec'),
            esc_html__('Location', 'mec'),
            esc_html__('Order Time', 'mec'),
            $this->main->m('ticket', esc_html__('Ticket', 'mec')),
            esc_html__('Transaction ID', 'mec'),
            esc_html__('Total Price', 'mec'),
            esc_html__('Gateway', 'mec'),
            esc_html__('Name', 'mec'),
            esc_html__('Email', 'mec'),
            esc_html__('Ticket Variation', 'mec'),
            esc_html__('Confirmation', 'mec'),
            esc_html__('Verification', 'mec'),
            esc_html__('Other Dates', 'mec'),
        );

        $columns = apply_filters('mec_csv_export_columns', $columns);

        $bfixed_fields = $this->main->get_bfixed_fields($main_event_id);
        foreach($bfixed_fields as $bfixed_field_key=>$bfixed_field)
        {
            // Placeholder Keys
            if(!is_numeric($bfixed_field_key)) continue;

            $type = $bfixed_field['type'] ?? '';
            $label = isset($bfixed_field['label']) ? esc_html__($bfixed_field['label'], 'mec') : '';

            if($type == 'agreement') $label = sprintf($label, get_the_title($bfixed_field['page']));
            if(trim($label) == '') continue;

            $columns[] = stripslashes($label);
        }

        $reg_fields = $this->main->get_reg_fields($main_event_id);
        foreach($reg_fields as $reg_field_key=>$reg_field)
        {
            // Placeholder Keys
            if(!is_numeric($reg_field_key)) continue;

            $type = $reg_field['type'] ?? '';
            $label = isset($reg_field['label']) ? esc_html__($reg_field['label'], 'mec') : '';

            if(trim($label) == '' or $type == 'name' or $type == 'mec_email') continue;
            if($type == 'agreement') $label = sprintf($label, get_the_title($reg_field['page']));

            $columns[] = stripslashes($label);
        }

        $columns[] = 'Attachments';

        // Date & Time Format
        $datetime_format = 'Y-m-d H:i:s';

        // MEC User
        $u = $this->getUser();

        $rows = [];
        $rows[] = $columns;

        foreach($post_ids as $post_id)
        {
            $post_id = (int) $post_id;

            $event_id = get_post_meta($post_id, 'mec_event_id', true);
            $transaction_id = get_post_meta($post_id, 'mec_transaction_id', true);
            $order_time = get_post_meta($post_id, 'mec_booking_time', true);
            $tickets = get_post_meta($event_id, 'mec_tickets', true);
            $timestamps = explode(':', get_post_meta($post_id, 'mec_date', true));

            $main_location_id = get_post_meta($event_id, 'mec_location_id', true);

            $location_name = '';
            if(is_numeric($main_location_id) && $main_location_id > 1)
            {
                $location = get_term((int) $main_location_id, 'mec_location');
                if($location instanceof WP_Term) $location_name = $location->name;
            }

            $attendees = get_post_meta($post_id, 'mec_attendees', true);
            if(!is_array($attendees) || !count($attendees)) $attendees = array(get_post_meta($post_id, 'mec_attendee', true));

            $gateway_label = get_post_meta($post_id, 'mec_gateway_label', true);
            $booker = $u->booking($post_id);

            $confirmed = $this->main->get_confirmation_label(get_post_meta($post_id, 'mec_confirmed', true));
            $verified = $this->main->get_verification_label(get_post_meta($post_id, 'mec_verified', true));
            $transaction = $this->book->get_transaction($transaction_id);

            $requested_event_id = $transaction['translated_event_id'] ?? $event_id;

            // Transaction not valid
            if(!is_array($transaction) or (is_array($transaction) and !isset($transaction['date']))) continue;

            // Make sure event ID Exists on transaction data
            if(!isset($transaction['event_id'])) $transaction['event_id'] = $event_id;

            $other_dates_formatted = [];

            $other_dates = (isset($transaction['other_dates']) and is_array($transaction['other_dates'])) ? $transaction['other_dates'] : [];
            foreach($other_dates as $other_date)
            {
                $other_timestamps = explode(':', $other_date);
                $other_dates_formatted[] = date($datetime_format, $other_timestamps[0]).' -> '.date($datetime_format, $other_timestamps[1]);
            }

            $attachments = '';
            if(isset($attendees['attachments']))
            {
                foreach($attendees['attachments'] as $attachment)
                {
                    $attachments .= @$attachment['url'] . "\n";
                }
            }

            $bookings = [];
            foreach($attendees as $key => $attendee)
            {
                if($key === 'attachments') continue;
                if(isset($attendee[0]['MEC_TYPE_OF_DATA'])) continue;

                $ticket_variations_output = '';
                if(isset($attendee['variations']) and is_array($attendee['variations']) and count($attendee['variations']))
                {
                    $ticket_variations = $this->main->ticket_variations($event_id, $attendee['id']);
                    foreach($attendee['variations'] as $a_variation_id => $a_variation_count)
                    {
                        if((int) $a_variation_count > 0) $ticket_variations_output .= (isset($ticket_variations[$a_variation_id]) ? $ticket_variations[$a_variation_id]['title'] : 'N/A').": (".$a_variation_count.')'.", ";
                    }
                }

                $rendered_price = $this->main->render_price($this->book->get_ticket_total_price($transaction, $attendee, $post_id), $requested_event_id);

                $ticket_id = $attendee['id'] ?? get_post_meta($post_id, 'mec_ticket_id', true);
                $booking = array(
                    $post_id,
                    html_entity_decode(get_the_title($event_id), ENT_QUOTES | ENT_HTML5),
                    date($datetime_format, $timestamps[0]),
                    date($datetime_format, $timestamps[1]),
                    $location_name,
                    date($datetime_format, strtotime($order_time)),
                    ($tickets[$ticket_id]['name'] ?? esc_html__('Unknown', 'mec')),
                    $transaction_id,
                    $rendered_price,
                    html_entity_decode($gateway_label, ENT_QUOTES | ENT_HTML5),
                    ($attendee['name'] ?? (isset($booker->first_name) ? trim($booker->first_name . ' ' . $booker->last_name) : '')),
                    ($attendee['email'] ?? @$booker->user_email),
                    html_entity_decode(trim($ticket_variations_output, ', '), ENT_QUOTES | ENT_HTML5),
                    $confirmed,
                    $verified,
                    (count($other_dates_formatted) ? implode("\n", $other_dates_formatted) : NULL)
                );

                $booking = apply_filters('mec_csv_export_booking', $booking, $post_id, $event_id, $attendee);

                $bfixed_values = (isset($transaction['fields']) and is_array($transaction['fields'])) ? $transaction['fields'] : [];
                foreach($bfixed_fields as $bfixed_field_id => $bfixed_field)
                {
                    if(!is_numeric($bfixed_field_id)) continue;

                    $bfixed_label = $bfixed_field['label'] ?? '';
                    if(trim($bfixed_label) == '') continue;

                    $booking[] = isset($bfixed_values[$bfixed_field_id]) ? ((is_string($bfixed_values[$bfixed_field_id]) and trim($bfixed_values[$bfixed_field_id])) ? stripslashes($bfixed_values[$bfixed_field_id]) : (is_array($bfixed_values[$bfixed_field_id]) ? implode(' | ', $bfixed_values[$bfixed_field_id]) : '---')) : '';
                }

                $reg_form = $attendee['reg'] ?? [];
                foreach($reg_fields as $field_id=>$reg_field)
                {
                    // Placeholder Keys
                    if(!is_numeric($field_id)) continue;

                    $type = $reg_field['type'] ?? '';
                    $label = isset($reg_field['label']) ? esc_html__($reg_field['label'], 'mec') : '';
                    if(trim($label) == '' or $type == 'name' or $type == 'mec_email') continue;

                    $booking[] = isset($reg_form[$field_id]) ? ((is_string($reg_form[$field_id]) and trim($reg_form[$field_id])) ? stripslashes($reg_form[$field_id]) : (is_array($reg_form[$field_id]) ? implode(' | ', $reg_form[$field_id]) : '---')) : '';
                }

                $booking[]  = $attachments;
                $attachments = '';

                $bookings[] = $booking;
            }

            $bookings = apply_filters('mec_csv_export_booking_all', $bookings);
            foreach($bookings as $b) $rows[] = $b;
        }

        return $rows;
    }

    /**
     * Save book data from backend
     * @author Webnus <info@webnus.net>
     * @param int $post_id
     * @return void
     */
    public function save_book($post_id)
    {
        // Check if our nonce is set.
        if(!isset($_POST['mec_book_nonce'])) return;

        // Verify that the nonce is valid.
        if(!wp_verify_nonce(sanitize_text_field($_POST['mec_book_nonce']), 'mec_book_data')) return;

        // If this is an autosave, our form has not been submitted, so we don't want to do anything.
        if(defined('DOING_AUTOSAVE') and DOING_AUTOSAVE) return;

        if(isset($_GET['mec-edit-booking-done'])) return;
        $_GET['mec-edit-booking-done'] = 1;

        // New Booking
        $is_new_booking = isset($_POST['mec_is_new_booking']) ? sanitize_text_field($_POST['mec_is_new_booking']) : 0;
        if($is_new_booking and isset($_POST['mec_attendee']) and isset($_POST['mec_date']))
        {
            // Initialize Pay Locally Gateway to handle the booking
            $gateway = new MEC_gateway_pay_locally();

            // Register Attendee
            $attendees = is_array($_POST['mec_attendee']) ? $this->main->sanitize_deep_array($_POST['mec_attendee']) : [];

            $main_attendee = (isset($attendees[0]) and is_array($attendees[0])) ? $attendees[0] : [];
            $user_id = $gateway->register_user($main_attendee);

            $attention_date = $this->main->sanitize_deep_array($_POST['mec_date']);

            $all_dates = [];
            $other_dates = [];
            $timestamps = is_array($attention_date) ? $attention_date : array($attention_date);

            // Multiple Date Booking System
            if(is_array($attention_date))
            {
                $all_dates = $attention_date;
                $other_dates = $attention_date;
                $attention_date = array_shift($other_dates);
            }

            $attention_times = explode(':', $attention_date);
            $date = date('Y-m-d H:i:s', trim($attention_times[0]));

            $name = $main_attendee['name'] ?? '';
            $event_id = isset($_POST['mec_event_id']) ? sanitize_text_field($_POST['mec_event_id']) : '';
            $coupon = isset($_POST['mec_coupon']) ? sanitize_text_field($_POST['mec_coupon']) : '';

            // Booking Fixed Fields
            $bfixed_fields = (isset($_POST['mec_fields']) and is_array($_POST['mec_fields'])) ? $_POST['mec_fields'] : [];

            $attendees_count = count($attendees);
            if($attendees_count < 1) $attendees_count = 1;

            $raw_tickets = [];
            $raw_variations = [];
            $tickets = [];
            $ticket_ids = '';

            for($i = 0; $i < $attendees_count; $i++)
            {
                $attendee = (isset($attendees[$i]) and is_array($attendees[$i])) ? $attendees[$i] : [];
                $ticket_id = $attendee['id'] ?? 0;

                $tickets[] = array_merge($attendee, array(
                    'id'=>$ticket_id,
                    'count'=>1,
                    'variations'=>$attendee['variations'] ?? [],
                    'reg'=>$attendee['reg'] ?? []
                ));

                $ticket_ids .= $ticket_id.',';

                if(!isset($raw_tickets[$ticket_id])) $raw_tickets[$ticket_id] = 1;
                else $raw_tickets[$ticket_id] += 1;

                if(isset($attendee['variations']) and is_array($attendee['variations']) and count($attendee['variations']))
                {
                    // Variations Per Ticket
                    if(!isset($raw_variations[$ticket_id])) $raw_variations[$ticket_id] = [];

                    foreach($attendee['variations'] as $variation_id=>$variation_count)
                    {
                        if(!trim($variation_count)) continue;

                        if(!isset($raw_variations[$ticket_id][$variation_id])) $raw_variations[$ticket_id][$variation_id] = $variation_count;
                        else $raw_variations[$ticket_id][$variation_id] += $variation_count;
                    }
                }
            }

            $event_tickets = get_post_meta($event_id, 'mec_tickets', true);

            // ID of Pay Locally Gateway
            $gateway_id = 1;

            // Disabled Gateways
            $disabled_gateways = ((isset($this->settings['fees_disabled_gateways']) and is_array($this->settings['fees_disabled_gateways'])) ? $this->settings['fees_disabled_gateways'] : array());

            $apply_fees = false;
            if(!count($disabled_gateways) or !isset($disabled_gateways[$gateway_id]) or (isset($disabled_gateways[$gateway_id]) and !$disabled_gateways[$gateway_id])) $apply_fees = true;

            $transaction = [];
            $transaction['tickets'] = $tickets;
            $transaction['date'] = $attention_date;
            $transaction['all_dates'] = $all_dates;
            $transaction['other_dates'] = $other_dates;
            $transaction['timestamps'] = $timestamps;
            $transaction['event_id'] = $event_id;

            // Calculate price of bookings
            $price_details = $this->book->get_price_details($raw_tickets, $event_id, $event_tickets, $raw_variations, $timestamps, $apply_fees);

            $transaction['price_details'] = $price_details;
            $transaction['total'] = $price_details['total'];
            $transaction['discount'] = 0;
            $transaction['price'] = $price_details['total'];
            $transaction['payable'] = $price_details['payable'];
            $transaction['coupon'] = $coupon;
            $transaction['fields'] = $bfixed_fields;

            // Save The Transaction
            $transactionObject = new \MEC\Transactions\Transaction( 0, $transaction );
            $transaction_id = $transactionObject->update_data();

            // MEC User
            $u = $this->getUser();

            remove_action('save_post', array($this, 'save_book'), 10); // In order to don't create infinitive loop!
            $post_id = $this->book->add(array(
                'ID'=>$post_id,
                'post_author'=>$user_id,
                'post_type'=>$this->PT,
                'post_title'=>$name.' - '.$u->get($user_id)->user_email,
                'post_date'=>$date,
                'mec_attendees'=>$tickets,
                'mec_gateway' => 'MEC_gateway_pay_locally',
                'mec_gateway_label' => $gateway->title()
            ), $transaction_id, ','.trim($ticket_ids, ', ').',');

            // Assign User
            $u->assign($post_id, $user_id);

            update_post_meta($post_id, 'mec_attendees', $tickets);
            update_post_meta($post_id, 'mec_reg', $attendee['reg'] ?? []);

            // For Booking Badge
            update_post_meta($post_id, 'mec_book_date_submit', date('YmdHis', current_time('timestamp', 0)));

            // Apply Coupon
            if($coupon)
            {
                $this->book->coupon_apply($coupon, $transaction_id);

                $transaction = $this->book->get_transaction($transaction_id);

                update_post_meta($post_id, 'mec_price', $transaction['price']);
                if(isset($transaction['payable'])) update_post_meta($post_id, 'mec_payable', $transaction['payable']);
            }

            $confirmation_status = isset($_POST['confirmation']) ? sanitize_text_field($_POST['confirmation']) : NULL;
            $verification_status = isset($_POST['verification']) ? sanitize_text_field($_POST['verification']) : NULL;

            if($confirmation_status == 1) $this->book->confirm($post_id);
            if($verification_status == 1) $this->book->verify($post_id);

            // Fires after completely creating a new booking
            do_action('mec_booking_completed', $post_id);
        }
        // It's a new booking request but due to lack of data it did not created
        elseif($is_new_booking)
        {
            return;
        }

        // Edit Booking
        $is_edit_booking = isset($_POST['mec_booking_edit_status']) ? sanitize_text_field($_POST['mec_booking_edit_status']) : 0;
        if($is_edit_booking)
        {
            $event_id = isset($_POST['mec_event_id']) ? sanitize_text_field($_POST['mec_event_id']) : '';
            if($event_id) update_post_meta($post_id, 'mec_event_id', $event_id);

            $attention_date = isset($_POST['mec_date']) ? $this->main->sanitize_deep_array($_POST['mec_date']) : NULL;

            $all_dates = [];
            $other_dates = [];
            $timestamps = is_array($attention_date) ? $attention_date : array($attention_date);

            // Multiple Date Booking System
            if(is_array($attention_date))
            {
                $all_dates = $attention_date;
                $other_dates = $attention_date;
                $attention_date = array_shift($other_dates);
            }

            if($attention_date) update_post_meta($post_id, 'mec_date', $attention_date);

            $attention_times = explode(':', $attention_date);
            $date = date('Y-m-d H:i:s', $attention_times[0] ? trim($attention_times[0]) : null);

            // Attendees
            $mec_attendees = get_post_meta($post_id, 'mec_attendees', true);
            $mec_atts = (isset($_POST['mec_att']) and is_array($_POST['mec_att'])) ? $this->main->sanitize_deep_array($_POST['mec_att']) : [];

            // Booking Fixed Fields
            $bfixed_fields = (isset($_POST['mec_fields']) and is_array($_POST['mec_fields'])) ? $this->main->sanitize_deep_array($_POST['mec_fields']) : [];

            // Attachments
            $attachments = (isset($mec_attendees['attachments']) and is_array($mec_attendees['attachments'])) ? $mec_attendees['attachments'] : NULL;

            $reg_fields = $this->main->get_reg_fields($event_id);

            $ticket_ids = '';
            $raw_tickets = [];
            $raw_variations = [];
            $done_files = [];

            $new_attendees = [];
            $new_attachments = [];
            foreach($mec_atts as $key => $mec_att)
            {
                $original = $mec_attendees[$key] ?? [];

                $reg_data = (isset($mec_att['reg']) and is_array($mec_att['reg'])) ? $mec_att['reg'] : [];
                foreach($reg_data as $reg_id => $reg_value)
                {
                    if(!$reg_value) continue;

                    $reg_field = $reg_fields[$reg_id] ?? NULL;
                    if(!$reg_field) continue;

                    $reg_field_type = $reg_field['type'] ?? NULL;
                    if($reg_field_type !== 'file') continue;

                    if(in_array($reg_value, $done_files)) continue;

                    $new_attachments[] = array(
                        'MEC_TYPE_OF_DATA' => 'attachment',
                        'response' => 'SUCCESS',
                        'filename' => basename(get_attached_file($reg_value)),
                        'url' => wp_get_attachment_url($reg_value),
                        'type' => get_post_mime_type($reg_value),
                    );

                    $done_files[] = $reg_value;
                }

                $new_attendee = array_merge($original, $mec_att);
                $new_attendees[] = $new_attendee;

                $ticket_id = $mec_att['id'] ?? '';
                if($ticket_id)
                {
                    $ticket_ids .= $mec_att['id'].',';

                    if(!isset($raw_tickets[$ticket_id])) $raw_tickets[$ticket_id] = 1;
                    else $raw_tickets[$ticket_id]++;

                    if(isset($new_attendee['variations']) and is_array($new_attendee['variations']) and count($new_attendee['variations']))
                    {
                        // Variations Per Ticket
                        if(!isset($raw_variations[$ticket_id])) $raw_variations[$ticket_id] = [];

                        foreach($new_attendee['variations'] as $variation_id=>$variation_count)
                        {
                            if(!trim($variation_count)) continue;

                            if(!isset($raw_variations[$ticket_id][$variation_id])) $raw_variations[$ticket_id][$variation_id] = $variation_count;
                            else $raw_variations[$ticket_id][$variation_id] += $variation_count;
                        }
                    }
                }
            }

            // Apply Attachments
            if(count($new_attachments)) $attachments = $new_attachments;
            if(is_array($attachments)) $new_attendees['attachments'] = $attachments;

            update_post_meta($post_id, 'mec_attendees', $new_attendees);
            update_post_meta($post_id, 'mec_ticket_id', ','.trim($ticket_ids, ', ').',');

            $transaction_id = get_post_meta($post_id, 'mec_transaction_id', true);
            $transaction = $this->book->get_transaction($transaction_id);

            $woo_order_id = get_post_meta($post_id, 'mec_order_id', true);

            // Pricing
            $event_tickets = get_post_meta($event_id, 'mec_tickets', true);
            $price_details = $this->book->get_price_details($raw_tickets, $event_id, $event_tickets, $raw_variations, $timestamps, ($woo_order_id ? false : true));

            update_post_meta($post_id, 'mec_price', $price_details['total']);
            if(isset($price_details['payable'])) update_post_meta($post_id, 'mec_payable', $price_details['payable']);

            // Coupon
            $existing_coupon = $transaction['coupon'] ?? NULL;
            $coupon = (isset($_POST['mec_coupon']) ? sanitize_text_field($_POST['mec_coupon']) : $existing_coupon);

            // Update Transaction
            $transaction['event_id'] = $event_id;
            $transaction['tickets'] = $new_attendees;
            $transaction['date'] = $attention_date;
            $transaction['all_dates'] = $all_dates;
            $transaction['other_dates'] = $other_dates;
            $transaction['timestamps'] = $timestamps;
            $transaction['price_details'] = $price_details;
            $transaction['total'] = $price_details['total'];
            $transaction['discount'] = 0;
            $transaction['price'] = $price_details['total'];
            $transaction['payable'] = $price_details['payable'];
            $transaction['coupon'] = NULL;
            $transaction['fields'] = $bfixed_fields;

            $this->book->update_transaction($transaction_id, $transaction);

            update_post_meta($post_id, 'mec_all_dates', $all_dates);
            update_post_meta($post_id, 'mec_other_dates', $other_dates);

            // Apply Coupon
            if($coupon)
            {
                $this->book->coupon_apply($coupon, $transaction_id);

                $transaction = $this->book->get_transaction($transaction_id);

                update_post_meta($post_id, 'mec_price', $transaction['price']);
                if(isset($transaction['payable'])) update_post_meta($post_id, 'mec_payable', $transaction['payable']);

                // A coupon applied
                if(isset($transaction['coupon']))
                {
                    $coupon_id = $this->book->coupon_get_id($transaction['coupon']);
                    if($coupon_id)
                    {
                        wp_set_object_terms($post_id, $coupon_id, 'mec_coupon');
                        update_post_meta($post_id, 'mec_coupon_code', $transaction['coupon']);
                    }
                }
            }

            remove_action('save_post', array($this, 'save_book'), 10); // In order to don't create infinitive loop!

            // Update Post
            wp_update_post(array(
                'ID' => $post_id,
                'post_date' => $date,
                'post_date_gmt' => get_gmt_from_date($date)
            ));
        }

        // Refund
        $refund_status = isset($_POST['refund_status']) ? sanitize_text_field($_POST['refund_status']) : NULL;
        if($refund_status)
        {
            $refunded = true;

            $refund_amount_status = isset($_POST['refund_amount_status']) ? sanitize_text_field($_POST['refund_amount_status']) : NULL;
            if($refund_amount_status)
            {
                // Payment Gateway
                $gateway = get_post_meta($post_id, 'mec_gateway', true);

                $refunded = false;
                if($gateway == 'MEC_gateway_stripe')
                {
                    $refund_amount = isset($_POST['refund_amount']) ? sanitize_text_field($_POST['refund_amount']) : '';

                    $stripe = new MEC_gateway_stripe();
                    $refunded = $stripe->refund($post_id, $refund_amount);
                }
            }

            // Reject the Booking Automatically
            if($refunded)
            {
                update_post_meta($post_id, 'mec_refunded', 1);
                update_post_meta($post_id, 'mec_refunded_at', current_time('Y-m-d H:i:s'));

                $_POST['confirmation'] = '-1';
            }
        }

        $new_confirmation = isset($_POST['confirmation']) ? sanitize_text_field($_POST['confirmation']) : NULL;
        $new_verification = isset($_POST['verification']) ? sanitize_text_field($_POST['verification']) : NULL;

        $confirmed = get_post_meta($post_id, 'mec_confirmed', true);
        $verified = get_post_meta($post_id, 'mec_verified', true);

        $resend_confirmation_email = isset($_POST['resend_confirmation_email']) ? sanitize_text_field($_POST['resend_confirmation_email']) : NULL;
        $resend_verification_email = isset($_POST['resend_verification_email']) ? sanitize_text_field($_POST['resend_verification_email']) : NULL;

        // Change Confirmation Status
        if(!is_null($new_confirmation) and $new_confirmation != $confirmed)
        {
            switch($new_confirmation)
            {
                case '1':

                    $this->book->confirm($post_id);
                    $resend_confirmation_email = false;

                    break;

                case '-1':

                    $this->book->reject($post_id);
                    break;

                default:

                    $this->book->pending($post_id);
                    break;
            }
        }

        // Change Verification Status
        if(!is_null($new_verification) and $new_verification != $verified)
        {
            switch($new_verification)
            {
                case '1':

                    $this->book->verify($post_id);
                    $resend_verification_email = false;

                    break;

                case '-1':

                    $this->book->cancel($post_id);
                    break;

                default:

                    $this->book->waiting($post_id);
                    break;
            }
        }

        // MEC Notifications
        $notifications = $this->getNotifications();

        // Resend Confirmation Email
        if($resend_confirmation_email) $notifications->booking_confirmation($post_id, 'manually');

        // Resend Verification Email
        if($resend_verification_email) $notifications->email_verification($post_id, 'manually');

        do_action('mec_booking_saved_and_process_completed', $post_id);
    }

    /**
     * Process book steps from book form in frontend
     * @author Webnus <info@webnus.net>
     */
    public function book()
    {
        $event_id = sanitize_text_field($_REQUEST['event_id']);
        $translated_event_id = (isset($_REQUEST['translated_event_id']) ? sanitize_text_field($_REQUEST['translated_event_id']) : 0);
        $step_skipped = (isset($_REQUEST['do_skip']) ? sanitize_text_field($_REQUEST['do_skip']) : 0);

        if(isset($_FILES['book']))
        {
            if(!function_exists('wp_handle_upload')) require_once(ABSPATH . 'wp-admin/includes/file.php');

            $counter = 0;
            $attachments = [];
            $files = $_FILES['book'];

            foreach($files['name'] as $key => $value)
            {
                foreach($value as $vid => $data)
                {
                    foreach($files['name'][$key][$vid]['reg'] as $id => $reg)
                    {
                        if(!empty($files['name'][$key][$vid]['reg'][$id]))
                        {
                            $file = [
                                'name'     => $this->main->random_string_generator(16).'-'.$files['name'][$key][$vid]['reg'][$id],
                                'type'     => $files['type'][$key][$vid]['reg'][$id],
                                'tmp_name' => $files['tmp_name'][$key][$vid]['reg'][$id],
                                'error'    => $files['error'][$key][$vid]['reg'][$id],
                                'size'     => $files['size'][$key][$vid]['reg'][$id]
                            ];

                            $maxFileSize = isset($this->settings['upload_field_max_upload_size']) && $this->settings['upload_field_max_upload_size'] ? $this->settings['upload_field_max_upload_size'] * 1048576 : wp_max_upload_size();
                            if($file['error'] || $file['size'] > $maxFileSize)
                            {
                                $this->main->response(array('success'=>0, 'message'=> '"'.$files['name'][$key][1]['reg'][$id] .'"<br />'.esc_html__('Uploaded file size exceeds the maximum allowed size.', 'mec')));
                                die();
                            }

                            $ex_file         = explode(".", $file['name']);
                            $extensions     = isset($this->settings['upload_field_mime_types']) && $this->settings['upload_field_mime_types'] ? explode(',', $this->settings['upload_field_mime_types']): ['jpeg','jpg','png','pdf'];
                            $file_extension  = count($ex_file) >= 2 ? end($ex_file) : '';
                            $has_valid_type = false;

                            foreach($extensions as $extension)
                            {
                                if($extension == $file_extension)
                                {
                                    $has_valid_type = true;
                                    break;
                                }
                            }

                            if(!$has_valid_type)
                            {
                                $this->main->response(array('success'=>0, 'message'=> '"'.$files['name'][$key][$vid]['reg'][$id] .'"<br />'.esc_html__('Uploaded file type is not supported.', 'mec')));
                                die();
                            }

                            $uploaded_file = wp_handle_upload($file, array('test_form' => false));
                            if($uploaded_file && !isset($uploaded_file['error']))
                            {
                                $attachment = array('guid' => $uploaded_file['url'], 'post_mime_type' => $uploaded_file['type'], 'post_title' => preg_replace('/\\.[^.]+$/', '', basename($file['name'])), 'post_content' => '', 'post_status' => 'inherit');

                                // Adds file as attachment to WordPress
                                $attachment_id = wp_insert_attachment($attachment, $uploaded_file['file']);
                                if(!is_wp_error($attachment_id)) wp_update_attachment_metadata($attachment_id, wp_generate_attachment_metadata($attachment_id, $uploaded_file['file']));

                                $attachments[$counter]['MEC_TYPE_OF_DATA'] = "attachment";
                                $attachments[$counter]['response'] = "SUCCESS";
                                $attachments[$counter]['filename'] = basename( $uploaded_file['url'] );
                                $attachments[$counter]['url'] = $uploaded_file['url'];
                                $attachments[$counter]['type'] = $uploaded_file['type'];
                                $attachments[$counter]['attachment_id'] = $attachment_id;
                            }

                            $counter++;
                        }
                    }
                }
            }
        }

        $step = sanitize_text_field($_REQUEST['step']);
        if(!is_numeric($step) || ($step < 1 || $step > 4)) $this->main->response(array('success'=>0, 'message'=>__('Invalid Request.', 'mec'), 'code'=>'INVALID_REQUEST'));

        $book = $this->main->sanitize_deep_array($_REQUEST['book']);
        $date = $book['date'] ?? NULL;
        $tickets = $book['tickets'] ?? NULL;
        $uniqueid = isset($_REQUEST['uniqueid']) ? sanitize_text_field($_REQUEST['uniqueid']) : $event_id;

        $all_dates = [];
        $other_dates = [];
        $timestamps = is_array($date) ? $date : array($date);

        // Multiple Date Booking System
        if(is_array($date))
        {
            $all_dates = $date;
            $other_dates = $date;
            $date = array_shift($other_dates);
        }

        if(is_null($date) or trim($date) == '' or is_null($tickets)) $this->main->response(array('success'=>0, 'message'=>__('Please select a date first.', 'mec'), 'code'=>'INVALID_REQUEST'));

        list($start_timestamp, $end_timestamp) = explode(':', $date);

        // Validation on Booking Time
        if(!$this->db->select("SELECT `id` FROM `#__mec_dates` WHERE `post_id`='".$event_id."' AND `tstart`='".$start_timestamp."' AND `tend`='".$end_timestamp."'", 'loadResult')) $this->main->response(array('success'=>0, 'message'=>__('Selected date is not valid.', 'mec'), 'code'=>'INVALID_REQUEST'));

        // Booking of an ongoing event is not permitted
        if($start_timestamp <= current_time('timestamp') and (!isset($this->settings['booking_ongoing']) or (isset($this->settings['booking_ongoing']) and !$this->settings['booking_ongoing']))) $this->main->response(array('success'=>0, 'message'=>__('The event has started and you cannot book it.', 'mec'), 'code'=>'INVALID_REQUEST'));

        // Render library
        $render = $this->getRender();
        $rendered = $render->data($event_id, '');

        $event = new stdClass();
        $event->ID = $event_id;
        $event->requested_id = $event_id;
        $event->data = $rendered;

        // Set some data from original event in multilingual websites
        if($translated_event_id and $event_id != $translated_event_id)
        {
            $event->requested_id = $translated_event_id;

            $translated_tickets = get_post_meta($translated_event_id, 'mec_tickets', true);
            if(!is_array($translated_tickets)) $translated_tickets = [];

            foreach($translated_tickets as $ticket_id=>$translated_ticket)
            {
                if(!isset($event->data->tickets[$ticket_id])) continue;

                $event->data->tickets[$ticket_id]['name'] = $translated_ticket['name'];
                $event->data->tickets[$ticket_id]['description'] = $translated_ticket['description'];
                $event->data->tickets[$ticket_id]['price_label'] = $translated_ticket['price_label'];
            }
        }

        // Next Booking step
        $response_data = [];

        // User Booking Limits
        list($limit, $unlimited) = $this->book->get_user_booking_limit($event_id);

        // Minimum Tickets Per Booking
        $minimum_ticket_per_booking = $this->book->get_minimum_tickets_per_booking($event_id);

        switch($step)
        {
            case '1':

                $total_tickets = 0;
                $has_ticket = false;
                $tickets_info = get_post_meta($event_id, 'mec_tickets', true);

                foreach($tickets as $key => $ticket)
                {
                    if($ticket > 0)
                    {
                        $total_tickets += $ticket;

                        $has_ticket = true;
                        $ticket_name = (isset($tickets_info[$key]['name']) and trim($tickets_info[$key]['name'])) ? trim($tickets_info[$key]['name']) : '';

                        $minimum_ticket = (isset($tickets_info[$key]['minimum_ticket']) and intval($tickets_info[$key]['minimum_ticket']) > 0) ? intval($tickets_info[$key]['minimum_ticket']) : 0;
                        $maximum_ticket = (isset($tickets_info[$key]['maximum_ticket']) and intval($tickets_info[$key]['maximum_ticket']) > 0) ? intval($tickets_info[$key]['maximum_ticket']) : 0;

                        if($maximum_ticket > 0) $minimum_ticket = min($minimum_ticket, $maximum_ticket);
                        if($maximum_ticket > 0 and $minimum_ticket > 0) $maximum_ticket = max($minimum_ticket, $maximum_ticket);

                        if((int) $ticket < (int) $minimum_ticket) $this->main->response(array('success'=>0, 'message'=>sprintf(esc_html__('To book %s ticket you should book at-least %s ones!', 'mec'), '<strong>'.esc_html($ticket_name).'</strong>', esc_html($minimum_ticket)), 'code'=>'MINIMUM_INVALID'));
                        if($maximum_ticket > 0 and (int) $ticket > $maximum_ticket) $this->main->response(array('success'=>0, 'message'=>sprintf(esc_html__('To book %s ticket you should book maximum %s ones!', 'mec'), '<strong>'.esc_html($ticket_name).'</strong>', esc_html($maximum_ticket)), 'code'=>'MAXIMUM_INVALID'));
                    }
                }

                // Minimum Tickets Per Booking
                if($total_tickets < $minimum_ticket_per_booking) $this->main->response(array('success'=>0, 'message'=>sprintf(esc_html__('You should book at-least %s tickets. You booked %s ones.', 'mec'), '<strong>'.esc_html($minimum_ticket_per_booking).'</strong>', '<strong>'.esc_html($total_tickets).'</strong>'), 'code'=>'MINIMUM_INVALID'));

                $ip_restriction = !isset($this->settings['booking_ip_restriction']) || $this->settings['booking_ip_restriction'];
                if($ip_restriction and !$unlimited)
                {
                    if(count($all_dates)) $total_tickets *= count($all_dates);
                    $permitted_by_ip_info = $this->main->booking_permitted_by_ip($event_id, $limit, array('date' => explode(':', $date)[0], 'count'=> $total_tickets));

                    if($permitted_by_ip_info['permission'] === false)
                    {
                        $this->main->response(array('success'=>0, 'message'=>sprintf($this->main->m('booking_restriction_message3', esc_html__("Maximum allowed number of tickets that you can book is %s.", 'mec')), $limit), 'code'=>'LIMIT_REACHED'));
                        return;
                    }
                }

                if(!$has_ticket) $this->main->response(array('success'=>0, 'message'=>__('Please select tickets!', 'mec'), 'code'=>'NO_TICKET'));

                // Validate Captcha
                if($this->getCaptcha()->status('booking') and !$this->getCaptcha()->is_valid())
                {
                    $this->main->response(array('success'=>0, 'message'=>__('Captcha is invalid. Please try again.', 'mec'), 'code'=>'CAPTCHA_IS_INVALID'));
                }

                do_action('mec_validate_booking_form_step_1', $event_id, $tickets, $all_dates, $date);

                $next_step = 'form';

                // WC System
                $WC_status = (isset($this->settings['wc_status']) and $this->settings['wc_status'] and class_exists('WooCommerce'));
                $WC_booking_form = (isset($this->settings['wc_booking_form']) and $this->settings['wc_booking_form']);

                if($WC_status and !$WC_booking_form)
                {
                    $wc = $this->getWC();
                    $next = $wc->cart($event_id, $date, $other_dates, $tickets)->next();

                    $this->main->response(array('success'=>1, 'output'=>'', 'data'=>array('next' => $next)));
                }

                break;

            case '2':

                $raw_tickets = [];
                $raw_variations = [];
                $validated_tickets = [];

                // Apply first attendee information for all attendees
                $first_for_all = isset($book['first_for_all']) ? (int) $book['first_for_all'] : 0;
                $booking_unique_emails = isset($this->settings['booking_unique_emails']) && $this->settings['booking_unique_emails'];

                if($first_for_all)
                {
                    $first_attendee = NULL;

                    $rendered_tickets = [];
                    foreach($tickets as $ticket)
                    {
                        // Find first ticket
                        if(is_null($first_attendee)) $first_attendee = $ticket;

                        $ticket['name'] = strip_tags($first_attendee['name']);
                        $ticket['email'] = $first_attendee['email'];
                        $ticket['reg'] = $first_attendee['reg'] ?? '';
                        $ticket['variations'] = $first_attendee['variations'] ?? [];

                        $rendered_tickets[] = $ticket;
                    }

                    $tickets = $rendered_tickets;
                }

                $booking_options = get_post_meta($event_id, 'mec_booking', true);
                $attendees_info = [];

                foreach($tickets as $ticket)
                {
                    if(isset($ticket['email']) and (trim($ticket['email']) == '' or !filter_var($ticket['email'], FILTER_VALIDATE_EMAIL))) continue;

                    // Variations Per Ticket
                    if(!isset($raw_variations[$ticket['id']])) $raw_variations[$ticket['id']] = [];

                    // Booking limit attendee
                    if(!$unlimited)
                    {
                        if(!array_key_exists($ticket['email'], $attendees_info)) $attendees_info[$ticket['email']] = array('count' => $ticket['count']);
                        else $attendees_info[$ticket['email']]['count'] = ($attendees_info[$ticket['email']]['count'] + $ticket['count']);
                    }

                    if(!isset($ticket['name']) || trim($ticket['name']) == '') continue;

                    // Remove HTML Tags
                    $ticket['name'] = strip_tags($ticket['name']);

                    if(!isset($raw_tickets[$ticket['id']])) $raw_tickets[$ticket['id']] = 1;
                    else $raw_tickets[$ticket['id']] += 1;

                    if(isset($ticket['variations']) and is_array($ticket['variations']) and count($ticket['variations']))
                    {
                        foreach($ticket['variations'] as $variation_id=>$variation_count)
                        {
                            if(!trim($variation_count)) continue;

                            if(!isset($raw_variations[$ticket['id']][$variation_id])) $raw_variations[$ticket['id']][$variation_id] = $variation_count;
                            else $raw_variations[$ticket['id']][$variation_id] += $variation_count;
                        }
                    }

                    $validated_tickets[] = $ticket;
                }

                if(!$unlimited)
                {
                    foreach($attendees_info as $attendee_email => $attendee_info)
                    {
                        if($attendee_info['count'] > $limit)
                        {
                            $this->main->response(array('success'=>0, 'message'=>sprintf($this->main->m('booking_restriction_message1', esc_html__("You selected %s tickets to book but maximum number of tikets per user is %s tickets.", 'mec')), $attendee_info['count'], $limit), 'code'=>'LIMIT_REACHED'));
                            return;
                        }
                        else
                        {
                            $total_tickets = $attendee_info['count'];
                            if(count($all_dates)) $total_tickets *= count($all_dates);

                            $permitted_info = $this->main->booking_permitted($attendee_email, array('event_id' => $event_id, 'date' => explode(':', $date)[0], 'count'=> $total_tickets), $limit);
                            if((is_bool($permitted_info) and !$permitted_info) or (is_array($permitted_info) and $permitted_info['permission'] === false))
                            {
                                $this->main->response(array('success'=>0, 'message'=>sprintf($this->main->m('booking_restriction_message2', esc_html__("You booked %s tickets till now but maximum number of tickets per user is %s tickets.", 'mec')), $permitted_info['booking_count'], $limit), 'code'=>'LIMIT_REACHED'));
                                return;
                            }
                        }
                    }
                }

                $bookings_all_occurrences = ($booking_options['bookings_all_occurrences'] ?? 0);
                $bookings_all_occurrences_multiple = ($booking_options['bookings_all_occurrences_multiple'] ?? 0);
                if($bookings_all_occurrences and !$bookings_all_occurrences_multiple)
                {
                    foreach($validated_tickets as $t)
                    {
                        if(isset($t['email']) and $this->main->is_second_booking($event_id, $t['email']))
                        {
                            $this->main->response(array('success'=>0, 'message'=>sprintf(esc_html__("%s email already booked this event and it's not possible to book it again.", 'mec'), $t['email']), 'code'=>'MULTIPLE_BOOKING'));
                            return;
                        }
                    }
                }

                // Check uniqueness of emails
                if($booking_unique_emails)
                {
                    $unique_emails = [];
                    foreach($validated_tickets as $t)
                    {
                        if(in_array($t['email'], $unique_emails))
                        {
                            $this->main->response(['success'=>0, 'message'=>sprintf(esc_html__("%s email is duplicated. Please use unique emails for all attendees.", 'mec'), $t['email']), 'code'=>'DUPLICATE_EMAIL']);
                            return;
                        }

                        $unique_emails[] = $t['email'];
                    }
                }

                // Attendee form is not filled correctly
                if(count($validated_tickets) != count($tickets)) $this->main->response(array('success'=>0, 'message'=>__('Please fill the form correctly. Email and Name fields are required!', 'mec'), 'code'=>'ATTENDEE_FORM_INVALID'));

                // Username & Password Method
                $booking_userpass = ((isset($this->settings['booking_userpass']) and trim($this->settings['booking_userpass'])) ? $this->settings['booking_userpass'] : 'auto');
                $booking_registration = !isset($this->settings['booking_registration']) || $this->settings['booking_registration'];

                // Valid Username & Password are Required
                if($booking_registration and $booking_userpass == 'manual' and !is_user_logged_in())
                {
                    $username = isset($book['username']) ? sanitize_text_field(trim($book['username'])) : '';
                    $password = isset($book['password']) ? sanitize_text_field($book['password']) : '';

                    if(strlen($password) < 8) $this->main->response(array('success'=>0, 'message'=>__('Password should be at-least 8 characters!', 'mec'), 'code'=>'PASSWORD_TOO_SHORT'));
                    if(strlen($username) < 6 or strlen($username) > 20) $this->main->response(array('success'=>0, 'message'=>__('Username should be between 6 and 20 characters!', 'mec'), 'code'=>'USERNAME_INVALID_SIZE'));
                    if(!preg_match('/^\w{6,}$/', $username)) $this->main->response(array('success'=>0, 'message'=>__('Only alphabetical characters including numbers and underscore are allowed in username.', 'mec'), 'code'=>'USERNAME_INVALID_CHARS'));

                    if(username_exists($username)) $this->main->response(array('success'=>0, 'message'=>__('Selected username already exists so please insert another one.', 'mec'), 'code'=>'USERNAME_EXISTS'));
                }

                // Attachments
                if(isset($attachments)) $validated_tickets['attachments'] = $attachments;

                // WC System
                $WC_status = (isset($this->settings['wc_status']) and $this->settings['wc_status'] and class_exists('WooCommerce'));

                // MEC Cart
                $mec_cart = (isset($this->settings['mec_cart_status']) and $this->settings['mec_cart_status']);
                if($mec_cart) $WC_status = false;

                // Tickets
                $event_tickets = $event->data->tickets ?? [];

                // Calculate price of bookings
                $price_details = $this->book->get_price_details($raw_tickets, $event_id, $event_tickets, $raw_variations, $timestamps, (!$WC_status));

                $book['date'] = $event_id;
                $book['date'] = $date;
                $book['all_dates'] = $all_dates;
                $book['other_dates'] = $other_dates;
                $book['timestamps'] = $timestamps;
                $book['tickets'] = $validated_tickets;
                $book['price_details'] = $price_details;
                $book['total'] = $price_details['total'];
                $book['discount'] = 0;
                $book['price'] = $price_details['total'];
                $book['payable'] = $price_details['payable'];
                $book['coupon'] = NULL;

                // Attachments
                if(isset($attachments)) $book['attachments'] = $attachments;

                do_action('mec_validate_booking_form_step_2', $book);

                $next_step = 'checkout';
                $transactionObject = new \MEC\Transactions\Transaction(0, $book);
                $transaction_id = $transactionObject->update_data();

                // WooCommerce System
                if($WC_status)
                {
                    $wc = $this->getWC();
                    $next = $wc->cart($event_id, $date, $other_dates, $tickets, $transaction_id)->next();

                    $this->main->response(array('success'=>1, 'output'=>'', 'data'=>array('next' => $next)));
                }

                // MEC Cart
                if($mec_cart)
                {
                    $cart = $this->getCart();
                    $next = $cart->add($transaction_id)->next();

                    $this->main->response(array('success'=>1, 'output'=>'', 'data'=>array('next' => $next)));
                }

                // the booking is free
                $use_free_gateway = apply_filters('mec_use_free_gateway', true);
                $skip_payment_step = (!isset($this->settings['skip_payment_step_for_free_bookings']) or (isset($this->settings['skip_payment_step_for_free_bookings']) and $this->settings['skip_payment_step_for_free_bookings']));

                $check_free_tickets_booking = apply_filters('check_free_tickets_booking', 1);
                if($price_details['total'] == 0 && $skip_payment_step && $use_free_gateway === true && $check_free_tickets_booking)
                {
                    $free_gateway = new MEC_gateway_free();
                    $response_data = $free_gateway->do_transaction($transaction_id);

                    $next_step = 'message';
                    $message = $response_data['message'];

                    $thankyou_page_id = $this->main->get_thankyou_page_id($event_id);
                    if($thankyou_page_id) $response_data['redirect_to'] = $this->book->get_thankyou_page($thankyou_page_id, $transaction_id);
                }

                break;

            case '3':

                $next_step = 'payment';
                break;

            case '4':

                $next_step = 'notifications';
                break;

            default:

                $next_step = 'form';
                break;
        }

        $display_progress_bar = $this->main->can_display_booking_progress_bar($this->settings);

        $path = MEC::import('app.modules.booking.steps.'.$next_step, true, true);

        $filtered_path = apply_filters('mec_get_module_booking_step_path', $next_step, $this->settings);
        if($filtered_path != $next_step and file_exists($filtered_path)) $path = $filtered_path;

        ob_start();
        include $path;
        $output = ob_get_clean();

        $this->main->response(array('success'=>1, 'output'=>$output, 'data'=>$response_data));
    }

    public function tickets_availability()
    {
        $event_id = isset($_REQUEST['event_id']) ? sanitize_text_field($_REQUEST['event_id']) : '';
        $date = isset($_REQUEST['date']) ? sanitize_text_field($_REQUEST['date']) : '';

        $ex = explode(':', $date);
        $date = $ex[0];

        $availability = $this->book->get_tickets_availability($event_id, $date);
        $prices = $this->book->get_tickets_prices($event_id, current_time('Y-m-d'), 'price_label', $date);

        if(is_plugin_active('mec-waiting-list/mec-waiting-list.php')){
            $this->main->response(array('success'=>1, 'availability'=>$availability, 'prices'=>$prices, 'active_mec_waiting'=>true));
        }else{
            $this->main->response(array('success'=>1, 'availability'=>$availability, 'prices'=>$prices));
        }

    }

    public function tickets_availability_multiple()
    {
        $event_id = isset($_REQUEST['event_id']) ? sanitize_text_field($_REQUEST['event_id']) : '';
        $dates = (isset($_REQUEST['date']) and is_array($_REQUEST['date']) and count($_REQUEST['date'])) ? array_map('sanitize_text_field', wp_unslash($_REQUEST['date'])) : [];

        $availability = $this->book->get_tickets_availability_multiple($event_id, $dates);

        $prices = $this->book->get_tickets_prices($event_id, current_time('Y-m-d'), 'price_label');
        if(count($dates) === 1) $prices = $this->book->get_tickets_prices($event_id, current_time('Y-m-d'), 'price_label', $dates[0]);

        $this->main->response(array('success'=>1, 'availability'=>$availability, 'prices'=>$prices));
    }

    public function bbf_date_tickets_booking_form()
    {
        $event_id = isset($_REQUEST['event_id']) ? sanitize_text_field($_REQUEST['event_id']) : '';
        $num_attendees = isset($_REQUEST['num_attendees']) ? (int) sanitize_text_field($_REQUEST['num_attendees']) : 1;

        // Event is invalid!
        if(!trim($event_id)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('Event is invalid. Please select an event.', 'mec').'</div>'));

        // Invalid Number of Attendees
        if($num_attendees < 1) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('You should select at-least one attendee.', 'mec').'</div>'));

        $tickets = get_post_meta($event_id, 'mec_tickets', true);

        $render = $this->getRender();

        $maximum_dates = 10;
        if(isset($this->settings['booking_maximum_dates']) and trim($this->settings['booking_maximum_dates'])) $maximum_dates = $this->settings['booking_maximum_dates'];

        $start = current_time('Y-m-d');

        $ongoing_event_book = isset($this->settings['booking_ongoing']) && $this->settings['booking_ongoing'] == '1';
        if($ongoing_event_book) $start = date('Y-m-d', strtotime('Yesterday'));

        $dates = $render->dates($event_id, NULL, $maximum_dates, $start);

        // Invalid Event, Tickets or Dates
        if(!is_array($tickets) || !count($tickets) || !is_array($dates) || !count($dates)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('No ticket or future date found for this event! Please try another event.', 'mec').'</div>'));

        $output = '<div class="mec-form-row"><div class="mec-col-2"><label for="mec_book_form_date">'.esc_html__('Date', 'mec').'</label></div>';
        $output .= '<div class="mec-col-6" id="mec_bbf_dates_wrapper">
            '.$this->bbf_load_dates([
                'event_id' => $event_id,
                'start' => $start,
                'type' => 'next',
                'dates' => $dates,
            ]).'
        </div></div>';

        // Coupon
        $output .= '<div class="mec-form-row"><div class="mec-col-2"><label for="mec_book_form_coupon">'.esc_html__('Coupon', 'mec').'</label></div>';
        $output .= '<div class="mec-col-6"><input class="widefat" type="text" name="mec_coupon" id="mec_book_form_coupon" /></div></div>';

        // Booking Form
        $bfixed_fields = $this->main->get_bfixed_fields($event_id);
        if(is_array($bfixed_fields) and isset($bfixed_fields[':i:'])) unset($bfixed_fields[':i:']);
        if(is_array($bfixed_fields) and isset($bfixed_fields[':fi:'])) unset($bfixed_fields[':fi:']);

        $booking_bfixed_options = '';
        if(count($bfixed_fields))
        {
            $output .= '<h3>'.sprintf(esc_html__('%s Fields', 'mec'), $this->main->m('booking', esc_html__('Booking', 'mec'))).'</h3>';
            foreach($bfixed_fields as $bfixed_field_id=>$bfixed_field)
            {
                if(!is_numeric($bfixed_field_id) or !isset($bfixed_field['type'])) continue;

                $booking_bfixed_options .= '<div class="mec-form-row">';

                if(isset($bfixed_field['label']) and $bfixed_field['type'] != 'agreement') $booking_bfixed_options .= '<div class="mec-col-2"><label for="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'">'.esc_html__($bfixed_field['label'], 'mec').'</label></div>';
                elseif(isset($bfixed_field['label']) and $bfixed_field['type'] == 'agreement') $booking_bfixed_options .= '<div class="mec-col-2"></div>';

                $booking_bfixed_options .= '<div class="mec-col-6">';
                $mandatory = (isset($bfixed_field['mandatory']) and $bfixed_field['mandatory']);

                if($bfixed_field['type'] == 'text')
                {
                    $booking_bfixed_options .= '<input class="widefat" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'" type="text" name="mec_fields['.esc_attr($bfixed_field_id).']" value="" placeholder="'.esc_html__($bfixed_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
                }
                elseif($bfixed_field['type'] == 'date')
                {
                    $booking_bfixed_options .= '<input class="widefat" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'" type="date" name="mec_fields['.esc_attr($bfixed_field_id).']" value="" placeholder="'.esc_html__($bfixed_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' min="'.esc_attr(date_i18n('Y-m-d', strtotime('-100 years'))).'" max="'.esc_attr(date_i18n('Y-m-d', strtotime('+100 years'))).'" />';
                }
                elseif($bfixed_field['type'] == 'email')
                {
                    $booking_bfixed_options .= '<input class="widefat" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'" type="email" name="mec_fields['.esc_attr($bfixed_field_id).']" value="" placeholder="'.esc_html__($bfixed_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
                }
                elseif($bfixed_field['type'] == 'tel')
                {
                    $booking_bfixed_options .= '<input class="widefat" oninput="this.value=this.value.replace(/(?![0-9])./gmi,"")" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'" type="tel" name="mec_fields['.esc_attr($bfixed_field_id).']" value="" placeholder="'.esc_html__($bfixed_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
                }
                elseif($bfixed_field['type'] == 'textarea')
                {
                    $booking_bfixed_options .= '<textarea class="widefat" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'" name="mec_fields['.esc_attr($bfixed_field_id).']" placeholder="'.esc_html__($bfixed_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'></textarea>';
                }
                elseif($bfixed_field['type'] == 'select')
                {
                    $booking_bfixed_options .= '<select class="widefat" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'" name="mec_fields['.esc_attr($bfixed_field_id).']" placeholder="'.esc_html__($bfixed_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'>';
                    foreach($bfixed_field['options'] as $reg_field_option) $booking_bfixed_options .= '<option value="'.esc_attr__($reg_field_option['label'], 'mec').'">'.esc_html__($reg_field_option['label'], 'mec').'</option>';
                    $booking_bfixed_options .= '</select>';
                }
                elseif($bfixed_field['type'] == 'radio')
                {
                    foreach($bfixed_field['options'] as $bfixed_field_option)
                    {
                        $booking_bfixed_options .= '<label for="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label'])).'">
                            <input type="radio" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label'])).'" name="mec_fields['.esc_attr($bfixed_field_id).']" value="'.esc_html__($bfixed_field_option['label'], 'mec').'" />
                            '.esc_html__($bfixed_field_option['label'], 'mec').'
                        </label>';
                    }
                }
                elseif($bfixed_field['type'] == 'checkbox')
                {
                    foreach($bfixed_field['options'] as $bfixed_field_option)
                    {
                        $booking_bfixed_options .= '<label for="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label'])).'">
                            <input type="checkbox" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'_'.strtolower(str_replace(' ', '_', $bfixed_field_option['label'])).'" name="mec_fields['.esc_attr($bfixed_field_id).'][]" value="'.esc_html__($bfixed_field_option['label'], 'mec').'" />
                            '.esc_html__($bfixed_field_option['label'], 'mec').'
                        </label>';
                    }
                }
                elseif($bfixed_field['type'] == 'agreement')
                {
                    $booking_bfixed_options .= '<label for="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'">
                        <input type="checkbox" id="mec_book_bfixed_field_reg'.esc_attr($bfixed_field_id).'" name="mec_fields['.esc_attr($bfixed_field_id).']" value="1" '.((!isset($bfixed_field['status']) or (isset($bfixed_field['status']) and $bfixed_field['status'] == 'checked')) ? 'checked="checked"' : '').' '.($mandatory ? 'required="required"' : '').' />
                        '.sprintf(esc_html__($bfixed_field['label'], 'mec'), '<a href="'.get_the_permalink($bfixed_field['page']).'" target="_blank">'.get_the_title($bfixed_field['page']).'</a>').'
                    </label>';
                }

                $booking_bfixed_options .= '</div>';
                $booking_bfixed_options .= '</div>';
            }

            $output .= $booking_bfixed_options;
        }

        // Booking Form
        $reg_fields = $this->main->get_reg_fields($event_id);
        if(is_array($reg_fields) and isset($reg_fields[':i:'])) unset($reg_fields[':i:']);
        if(is_array($reg_fields) and isset($reg_fields[':fi:'])) unset($reg_fields[':fi:']);

        $mec_email = false;
        $mec_name = false;
        foreach($reg_fields as $field)
        {
            if(isset($field['type']))
            {
                if($field['type'] == 'mec_email') $mec_email = true;
                if($field['type'] == 'name') $mec_name = true;
            }
        }

        if(!$mec_name)
        {
            $reg_fields[] = array(
                'mandatory' => '0',
                'type'      => 'name',
                'label'     => esc_html__( 'Name', 'mec'),
            );
        }

        if(!$mec_email)
        {
            $reg_fields[] = array(
                'mandatory' => '0',
                'type'      => 'mec_email',
                'label'     => esc_html__( 'Email', 'mec'),
            );
        }

        $booking_form_options = '';

        for($attendee_id = 0; $attendee_id < $num_attendees; $attendee_id++)
        {
            // Ticket option
            $ticket_options = '';
            foreach($tickets as $ticket_id => $ticket) $ticket_options .= '<option value="'.esc_attr($ticket_id).'">'.esc_html($ticket['name']).'</option>';

            $booking_form_options .= '<div class="mec-form-row" style="padding-bottom: 5px;"><div class="mec-col-2"><label for="mec_attendee_'.esc_attr($attendee_id).'_ticket">'.esc_html__('Ticket', 'mec').'</label></div>';
            $booking_form_options .= '<div class="mec-col-6"><select class="widefat mec-booking-edit-form-tickets" name="mec_attendee['.esc_attr($attendee_id).'][id]" id="mec_attendee_'.esc_attr($attendee_id).'_ticket" onchange="mec_edit_booking_ticket_changed(this.value, \''.esc_attr($attendee_id).'\');">'.$ticket_options.'</select></div></div>';

            if(count($reg_fields))
            {
                foreach($reg_fields as $reg_field_id=>$reg_field)
                {
                    if(!is_numeric($reg_field_id) or !isset($reg_field['type'])) continue;
                    if($reg_field['type'] == 'file') continue;

                    $booking_form_options .= '<div class="mec-form-row" style="padding-bottom: 5px;">';

                    if(isset($reg_field['label']) and $reg_field['type'] != 'agreement') $booking_form_options .= '<div class="mec-col-2"><label for="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'">'.esc_html__($reg_field['label'], 'mec').'</label></div>';
                    elseif(isset($reg_field['label']) and $reg_field['type'] == 'agreement') $booking_form_options .= '<div class="mec-col-2"></div>';

                    $booking_form_options .= '<div class="mec-col-6">';
                    $mandatory = (isset($reg_field['mandatory']) and $reg_field['mandatory']);

                    if($reg_field['type'] == 'name')
                    {
                        $booking_form_options .= '<input class="widefat" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" type="text" name="mec_attendee['.esc_attr($attendee_id).'][name]" value="" placeholder="'.esc_html__('Name', 'mec').'" required="required" />';
                    }
                    elseif($reg_field['type'] == 'mec_email')
                    {
                        $booking_form_options .= '<input class="widefat" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" type="email" name="mec_attendee['.esc_attr($attendee_id).'][email]" value="" placeholder="'.esc_html__('Email', 'mec').'" required="required" />';
                    }
                    elseif($reg_field['type'] == 'text')
                    {
                        $booking_form_options .= '<input class="widefat" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" type="text" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
                    }
                    elseif($reg_field['type'] == 'date')
                    {
                        $booking_form_options .= '<input class="widefat" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" type="date" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' min="'.esc_attr(date_i18n('Y-m-d', strtotime('-100 years'))).'" max="'.esc_attr(date_i18n('Y-m-d', strtotime('+100 years'))).'" />';
                    }
                    elseif($reg_field['type'] == 'email')
                    {
                        $booking_form_options .= '<input class="widefat" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" type="email" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
                    }
                    elseif ($reg_field['type'] == 'tel')
                    {
                        $booking_form_options .= '<input class="widefat" oninput="this.value=this.value.replace(/(?![0-9])./gmi,"")" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" type="tel" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
                    }
                    elseif($reg_field['type'] == 'textarea')
                    {
                        $booking_form_options .= '<textarea class="widefat" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'></textarea>';
                    }
                    elseif($reg_field['type'] == 'p')
                    {
                        $booking_form_options .= '<p>'.esc_html__($reg_field['content'], 'mec').'</p>';
                    }
                    elseif($reg_field['type'] == 'select')
                    {
                        $booking_form_options .= '<select class="widefat" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'>';
                        foreach($reg_field['options'] as $reg_field_option) $booking_form_options .= '<option value="'.esc_attr__($reg_field_option['label'], 'mec').'">'.esc_html__($reg_field_option['label'], 'mec').'</option>';
                        $booking_form_options .= '</select>';
                    }
                    elseif($reg_field['type'] == 'radio')
                    {
                        foreach($reg_field['options'] as $reg_field_option)
                        {
                            $booking_form_options .= '<label for="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'">
                                <input type="radio" id="mec_book_reg_field_reg'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" value="'.esc_html__($reg_field_option['label'], 'mec').'" />
                                '.esc_html__($reg_field_option['label'], 'mec').'
                            </label>';
                        }
                    }
                    elseif($reg_field['type'] == 'checkbox')
                    {
                        foreach($reg_field['options'] as $reg_field_option)
                        {
                            $booking_form_options .= '<label for="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'">
                                <input type="checkbox" id="mec_book_reg_field_reg'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).'][]" value="'.esc_html__($reg_field_option['label'], 'mec').'" />
                                '.esc_html__($reg_field_option['label'], 'mec').'
                            </label>';
                        }
                    }
                    elseif($reg_field['type'] == 'agreement')
                    {
                        $booking_form_options .= '<label for="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'">
                            <input type="checkbox" id="mec_book_'.esc_attr($attendee_id).'_reg_field_reg'.esc_attr($reg_field_id).'" name="mec_attendee['.esc_attr($attendee_id).'][reg]['.esc_attr($reg_field_id).']" value="1" '.((!isset($reg_field['status']) or (isset($reg_field['status']) and $reg_field['status'] == 'checked')) ? 'checked="checked"' : '').' '.($mandatory ? 'required="required"' : '').' />
                            '.sprintf(esc_html__($reg_field['label'], 'mec'), '<a href="'.get_the_permalink($reg_field['page']).'" target="_blank">'.get_the_title($reg_field['page']).'</a>').'
                        </label>';
                    }

                    $booking_form_options .= '</div>';
                    $booking_form_options .= '</div>';
                }
            }

            // Ticket Variations
            $ticket_variations = $this->main->ticket_variations($event_id);

            if(isset($this->settings['ticket_variations_status']) and $this->settings['ticket_variations_status'] and count($ticket_variations))
            {
                $booking_form_options .= '<div class="mec-book-ticket-variations" id="mec_book_ticket_variations_'.esc_attr($attendee_id).'" data-key="'.esc_attr($attendee_id).'">';
                foreach($ticket_variations as $ticket_variation_id=>$ticket_variation)
                {
                    if(!is_numeric($ticket_variation_id) or !isset($ticket_variation['title']) or (isset($ticket_variation['title']) and !trim($ticket_variation['title']))) continue;

                    $booking_form_options .= '<div class="mec-form-row" style="padding-bottom: 5px;">
                        <div class="mec-col-2">
                            <label for="mec_att_'.esc_attr($attendee_id).'_variations_'.esc_attr($ticket_variation_id).'" class="mec-ticket-variation-name">'.esc_html($ticket_variation['title']).'</label>
                        </div>
                        <div class="mec-col-6">
                            <input id="mec_att_'.esc_attr($attendee_id).'_variations_'.esc_attr($ticket_variation_id).'" type="number" min="0" max="'.((is_numeric($ticket_variation['max']) and $ticket_variation['max']) ? $ticket_variation['max'] : 1000).'" name="mec_attendee['.esc_attr($attendee_id).'][variations]['.esc_attr($ticket_variation_id).']" value="0">
                        </div>
                    </div>';
                }

                $booking_form_options .= '</div>';
            }

            if(($num_attendees - 1) > $attendee_id) $booking_form_options .= '<hr>';
        }

        $output .= '<h3>'.esc_html__('Attendees', 'mec').'</h3>';
        $output .= MEC_kses::form($booking_form_options);

        $response = apply_filters(
            'mec_bbf_add_event_options_response',
            array(
                'success' => 1,
                'output' => $output,
            ),
            $event_id,
            $num_attendees,
            $tickets,
            $dates
        );

        $this->main->response($response);
    }

    public function bbf_load_dates($args = [])
    {
        $event_id = isset($args['event_id']) ? sanitize_text_field($args['event_id']) : $_REQUEST['event_id'] ?? '';
        $start = isset($args['start']) ? sanitize_text_field($args['start']) : $_REQUEST['start'] ?? '';
        $type = isset($args['type']) ? sanitize_text_field($args['type']) : $_REQUEST['type'] ?? '';
        $dates = $args['dates'] ?? [];

        if(is_numeric($start)) $start = date('Y-m-d', $start);

        $maximum_dates = 10;
        if(isset($this->settings['booking_maximum_dates']) and trim($this->settings['booking_maximum_dates'])) $maximum_dates = $this->settings['booking_maximum_dates'];

        if($type === 'prev')
        {
            $start = date('Y-m-d', strtotime('-2 Months', strtotime($start)));
            $maximum_dates = max($maximum_dates, 60);
        }

        if(!count($dates))
        {
            // Render Library
            $render = $this->getRender();

            $dates = $render->dates($event_id, NULL, $maximum_dates, $start);
            if(!count($dates))
            {
                $this->main->response([
                    'success' => 0,
                    'output' => '',
                ]);
            }
        }

        // Date Selection Method
        $date_selection = (isset($this->settings['booking_date_selection']) and trim($this->settings['booking_date_selection'])) ? $this->settings['booking_date_selection'] : 'dropdown';

        $date_format = (isset($this->ml_settings['booking_date_format1']) and trim($this->ml_settings['booking_date_format1'])) ? $this->ml_settings['booking_date_format1'] : 'Y-m-d';

        $repeat_type = get_post_meta($event_id, 'mec_repeat_type', true);
        if($repeat_type === 'custom_days') $date_format .= ' '.get_option('time_format');

        // Date Options
        $date_options = '';
        $first_date = current_time('timestamp');
        $last_date = '';

        if(strtotime($start) < $first_date) $first_date = strtotime($start);

        if($date_selection === 'checkboxes')
        {
            foreach($dates as $date)
            {
                $date_options .= '<li><label><input type="checkbox" value="'.esc_attr($this->book->timestamp($date['start'], $date['end'])).'" name="mec_date[]">'.strip_tags($this->main->date_label($date['start'], $date['end'], $date_format, ' - ', false)).'</label></li>';
                $last_date = $date['end']['timestamp'];
            }

            $date_options = '<ul>'.$date_options.'</ul>';
        }
        else
        {
            foreach($dates as $date)
            {
                $date_options .= '<option value="'.esc_attr($this->book->timestamp($date['start'], $date['end'])).'">'.strip_tags($this->main->date_label($date['start'], $date['end'], $date_format, ' - ', false)).'</option>';
                $last_date = $date['end']['timestamp'];
            }

            $date_options = '<select class="widefat" name="mec_date" id="mec_book_form_date">'.$date_options.'</select>';
        }

        $output = '<div class="mec-add-booking-next-prev-dates" style="margin-bottom: 10px;">
                <button type="button" data-start="'.esc_attr($first_date).'" class="button mec-add-booking-prev-dates-button">'.esc_html__('Previous').'</button>
                <button type="button" data-start="'.esc_attr($last_date).'" class="button mec-add-booking-next-dates-button">'.esc_html__('Next').'</button>
            </div>
            '.MEC_kses::form($date_options);

        if(is_array($args) && count($args)) return $output;

        $this->main->response([
            'success' => 1,
            'output' => $output,
        ]);
    }

    public function bbf_event_edit_options()
    {
        $event_id = isset($_REQUEST['event_id']) ? sanitize_text_field($_REQUEST['event_id']) : '';
        $booking_id = isset($_REQUEST['booking_id']) ? sanitize_text_field($_REQUEST['booking_id']) : '';

        // Event is invalid!
        if(!trim($event_id)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('Event is invalid. Please select an event.', 'mec').'</div>'));

        $tickets = get_post_meta($event_id, 'mec_tickets', true);

        $render = $this->getRender();

        $meta = $this->main->get_post_meta($booking_id);

        $first_booked_timestamps = isset($meta['mec_all_dates'], $meta['mec_all_dates'][0]) ? explode(':', $meta['mec_all_dates'][0]) : explode(':', $meta['mec_date']);
        $now = current_time('timestamp');

        $occurrences_start_timestamp = min($now, $first_booked_timestamps[0]);
        $occurrences_start_timestamp = $occurrences_start_timestamp - (3600*24);

        $dates = $render->dates($event_id, NULL, 100, date('Y-m-d H:i:s', $occurrences_start_timestamp));

        // Invalid Event, Tickets or Dates
        if(!is_array($tickets) || !count($tickets)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('No ticket or future date found for this event! Please try another event.', 'mec').'</div>'));

        $date_format = (isset($this->ml_settings['booking_date_format1']) and trim($this->ml_settings['booking_date_format1'])) ? $this->ml_settings['booking_date_format1'] : 'Y-m-d';

        $repeat_type = get_post_meta($event_id, 'mec_repeat_type', true);
        if($repeat_type === 'custom_days') $date_format .= ' '.get_option('time_format');

        // Date Selection Method
        $date_selection = (isset($this->settings['booking_date_selection']) and trim($this->settings['booking_date_selection'])) ? $this->settings['booking_date_selection'] : 'dropdown';

        // Date Options
        $date_options = '';
        if($date_selection === 'checkboxes')
        {
            foreach($dates as $date) $date_options .= '<li><label><input type="checkbox" value="'.esc_attr($this->book->timestamp($date['start'], $date['end'])).'" name="mec_date[]">'.strip_tags($this->main->date_label($date['start'], $date['end'], $date_format, ' - ', false)).'</label></li>';
            $date_options = '<ul>'.$date_options.'</ul>';
        }
        else
        {
            foreach($dates as $date) $date_options .= '<option value="'.esc_attr($this->book->timestamp($date['start'], $date['end'])).'">'.strip_tags($this->main->date_label($date['start'], $date['end'], $date_format, ' - ', false)).'</option>';
            $date_options = '<select id="mec_book_form_date" class="widefat mec-booking-edit-form-dates" name="mec_date">'.$date_options.'</select>';
        }

        // Ticket option
        $ticket_options = '';
        foreach($tickets as $ticket_id => $ticket) $ticket_options .= '<option value="'.esc_attr($ticket_id).'">'.esc_html($ticket['name']).'</option>';

        // Variations Options
        $variation_options = '';

        $ticket_variations = $this->main->ticket_variations($event_id);
        foreach($ticket_variations as $ticket_variation_id => $ticket_variation)
        {
            if(!is_numeric($ticket_variation_id) or !isset($ticket_variation['title']) or (isset($ticket_variation['title']) and !trim($ticket_variation['title']))) continue;

            $key = ':key:';
            $variation_options .= '<div class="mec-form-row">
                <div class="mec-col-2">
                    <label for="mec_att_'.esc_attr($key).'_variations_'.esc_attr($ticket_variation_id).'" class="mec-ticket-variation-name">'.esc_html($ticket_variation['title']).'</label>
                </div>
                <div class="mec-col-6">
                    <input id="mec_att_'.esc_attr($key).'_variations_'.esc_attr($ticket_variation_id).'" type="number" min="0" max="'.((is_numeric($ticket_variation['max']) and $ticket_variation['max']) ? $ticket_variation['max'] : 1000).'" name="mec_att['.esc_attr($key).'][variations]['.esc_attr($ticket_variation_id).']" value="0">
                </div>
            </div>';
        }

        // Booking Form Options
        $booking_form_options = '';

        $reg_fields = $this->main->get_reg_fields($event_id);
        foreach($reg_fields as $reg_field_id=>$reg_field)
        {
            if(!is_numeric($reg_field_id) or !isset($reg_field['type']) or (isset($reg_field['type']) and !trim($reg_field['type']))) continue;
            if(in_array($reg_field['type'], array('name', 'mec_email'))) continue;

            $key = ':key:';
            $booking_form_options .= '<div class="mec-form-row">';

            if(isset($reg_field['label']) and $reg_field['type'] != 'agreement') $booking_form_options .= '<div class="mec-col-2"><label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'">'.esc_html__($reg_field['label'], 'mec').'</label></div>';
            elseif(isset($reg_field['label']) and $reg_field['type'] == 'agreement') $booking_form_options .= '<div class="mec-col-2"></div>';

            $booking_form_options .= '<div class="mec-col-6">';
            $mandatory = (isset($reg_field['mandatory']) and $reg_field['mandatory']) ? true : false;

            if($reg_field['type'] == 'text')
            {
                $booking_form_options .= '<input class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="text" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
            }
            elseif($reg_field['type'] == 'date')
            {
                $booking_form_options .= '<input class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="date" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' min="'.esc_attr(date_i18n('Y-m-d', strtotime('-100 years'))).'" max="'.esc_attr(date_i18n('Y-m-d', strtotime('+100 years'))).'" />';
            }
            elseif($reg_field['type'] == 'email')
            {
                $booking_form_options .= '<input class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="email" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
            }
            elseif ($reg_field['type'] == 'tel')
            {
                $booking_form_options .= '<input class="widefat" oninput="this.value=this.value.replace(/(?![0-9])./gmi,"")" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="tel" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
            }
            elseif($reg_field['type'] == 'textarea')
            {
                $booking_form_options .= '<textarea class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'></textarea>';
            }
            elseif($reg_field['type'] == 'select')
            {
                $booking_form_options .= '<select class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'>';
                foreach($reg_field['options'] as $reg_field_option) $booking_form_options .= '<option value="'.esc_attr__($reg_field_option['label'], 'mec').'">'.esc_html__($reg_field_option['label'], 'mec').'</option>';
                $booking_form_options .= '</select>';
            }
            elseif($reg_field['type'] == 'radio')
            {
                foreach($reg_field['options'] as $reg_field_option)
                {
                    $booking_form_options .= '<label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'">
                        <input type="radio" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="'.esc_html__($reg_field_option['label'], 'mec').'" />
                        '.esc_html__($reg_field_option['label'], 'mec').'
                    </label>';
                }
            }
            elseif($reg_field['type'] == 'checkbox')
            {
                foreach($reg_field['options'] as $reg_field_option)
                {
                    $booking_form_options .= '<label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'">
                        <input type="checkbox" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).'][]" value="'.esc_html__($reg_field_option['label'], 'mec').'" />
                        '.esc_html__($reg_field_option['label'], 'mec').'
                    </label>';
                }
            }
            elseif($reg_field['type'] == 'agreement')
            {
                $booking_form_options .= '<label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'">
                    <input type="checkbox" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="1" '.((!isset($reg_field['status']) or (isset($reg_field['status']) and $reg_field['status'] == 'checked')) ? 'checked="checked"' : '').' '.($mandatory ? 'required="required"' : '').' />
                    '.sprintf(esc_html__($reg_field['label'], 'mec'), '<a href="'.get_the_permalink($reg_field['page']).'" target="_blank">'.get_the_title($reg_field['page']).'</a>').'
                </label>';
            }
            elseif($reg_field['type'] == 'file')
            {
                $booking_form_options .= '<button type="button" class="mec-choose-file" data-for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'">'.esc_html__('Select File', 'mec').'</button><input type="hidden" class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" />';
            }

            $booking_form_options .= '</div>';
            $booking_form_options .= '</div>';
        }

        $date = current($dates);
        $date = $this->book->timestamp($date['start'], $date['end']);
        $response = apply_filters(
            'mec_bbf_edit_event_options_response',
            array(
                'success' => 1,
                'dates' => MEC_kses::form($date_options),
                'tickets' => MEC_kses::form($ticket_options),
                'variations' => MEC_kses::form($variation_options),
                'reg_fields' => MEC_kses::form($booking_form_options)
            ),
            $event_id,
            $date,
            $tickets
        );

        $this->main->response( $response );
    }

    public function bbf_edit_event_add_attendee()
    {
        $event_id = isset($_REQUEST['event_id']) ? sanitize_text_field($_REQUEST['event_id']) : '';
        $key = isset($_REQUEST['key']) ? sanitize_text_field($_REQUEST['key']) : '';

        // Event is invalid!
        if(!trim($event_id)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('Event is invalid. Please select an event.', 'mec').'</div>'));

        $tickets = get_post_meta($event_id, 'mec_tickets', true);

        // Invalid Tickets
        if(!is_array($tickets) or (is_array($tickets) and !count($tickets))) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('No ticket or future date found for this event! Please try another event.', 'mec').'</div>'));

        // Ticket option
        $ticket_options = '';
        foreach($tickets as $ticket_id => $ticket) $ticket_options .= '<option value="'.esc_attr($ticket_id).'">'.esc_html($ticket['name']).'</option>';

        // Variations Options
        $variation_options = '';

        $ticket_variations = $this->main->ticket_variations($event_id);
        foreach($ticket_variations as $ticket_variation_id => $ticket_variation)
        {
            if(!is_numeric($ticket_variation_id) or !isset($ticket_variation['title']) or (isset($ticket_variation['title']) and !trim($ticket_variation['title']))) continue;

            $variation_options .= '<div class="mec-form-row">
                <div class="mec-col-2">
                    <label for="mec_att_'.esc_attr($key).'_variations_'.esc_attr($ticket_variation_id).'" class="mec-ticket-variation-name">'.esc_html($ticket_variation['title']).'</label>
                </div>
                <div class="mec-col-6">
                    <input id="mec_att_'.esc_attr($key).'_variations_'.esc_attr($ticket_variation_id).'" type="number" min="0" max="'.((is_numeric($ticket_variation['max']) and $ticket_variation['max']) ? $ticket_variation['max'] : 1000).'" name="mec_att['.esc_attr($key).'][variations]['.esc_attr($ticket_variation_id).']" value="0">
                </div>
            </div>';
        }

        // Booking Form Options
        $booking_form_options = '';

        $reg_fields = $this->main->get_reg_fields($event_id);
        foreach($reg_fields as $reg_field_id=>$reg_field)
        {
            if(!is_numeric($reg_field_id) or !isset($reg_field['type']) or (isset($reg_field['type']) and !trim($reg_field['type']))) continue;
            if(in_array($reg_field['type'], array('name', 'mec_email'))) continue;

            $booking_form_options .= '<div class="mec-form-row">';

            if(isset($reg_field['label']) and $reg_field['type'] != 'agreement') $booking_form_options .= '<div class="mec-col-2"><label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'">'.esc_html__($reg_field['label'], 'mec').'</label></div>';
            elseif(isset($reg_field['label']) and $reg_field['type'] == 'agreement') $booking_form_options .= '<div class="mec-col-2"></div>';

            $booking_form_options .= '<div class="mec-col-6">';
            $mandatory = (isset($reg_field['mandatory']) and $reg_field['mandatory']) ? true : false;

            if($reg_field['type'] == 'text')
            {
                $booking_form_options .= '<input class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="text" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
            }
            elseif($reg_field['type'] == 'date')
            {
                $booking_form_options .= '<input class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="date" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' min="'.esc_attr(date_i18n('Y-m-d', strtotime('-100 years'))).'" max="'.esc_attr(date_i18n('Y-m-d', strtotime('+100 years'))).'" />';
            }
            elseif($reg_field['type'] == 'email')
            {
                $booking_form_options .= '<input class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="email" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
            }
            elseif ($reg_field['type'] == 'tel')
            {
                $booking_form_options .= '<input class="widefat" oninput="this.value=this.value.replace(/(?![0-9])./gmi,"")" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" type="tel" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').' />';
            }
            elseif($reg_field['type'] == 'textarea')
            {
                $booking_form_options .= '<textarea class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'></textarea>';
            }
            elseif($reg_field['type'] == 'select')
            {
                $booking_form_options .= '<select class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" placeholder="'.esc_html__($reg_field['label'], 'mec').'" '.($mandatory ? 'required="required"' : '').'>';
                foreach($reg_field['options'] as $reg_field_option) $booking_form_options .= '<option value="'.esc_attr__($reg_field_option['label'], 'mec').'">'.esc_html__($reg_field_option['label'], 'mec').'</option>';
                $booking_form_options .= '</select>';
            }
            elseif($reg_field['type'] == 'radio')
            {
                foreach($reg_field['options'] as $reg_field_option)
                {
                    $booking_form_options .= '<label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'">
                        <input type="radio" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="'.esc_html__($reg_field_option['label'], 'mec').'" />
                        '.esc_html__($reg_field_option['label'], 'mec').'
                    </label>';
                }
            }
            elseif($reg_field['type'] == 'checkbox')
            {
                foreach($reg_field['options'] as $reg_field_option)
                {
                    $booking_form_options .= '<label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'">
                        <input type="checkbox" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'_'.strtolower(str_replace(' ', '_', $reg_field_option['label'])).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).'][]" value="'.esc_html__($reg_field_option['label'], 'mec').'" />
                        '.esc_html__($reg_field_option['label'], 'mec').'
                    </label>';
                }
            }
            elseif($reg_field['type'] == 'agreement')
            {
                $booking_form_options .= '<label for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'">
                    <input type="checkbox" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="1" '.((!isset($reg_field['status']) or (isset($reg_field['status']) and $reg_field['status'] == 'checked')) ? 'checked="checked"' : '').' '.($mandatory ? 'required="required"' : '').' />
                    '.sprintf(esc_html__($reg_field['label'], 'mec'), '<a href="'.get_the_permalink($reg_field['page']).'" target="_blank">'.get_the_title($reg_field['page']).'</a>').'
                </label>';
            }
            elseif($reg_field['type'] == 'file')
            {
                $booking_form_options .= '<button type="button" class="mec-choose-file" data-for="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'">'.esc_html__('Select File', 'mec').'</button><input type="hidden" class="widefat" id="mec_book_reg_field_reg'.esc_attr($key).'_'.esc_attr($reg_field_id).'" name="mec_att['.esc_attr($key).'][reg]['.esc_attr($reg_field_id).']" value="" />';
            }

            $booking_form_options .= '</div>';
            $booking_form_options .= '</div>';
        }

        // Date Option
        $output = '<div class="mec-attendee" id="mec_attendee'.esc_attr($key).'">
        <hr>
        <div class="mec-form-row">
            <div class="mec-col-8" style="text-align: right;">
                <button type="button" class="button mec-remove-attendee" data-key="'.esc_attr($key).'">'.esc_html__('Remove Attendee', 'mec').'</button>
            </div>
        </div>
        <div class="mec-form-row">
            <div class="mec-col-2">
                <label for="att_'.esc_attr($key).'_name">'.esc_html__('Name', 'mec').'</label>
            </div>
            <div class="mec-col-6">
                <input type="text" value="" id="att_'.esc_attr($key).'_name" name="mec_att['.esc_attr($key).'][name]" placeholder="'.esc_attr__('Name', 'mec').'" class="widefat">
            </div>
        </div>
        <div class="mec-form-row">
            <div class="mec-col-2">
                <label for="att_'.esc_attr($key).'_email">'.esc_html__('Email', 'mec').'</label>
            </div>
            <div class="mec-col-6">
                <input type="email" value="" id="att_'.esc_attr($key).'_email" name="mec_att['.esc_attr($key).'][email]" placeholder="'.esc_attr__('Email', 'mec').'" class="widefat">
            </div>
        </div>
        <div class="mec-form-row">
            <div class="mec-col-2">
                <label for="att_'.esc_attr($key).'_ticket">'.esc_html($this->main->m('ticket', esc_html__('Ticket', 'mec'))).'</label>
            </div>
            <div class="mec-col-6">
                <select id="att_'.esc_attr($key).'_ticket" name="mec_att['.esc_attr($key).'][id]" class="widefat mec-booking-edit-form-tickets">'.$ticket_options.'</select>
            </div>
        </div>'.($booking_form_options).'
        '.((isset($this->settings['ticket_variations_status']) and $this->settings['ticket_variations_status'] and count($ticket_variations)) ? '<div class="mec-book-ticket-variations" data-key="'.esc_attr($key).'">'.$variation_options.'</div>' : '').'</div>';

        $this->main->response(array('success' => 1, 'output' => MEC_kses::form($output)));
    }

    public function bbf_edit_event_ticket_changed()
    {
        $booking_id = isset($_REQUEST['booking_id']) ? sanitize_text_field($_REQUEST['booking_id']) : '';
        $event_id = isset($_REQUEST['event_id']) ? sanitize_text_field($_REQUEST['event_id']) : '';
        $ticket_id = isset($_REQUEST['ticket_id']) ? sanitize_text_field($_REQUEST['ticket_id']) : '';
        $attendee_id = isset($_REQUEST['attendee_id']) ? sanitize_text_field($_REQUEST['attendee_id']) : '';
        $type = isset($_REQUEST['type']) ? sanitize_text_field($_REQUEST['type']) : 'edit';

        // Booking is invalid!
        if(!trim($booking_id)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('Booking is invalid!', 'mec').'</div>'));

        // Event is invalid!
        if(!trim($event_id)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('Event is invalid. Please select an event.', 'mec').'</div>'));

        $tickets = get_post_meta($event_id, 'mec_tickets', true);

        // Invalid Tickets
        if(!is_array($tickets) || !count($tickets)) $this->main->response(array('success'=>0, 'output'=>'<div class="warning-msg">'.esc_html__('No tickets found for this event! Please try another event.', 'mec').'</div>'));

        $meta = $this->main->get_post_meta($booking_id);
        $attendees = $meta['mec_attendees'] ?? (isset($meta['mec_attendee']) ? array($meta['mec_attendee']) : array());
        $attendee = $attendees[$attendee_id] ?? [];

        // Ticket Variations
        $ticket_variations = $this->main->ticket_variations($event_id, $ticket_id);

        $output = '';
        if(isset($this->settings['ticket_variations_status']) and $this->settings['ticket_variations_status'] and count($ticket_variations))
        {
            foreach($ticket_variations as $ticket_variation_id=>$ticket_variation)
            {
                if(!is_numeric($ticket_variation_id) or !isset($ticket_variation['title']) or (isset($ticket_variation['title']) and !trim($ticket_variation['title']))) continue;

                $output .= '<div class="mec-form-row" style="padding-bottom: 5px;">
                    <div class="mec-col-2">
                        <label for="mec_att_'.esc_attr($attendee_id).'_variations_'.esc_attr($ticket_variation_id).'" class="mec-ticket-variation-name">'.esc_html($ticket_variation['title']).'</label>
                    </div>
                    <div class="mec-col-6">
                        <input id="mec_att_'.esc_attr($attendee_id).'_variations_'.esc_attr($ticket_variation_id).'" type="number" min="0" max="'.((is_numeric($ticket_variation['max']) and $ticket_variation['max']) ? $ticket_variation['max'] : 1000).'" name="'.($type === 'edit' ? 'mec_att' : 'mec_attendee').'['.esc_attr($attendee_id).'][variations]['.esc_attr($ticket_variation_id).']" value="'.((isset($attendee['variations']) and isset($attendee['variations'][$ticket_variation_id])) ? esc_attr($attendee['variations'][$ticket_variation_id]) : 0).'">
                    </div>
                </div>';
            }
        }

        $this->main->response(array('success' => 1, 'output' => MEC_kses::form($output)));
    }

    /**
     * Change post status to publish for remove scheduled label.
     * @author Webnus <info@webnus.net>
     */
    public function remove_scheduled($post_id, $post)
    {
        if($post->post_type == $this->main->get_book_post_type() and $post->post_status == 'future') wp_publish_post($post_id);
    }

    public function add_occurrence_filter($event_id)
    {
        $output = '<select name="mec_occurrence" id="mec_filter_occurrence">';
        $output .= '<option value="">'.esc_html__('Occurrence', 'mec').'</option>';

        $q = new WP_Query();
        $bookings = $q->query(array
        (
            'post_type'=>$this->main->get_book_post_type(),
            'posts_per_page'=>-1,
            'post_status'=>array('future', 'publish'),
            'orderby'=>'post_date',
            'order'=>'ASC',
            'meta_query'=>array
            (
                array(
                    'key'=>'mec_event_id',
                    'value'=>$event_id,
                )
            )
        ));

        if(!count($bookings)) return '';

        $dates = [];
        foreach($bookings as $booking)
        {
            $dates[strtotime($booking->post_date)] = $booking->post_date;
        }

        $occurrence = isset($_REQUEST['mec_occurrence']) ? sanitize_text_field($_REQUEST['mec_occurrence']) : '';
        $datetime_format = get_option('date_format').' '.get_option('time_format');

        foreach($dates as $timestamp => $date)
        {
            $output .= '<option value="'.esc_attr($timestamp).'" '.($occurrence == $timestamp ? 'selected="selected"' : '').'>'.date($datetime_format, $timestamp).'</option>';
        }

        $output .= '</select>';
        return $output;
    }

    public function add_occurrence_filter_ajax()
    {
        $event_id = isset($_REQUEST['event_id']) ? sanitize_text_field($_REQUEST['event_id']) : 0;

        $html = $this->add_occurrence_filter($event_id);
        echo json_encode(array('html' => $html));
        exit;
    }

    public function shortcode($atts)
    {
        $event_id = $atts['event-id'] ?? 0;
        if(!$event_id) return '<p class="warning-msg">'.esc_html__('Please insert event id!', 'mec').'</p>';

        $event = get_post($event_id);
        if(!$event || $event->post_type != $this->main->get_main_post_type()) return '<p class="warning-msg">'.esc_html__('Event is not valid!', 'mec').'</p>';

        // Ticket ID
        $ticket_id = $atts['ticket-id'] ?? NULL;

        // Create Single Skin
        $single = new MEC_skin_single();

        // Initialize the skin
        $single->initialize(array(
            'id' => $event_id,
            'maximum_dates' => ($this->settings['booking_maximum_dates'] ?? 6)
        ));

        // Fetch the events
        $events = $single->fetch();

        if(!$this->main->can_show_booking_module($events[0])) return '';

        return '<div class="mec-wrap mec-events-meta-group mec-events-meta-group-booking mec-events-meta-group-booking-shortcode">' . MEC_kses::full($this->main->module('booking.default', array(
            'event' => $events,
            'ticket_id' => $ticket_id,
            'from_shortcode' => true
        ))) . '</div>';
    }

    public function ticket_variations_shortcode($atts)
    {
        $event_id = $atts['event-id'] ?? 0;
        if(!$event_id)
        {
            $post = get_post();
            if($post && isset($post->post_type) && $post->post_type === $this->main->get_main_post_type()) $event_id = $post->ID;
        }

        if(!$event_id) return '<p class="warning-msg">'.esc_html__('Please insert event id!', 'mec').'</p>';

        $event = get_post($event_id);
        if(!$event || $event->post_type !== $this->main->get_main_post_type()) return '<p class="warning-msg">'.esc_html__('Event is not valid!', 'mec').'</p>';

        $path = MEC::import('app.features.booking.variations', true, true);

        // Generate Month
        ob_start();
        include $path;
        return ob_get_clean();
    }

    public function adjust_booking_fees()
    {
        $gateway_id = sanitize_text_field($_POST['gateway_id']);
        $transaction_id = sanitize_text_field($_POST['transaction_id']);

        // Paramater validation
        if(!trim($gateway_id) or !trim($transaction_id)) $this->main->response(array('success'=>0, 'code'=>'INVALID_REQUEST'));

        // Check if our nonce is set.
        if(!isset($_POST['_wpnonce'])) $this->main->response(array('success'=>0, 'code'=>'NONCE_MISSING'));

        // Verify that the nonce is valid.
        if(!wp_verify_nonce(sanitize_text_field($_POST['_wpnonce']), 'mec_adjust_booking_fees')) $this->main->response(array('success'=>0, 'code'=>'NONCE_IS_INVALID'));

        // Disabled Gateways
        $disabled_gateways = ((isset($this->settings['fees_disabled_gateways']) and is_array($this->settings['fees_disabled_gateways'])) ? $this->settings['fees_disabled_gateways'] : array());

        $remove_fees = true;
        if(!count($disabled_gateways) or !isset($disabled_gateways[$gateway_id]) or (isset($disabled_gateways[$gateway_id]) and !$disabled_gateways[$gateway_id])) $remove_fees = false;

        $transaction = $this->book->get_transaction($transaction_id);

        $event_id = $transaction['event_id'] ?? NULL;
        $requested_event_id = $transaction['translated_event_id'] ?? $event_id;

        if($remove_fees) $this->book->remove_fees($transaction_id);
        else $this->book->readd_fees($transaction_id);

        $transaction = $this->book->get_transaction($transaction_id);

        $price_details = '';
        foreach($transaction['price_details']['details'] as $detail)
        {
            $price_details .= '<li class="mec-book-price-detail mec-book-price-detail-type-'.esc_attr($detail['type']).'">
                '.($detail['type'] === 'tickets' ? '<span class="mec-book-price-detail-icon">'.$this->main->svg('form/subtotal-icon').'</span>' : '').'
                <div class="mec-ticket-name-description-wrapper">
                    <span class="mec-book-price-detail-description">'.esc_html($detail['description']).'</span>
                    <span class="mec-book-price-detail-amount">'.esc_html($this->main->render_price($detail['amount'], $requested_event_id)).'</span>
                </div>
            </li>';
        }

        $this->main->response([
            'success' => 1,
            'data' => [
                'total_raw' => $transaction['total'],
                'total' => $this->main->render_price($transaction['total'], $requested_event_id),
                'price_raw' => $transaction['payable'],
                'price' => $this->main->render_price($transaction['payable'], $requested_event_id),
                'price_details' => $price_details,
                'transaction_id' => $transaction_id
            ]
        ]);
    }

    public function delete_transaction($post_id)
    {
        $post = get_post($post_id);
        if($post->post_type != $this->main->get_book_post_type()) return false;

        $transaction_id = get_post_meta($post_id, 'mec_transaction_id', true);
        return delete_option($transaction_id);
    }

    /**
     * @param $post_id
     * @param WP_Post $post
     */
    public function record_update($post_id, $post)
    {
        // If this is an autosave, our form has not been submitted, so we don't want to do anything.
        if(defined('DOING_AUTOSAVE') and DOING_AUTOSAVE) return;

        // It's not a booking
        if($post->post_type !== $this->main->get_book_post_type()) return;

        // Booking Record
        $this->getBookingRecord()->update($post_id);
    }

    public function record_delete($post_id, $post)
    {
        $post = get_post($post_id);
        if($post->post_type != $this->main->get_book_post_type()) return false;

        // Booking Record
        $this->getBookingRecord()->delete($post_id);
    }

    public function redirect_payment_thankyou($message)
    {
        // Transaction ID
        $transaction_id = $_REQUEST['mec_stripe_redirect_transaction_id'] ?? '';
        if(!trim($transaction_id)) $transaction_id = $_REQUEST['mec_stripe_connect_redirect_transaction_id'] ?? '';

        if($transaction_id)
        {
            $thankyou_message = get_option('mec_transaction_'.$transaction_id.'_message', '');
            if(trim($thankyou_message))
            {
                $message = $thankyou_message;
                delete_option('mec_transaction_'.$transaction_id.'_message');
            }
        }

        return $message;
    }

    public function reset_booking_cache( $book_id ) {

        $transaction_id = get_post_meta( $book_id, 'mec_transaction_id', true );

        if( $transaction_id ) {

            $transactionObject = new \MEC\Transactions\Transaction( $transaction_id );
            $transactionObject->reset_cache_tickets_details();
        }
    }
}
