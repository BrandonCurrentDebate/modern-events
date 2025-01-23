<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC coupons class.
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_coupons extends MEC_base
{
    public $factory;
    public $book;
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

        // Import MEC Book
        $this->book = $this->getBook();

        // Import MEC Main
        $this->main = $this->getMain();

        // MEC Settings
        $this->settings = $this->main->get_settings();
    }

    /**
     * Initialize coupons feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        // PRO Version is required
        if(!$this->getPRO()) return false;

        // Show coupons feature only if booking module is enabled
        if(!isset($this->settings['booking_status']) || !$this->settings['booking_status']) return false;

        // Show coupons feature only if coupons module is enabled
        if(!isset($this->settings['coupons_status']) || !$this->settings['coupons_status']) return false;

        $this->factory->action('init', array($this, 'register_taxonomy'), 9);
        $this->factory->action('mec_coupon_edit_form_fields', array($this, 'edit_form'));
        $this->factory->action('mec_coupon_add_form_fields', array($this, 'add_form'));
        $this->factory->action('edited_mec_coupon', array($this, 'save_metadata'));
        $this->factory->action('created_mec_coupon', array($this, 'save_metadata'));

        $this->factory->filter('manage_edit-mec_coupon_columns', array($this, 'filter_columns'));
        $this->factory->filter('manage_mec_coupon_custom_column', array($this, 'filter_columns_content'), 10, 3);

        // Apply Coupon Form
        $this->factory->action('wp_ajax_mec_apply_coupon', array($this, 'apply_coupon'));
        $this->factory->action('wp_ajax_nopriv_mec_apply_coupon', array($this, 'apply_coupon'));

        return true;
    }

    /**
     * Register label taxonomy
     * @author Webnus <info@webnus.net>
     */
    public function register_taxonomy()
    {
        $coupon_args = apply_filters(
            'mec_register_taxonomy_args',
            array(
                'label'=>__('Coupons', 'mec'),
                'labels'=>array(
                    'name'=>__('Coupons', 'mec'),
                    'singular_name'=>__('Coupon', 'mec'),
                    'all_items'=>__('All Coupons', 'mec'),
                    'edit_item'=>__('Edit Coupon', 'mec'),
                    'view_item'=>__('View Coupon', 'mec'),
                    'update_item'=>__('Update Coupon', 'mec'),
                    'add_new_item'=>__('Add New Coupon', 'mec'),
                    'new_item_name'=>__('New Coupon Name', 'mec'),
                    'popular_items'=>__('Popular Coupons', 'mec'),
                    'search_items'=>__('Search Coupons', 'mec'),
                    'back_to_items'=>__('← Back to Coupons', 'mec'),
                    'not_found'=>__('no coupons found.', 'mec'),
                ),
                'public'=>true,
                'show_ui'=>true,
                'publicly_queryable'=>false,
                'hierarchical'=>false,
                'capabilities' => array(
                    'manage_terms' => 'mec_coupons',
                    'edit_terms' => 'mec_coupons',
                    'delete_terms' => 'mec_coupons',
                    'assign_terms' => 'mec_coupons',
                )
            ),
            'mec_coupon'
        );
        register_taxonomy(
            'mec_coupon',
            $this->main->get_book_post_type(),
            $coupon_args
        );

        register_taxonomy_for_object_type('mec_coupon', $this->main->get_book_post_type());
    }

    /**
     * Show edit form of labels
     * @author Webnus <info@webnus.net>
     * @param object $term
     */
    public function edit_form($term)
    {
        $discount_type = get_metadata('term', $term->term_id, 'discount_type', true);
        $discount = get_metadata('term', $term->term_id, 'discount', true);
        $usage_limit = get_metadata('term', $term->term_id, 'usage_limit', true);
        $expiration_date = get_metadata('term', $term->term_id, 'expiration_date', true);

        $target_event = get_metadata('term', $term->term_id, 'target_event', true);
        $target_events = get_metadata('term', $term->term_id, 'target_events', true);

        if(!is_array($target_events))
        {
            $target_events = [];
            if($target_event) $target_events[] = $target_event;
        }

        $target_category = get_metadata('term', $term->term_id, 'target_category', true);
        $target_categories = get_metadata('term', $term->term_id, 'target_categories', true);

        $maximum_discount = get_metadata('term', $term->term_id, 'maximum_discount', true);
        $ticket_maximum = get_metadata('term', $term->term_id, 'ticket_maximum', true);

        $ticket_minimum = get_metadata('term', $term->term_id, 'ticket_minimum', true);
        if(trim($ticket_minimum) === '') $ticket_minimum = 1;

        $date_maximum = get_metadata('term', $term->term_id, 'date_maximum', true);

        $date_minimum = get_metadata('term', $term->term_id, 'date_minimum', true);
        if(trim($date_minimum) === '') $date_minimum = 1;

        $events = get_posts(array('post_type'=>$this->main->get_main_post_type(), 'post_status'=>'publish', 'posts_per_page'=>-1));
        $categories = get_terms([
            'taxonomy' => 'mec_category',
            'hide_empty' => 0,
        ]);

        $apply_on_fees = get_metadata('term', $term->term_id, 'apply_on_fees', true);
    ?>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_discount_type"><?php esc_html_e('Discount Type', 'mec'); ?></label>
            </th>
            <td>
                <select name="discount_type" id="mec_discount_type">
                    <option value="percent" <?php echo ($discount_type == 'percent' ? 'selected="selected"' : ''); ?>><?php esc_html_e('Percent', 'mec'); ?></option>
                    <option value="amount" <?php echo ($discount_type == 'amount' ? 'selected="selected"' : ''); ?>><?php esc_html_e('Amount', 'mec'); ?></option>
                </select>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_discount"><?php esc_html_e('Discount', 'mec'); ?></label>
            </th>
            <td>
                <input type="text" name="discount" id="mec_discount" value="<?php echo esc_attr($discount); ?>" />
                <p class="description"><?php esc_html_e('Discount percentage, considered as amount if you set the discount type to amount', 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_usage_limit"><?php esc_html_e('Usage Limit', 'mec'); ?></label>
            </th>
            <td>
                <input type="text" name="usage_limit" id="mec_usage_limit" value="<?php echo esc_attr($usage_limit); ?>" />
                <p class="description"><?php esc_html_e('Insert -1 for unlimited usage', 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_expiration_date"><?php esc_html_e('Expiration Date', 'mec'); ?></label>
            </th>
            <td>
                <input type="text" name="expiration_date" id="mec_expiration_date" value="<?php echo esc_attr($expiration_date); ?>" class="mec_date_picker" autocomplete="off" />
                <p class="description"><?php esc_html_e('Leave empty for no expiration!', 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_target_event"><?php esc_html_e('Target Event', 'mec'); ?></label>
            </th>
            <td>
                <label>
                    <input type="hidden" name="target_event" value="0">
                    <input id="mec_target_event" type="checkbox" name="target_event" value="1" onchange="jQuery('#mec_coupon_target_events').toggleClass('w-hidden');" <?php echo (($target_event == '1' or trim($target_event) == '') ? 'checked="checked"' : ''); ?>>
                    <?php esc_html_e('All Events', 'mec'); ?>
                </label>
            </td>
        </tr>
        <tr class="form-field <?php echo (($target_event == '1' or trim($target_event) == '') ? 'w-hidden' : ''); ?>" id="mec_coupon_target_events">
            <th scope="row">
                <label><?php esc_html_e('Events', 'mec'); ?></label>
            </th>
            <td>
                <ul class="mec-select-deselect-actions" data-for="#mec_coupon_events">
                    <li data-action="select-all"><?php esc_html_e('Select All', 'mec'); ?></li>
                    <li data-action="deselect-all"><?php esc_html_e('Deselect All', 'mec'); ?></li>
                    <li data-action="toggle"><?php esc_html_e('Toggle', 'mec'); ?></li>
                </ul>
                <ul id="mec_coupon_events">
                    <?php foreach($events as $event): ?>
                    <li>
                        <label>
                            <input type="checkbox" name="target_events[]" value="<?php echo esc_attr($event->ID); ?>" <?php echo (in_array($event->ID, $target_events) ? 'checked="checked"' : ''); ?>>
                            <?php echo esc_html($event->post_title); ?>
                        </label>
                    </li>
                    <?php endforeach; ?>
                </ul>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_target_category"><?php esc_html_e('Target Category', 'mec'); ?></label>
            </th>
            <td>
                <label>
                    <input type="hidden" name="target_category" value="0">
                    <input id="mec_target_category" type="checkbox" name="target_category" value="1" onchange="jQuery('#mec_coupon_target_categories').toggleClass('w-hidden');" <?php echo (($target_category == '1' or trim($target_category) == '') ? 'checked="checked"' : ''); ?>>
                    <?php esc_html_e('All Categories', 'mec'); ?>
                </label>
            </td>
        </tr>
        <tr class="form-field <?php echo (($target_category == '1' or trim($target_category) == '') ? 'w-hidden' : ''); ?>" id="mec_coupon_target_categories">
            <th scope="row">
                <label><?php esc_html_e('Categories', 'mec'); ?></label>
            </th>
            <td>
                <ul>
                    <?php foreach($categories as $category): ?>
                    <li>
                        <label>
                            <input type="checkbox" name="target_categories[]" value="<?php echo esc_attr($category->term_id); ?>" <?php echo (in_array($category->term_id, $target_categories) ? 'checked="checked"' : ''); ?>>
                            <?php echo esc_html($category->name); ?>
                        </label>
                    </li>
                    <?php endforeach; ?>
                </ul>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_ticket_minimum"><?php esc_html_e('Minimum Ticket', 'mec'); ?></label>
            </th>
            <td>
                <input type="number" name="ticket_minimum" id="mec_ticket_minimum" value="<?php echo esc_attr($ticket_minimum); ?>" min="1" />
                <p class="description"><?php esc_html_e('Insert 1 to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or higher tickets.', 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_ticket_maximum"><?php esc_html_e('Maximum Ticket', 'mec'); ?></label>
            </th>
            <td>
                <input type="number" name="ticket_maximum" id="mec_ticket_maximum" value="<?php echo esc_attr($ticket_maximum); ?>" min="0" />
                <p class="description"><?php esc_html_e('Leave it empty to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or less tickets.', 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_date_minimum"><?php esc_html_e('Minimum Dates', 'mec'); ?></label>
            </th>
            <td>
                <input type="number" name="date_minimum" id="mec_date_minimum" value="<?php echo esc_attr($date_minimum); ?>" min="1" />
                <p class="description"><?php esc_html_e('Insert 1 to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or higher dates booked.', 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_date_maximum"><?php esc_html_e('Maximum Dates', 'mec'); ?></label>
            </th>
            <td>
                <input type="number" name="date_maximum" id="mec_date_maximum" value="<?php echo esc_attr($date_maximum); ?>" min="0" />
                <p class="description"><?php esc_html_e('Leave it empty to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or less dates booked.', 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_maximum_discount"><?php esc_html_e('Maximum Discount', 'mec'); ?></label>
            </th>
            <td>
                <input type="number" name="maximum_discount" id="mec_maximum_discount" value="<?php echo esc_attr($maximum_discount); ?>" min="0" />
                <p class="description"><?php esc_html_e("Set a maximum amount of discount for percentage coupons. E.g. 100 for a 50% coupon. Leave empty if you don't want to use it!", 'mec'); ?></p>
            </td>
        </tr>
        <tr class="form-field">
            <th scope="row">
                <label for="mec_apply_on_fees"><?php esc_html_e('Apply Discount on Fees', 'mec'); ?></label>
            </th>
            <td>
                <label>
                    <input type="hidden" name="apply_on_fees" value="0">
                    <input id="mec_apply_on_fees" type="checkbox" name="apply_on_fees" value="1" <?php echo $apply_on_fees == '1' ? 'checked="checked"' : ''; ?>>
                    <?php esc_html_e('Enabled', 'mec'); ?>
                </label>
                <p class="description"><?php esc_html_e("Whether to apply the discount on all fees. Not recommended if you're charging taxes.", 'mec'); ?></p>
            </td>
        </tr>
    <?php
    }

    /**
     * Show add form of labels
     * @author Webnus <info@webnus.net>
     */
    public function add_form()
    {
        $events = get_posts(array('post_type'=>$this->main->get_main_post_type(), 'post_status'=>'publish', 'posts_per_page'=>-1));
        $categories = get_terms(array(
            'taxonomy' => 'mec_category',
            'hide_empty' => 0,
        ));
    ?>
        <div class="form-field">
            <label for="mec_discount_type"><?php esc_html_e('Discount Type', 'mec'); ?></label>
            <select name="discount_type" id="mec_discount_type">
                <option value="percent"><?php esc_html_e('Percent', 'mec'); ?></option>
                <option value="amount"><?php esc_html_e('Amount', 'mec'); ?></option>
            </select>
        </div>
        <div class="form-field">
            <label for="mec_discount"><?php esc_html_e('Discount', 'mec'); ?></label>
            <input type="text" name="discount" id="mec_discount" value="10" />
            <p class="description"><?php esc_html_e('Discount percentage, considered as amount if you set the discount type to amount', 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label for="mec_usage_limit"><?php esc_html_e('Usage Limit', 'mec'); ?></label>
            <input type="text" name="usage_limit" id="mec_usage_limit" value="100" />
            <p class="description"><?php esc_html_e('Insert -1 for unlimited usage', 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label for="mec_expiration_date"><?php esc_html_e('Expiration Date', 'mec'); ?></label>
            <input type="text" name="expiration_date" id="mec_expiration_date" value="" class="mec_date_picker" autocomplete="off" />
            <p class="description"><?php esc_html_e('Leave empty for no expiration!', 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label for="mec_target_event"><?php esc_html_e('Target Event', 'mec'); ?></label>
            <label>
                <input type="hidden" name="target_event" value="0">
                <input id="mec_target_event" type="checkbox" name="target_event" value="1" onchange="jQuery('#mec_coupon_target_events').toggleClass('w-hidden');" checked="checked">
                <?php esc_html_e('All Events', 'mec'); ?>
            </label>
        </div>
        <div class="form-field w-hidden" id="mec_coupon_target_events">

            <ul class="mec-select-deselect-actions" data-for="#mec_coupon_events">
                <li data-action="select-all"><?php esc_html_e('Select All', 'mec'); ?></li>
                <li data-action="deselect-all"><?php esc_html_e('Deselect All', 'mec'); ?></li>
                <li data-action="toggle"><?php esc_html_e('Toggle', 'mec'); ?></li>
            </ul>

            <label><?php esc_html_e('Events', 'mec'); ?></label>
            <ul id="mec_coupon_events">
                <?php foreach($events as $event): ?>
                <li>
                    <label>
                        <input type="checkbox" name="target_events[]" value="<?php echo esc_attr($event->ID); ?>" checked="checked">
                        <?php echo esc_html($event->post_title); ?>
                    </label>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
        <div class="form-field">
            <label for="mec_target_category"><?php esc_html_e('Target Category', 'mec'); ?></label>
            <label>
                <input type="hidden" name="target_category" value="0">
                <input id="mec_target_category" type="checkbox" name="target_category" value="1" onchange="jQuery('#mec_coupon_target_categories').toggleClass('w-hidden');" checked="checked">
                <?php esc_html_e('All Categories', 'mec'); ?>
            </label>
        </div>
        <div class="form-field w-hidden" id="mec_coupon_target_categories">
            <label><?php esc_html_e('Categories', 'mec'); ?></label>
            <ul>
                <?php foreach($categories as $category): ?>
                <li>
                    <label>
                        <input type="checkbox" name="target_categories[]" value="<?php echo esc_attr($category->term_id); ?>" checked="checked">
                        <?php echo esc_html($category->name); ?>
                    </label>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
        <div class="form-field">
            <label for="mec_ticket_minimum"><?php esc_html_e('Minimum Ticket', 'mec'); ?></label>
            <input type="number" name="ticket_minimum" id="mec_ticket_minimum" value="1" min="1" />
            <p class="description"><?php esc_html_e('Insert 1 to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or higher tickets.', 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label for="mec_ticket_maximum"><?php esc_html_e('Maximum Ticket', 'mec'); ?></label>
            <input type="number" name="ticket_maximum" id="mec_ticket_maximum" value="" min="0" />
            <p class="description"><?php esc_html_e('Leave empty to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or less tickets.', 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label for="mec_date_minimum"><?php esc_html_e('Minimum Dates', 'mec'); ?></label>
            <input type="number" name="date_minimum" id="mec_date_minimum" value="1" min="1" />
            <p class="description"><?php esc_html_e('Insert 1 to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or higher dates booked.', 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label for="mec_date_maximum"><?php esc_html_e('Maximum Dates', 'mec'); ?></label>
            <input type="number" name="date_maximum" id="mec_date_maximum" value="" min="0" />
            <p class="description"><?php esc_html_e('Leave empty to be applicable to all bookings. E.g. if you set 5 then it will be applicable to bookings with 5 or less dates booked.', 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label for="mec_maximum_discount"><?php esc_html_e('Maximum Discount', 'mec'); ?></label>
            <input type="number" name="maximum_discount" id="mec_maximum_discount" value="" min="0" />
            <p class="description"><?php esc_html_e("Set a maximum amount of discount for percentage coupons. E.g. 100 for a 50% coupon. Leave empty if you don't want to use it!", 'mec'); ?></p>
        </div>
        <div class="form-field">
            <label>
                <input type="hidden" name="apply_on_fees" value="0">
                <input id="mec_apply_on_fees" type="checkbox" name="apply_on_fees" value="1">
                <?php esc_html_e('Apply Discount on Fees', 'mec'); ?>
            </label>
            <p class="description"><?php esc_html_e("Whether to apply the discount on all fees. Not recommended if you're charging taxes.", 'mec'); ?></p>
        </div>
    <?php
    }

    /**
     * Save label meta data
     * @author Webnus <info@webnus.net>
     * @param int $term_id
     */
    public function save_metadata($term_id)
    {
        // Quick Edit
        if(!isset($_POST['discount_type'])) return;

        $discount_type = in_array($_POST['discount_type'], array('percent', 'amount')) ? sanitize_text_field($_POST['discount_type']) : 'percent';
        update_term_meta($term_id, 'discount_type', $discount_type);

        $discount = (isset($_POST['discount']) and trim($_POST['discount'])) ? sanitize_text_field($_POST['discount']) : 10;
        update_term_meta($term_id, 'discount', $discount);

        $usage_limit = (isset($_POST['usage_limit']) and trim($_POST['usage_limit'])) ? sanitize_text_field($_POST['usage_limit']) : 10;
        update_term_meta($term_id, 'usage_limit', $usage_limit);

        $expiration_date = (isset($_POST['expiration_date']) and trim($_POST['expiration_date'])) ? sanitize_text_field($_POST['expiration_date']) : '';
        update_term_meta($term_id, 'expiration_date', $expiration_date);

        $target_event = (isset($_POST['target_event']) and trim($_POST['target_event']) != '') ? sanitize_text_field($_POST['target_event']) : 0;
        update_term_meta($term_id, 'target_event', $target_event);

        $target_events = (isset($_POST['target_events']) and is_array($_POST['target_events']) and !$target_event and count($_POST['target_events'])) ? array_map('sanitize_text_field', wp_unslash($_POST['target_events'])) : [];
        update_term_meta($term_id, 'target_events', $target_events);

        $ticket_minimum = (isset($_POST['ticket_minimum']) and trim($_POST['ticket_minimum'])) ? sanitize_text_field($_POST['ticket_minimum']) : 1;
        update_term_meta($term_id, 'ticket_minimum', $ticket_minimum);

        $ticket_maximum = (isset($_POST['ticket_maximum']) and trim($_POST['ticket_maximum'])) ? sanitize_text_field($_POST['ticket_maximum']) : 0;
        update_term_meta($term_id, 'ticket_maximum', $ticket_maximum);

        $date_minimum = (isset($_POST['date_minimum']) and trim($_POST['date_minimum'])) ? sanitize_text_field($_POST['date_minimum']) : 1;
        update_term_meta($term_id, 'date_minimum', $date_minimum);

        $date_maximum = (isset($_POST['date_maximum']) and trim($_POST['date_maximum'])) ? sanitize_text_field($_POST['date_maximum']) : 0;
        update_term_meta($term_id, 'date_maximum', $date_maximum);

        $maximum_discount = (isset($_POST['maximum_discount']) and trim($_POST['maximum_discount'])) ? sanitize_text_field($_POST['maximum_discount']) : 0;
        update_term_meta($term_id, 'maximum_discount', $maximum_discount);

        $target_category = (isset($_POST['target_category']) and trim($_POST['target_category']) != '') ? sanitize_text_field($_POST['target_category']) : 0;
        update_term_meta($term_id, 'target_category', $target_category);

        $target_categories = (isset($_POST['target_categories']) and is_array($_POST['target_categories']) and !$target_category and count($_POST['target_categories'])) ? array_map('sanitize_text_field', wp_unslash($_POST['target_categories'])) : [];
        update_term_meta($term_id, 'target_categories', $target_categories);

        $apply_on_fees = (isset($_POST['apply_on_fees']) and trim($_POST['apply_on_fees'])) ? (int) sanitize_text_field($_POST['apply_on_fees']) : 0;
        update_term_meta($term_id, 'apply_on_fees', $apply_on_fees);
    }

    /**
     * Filter label taxonomy columns
     * @author Webnus <info@webnus.net>
     * @param array $columns
     * @return array
     */
    public function filter_columns($columns)
    {
        unset($columns['name']);
        unset($columns['slug']);
        unset($columns['description']);
        unset($columns['posts']);

        $columns['name'] = esc_html__('Name/Code', 'mec');
        $columns['description'] = esc_html__('Description', 'mec');
        $columns['discount'] = esc_html__('Discount', 'mec');
        $columns['limit'] = esc_html__('Limit', 'mec');
        $columns['posts'] = esc_html__('Count', 'mec');

        return $columns;
    }

    /**
     * Filter content of label taxonomy
     * @author Webnus <info@webnus.net>
     * @param string $content
     * @param string $column_name
     * @param int $term_id
     * @return string
     */
    public function filter_columns_content($content, $column_name, $term_id)
    {
        switch($column_name)
        {
            case 'discount':

                $discount = get_metadata('term', $term_id, 'discount', true);
                $discount_type = get_metadata('term', $term_id, 'discount_type', true);

                if($discount_type === 'percent') $content = $discount.' (%)';
                else $content = $this->main->render_price($discount);

                break;

            case 'limit':

                $usage_limit = get_metadata('term', $term_id, 'usage_limit', true);
                $expiration_date = get_metadata('term', $term_id, 'expiration_date', true);

                $content = ($usage_limit == '-1' ? esc_html__('Unlimited', 'mec') : $usage_limit);
                if(trim($expiration_date)) $content .= ' / '.$expiration_date;

                break;

            default:
                break;
        }

        return $content;
    }

    public function apply_coupon()
    {
        $transaction_id = sanitize_text_field($_POST['transaction_id']);

        // Check if our nonce is set.
        if(!isset($_POST['_wpnonce'])) $this->main->response(array('success'=>0, 'code'=>'NONCE_MISSING'));

        // Verify that the nonce is valid.
        if(!wp_verify_nonce(sanitize_text_field($_POST['_wpnonce']), 'mec_apply_coupon_'.$transaction_id)) $this->main->response(array('success'=>0, 'code'=>'NONCE_IS_INVALID'));

        $transaction = $this->book->get_transaction($transaction_id);
        $event_id = $transaction['event_id'] ?? NULL;

        $coupon = sanitize_text_field($_POST['coupon']);
        $validity = $this->book->coupon_check_validity($coupon, $event_id, $transaction);

        // Coupon is not valid
        if($validity == 0) $this->main->response(array('success'=>0, 'code'=>'COUPON_INVALID', 'message'=>__('Discount coupon is invalid!', 'mec')));
        // Coupon is valid but usage limit reached!
        elseif($validity == -1) $this->main->response(array('success'=>0, 'code'=>'COUPON_USAGE_REACHED', 'message'=>__('Discount coupon use limit reached!', 'mec')));
        // Coupon is expired!
        elseif($validity == -2) $this->main->response(array('success'=>0, 'code'=>'COUPON_EXPIRED', 'message'=>__('Discount coupon is expired!', 'mec')));
        // Coupon is not for this event!
        elseif($validity == -3) $this->main->response(array('success'=>0, 'code'=>'COUPON_NOT_FOR_THIS_EVENT', 'message'=>__('Discount is not valid for this event!', 'mec')));
        // Minimum Tickets
        elseif($validity == -4)
        {
            $coupon_id = $this->book->coupon_get_id($coupon);
            $ticket_minimum = get_term_meta($coupon_id, 'ticket_minimum', true);

            $this->main->response(array('success'=>0, 'code'=>'COUPON_NOT_MEET_MINIMUM_TICKETS', 'message'=>sprintf(esc_html__('You should buy at-least %s tickets to use this discount.', 'mec'), $ticket_minimum)));
        }
        // Maximum Tickets
        elseif($validity == -5)
        {
            $coupon_id = $this->book->coupon_get_id($coupon);
            $ticket_maximum = get_term_meta($coupon_id, 'ticket_maximum', true);

            $this->main->response(array('success'=>0, 'code'=>'COUPON_NOT_MEET_MAXIMUM_TICKETS', 'message'=>sprintf(esc_html__('This coupon can be applied to bookings with maximum %s tickets.', 'mec'), $ticket_maximum)));
        }
        // Minimum Dates
        elseif($validity == -7)
        {
            $coupon_id = $this->book->coupon_get_id($coupon);
            $date_minimum = get_term_meta($coupon_id, 'date_minimum', true);

            $this->main->response(array('success'=>0, 'code'=>'COUPON_NOT_MEET_MINIMUM_DATES', 'message'=>sprintf(esc_html__('You should buy at-least %s dates to use this discount.', 'mec'), $date_minimum)));
        }
        // Maximum Dates
        elseif($validity == -8)
        {
            $coupon_id = $this->book->coupon_get_id($coupon);
            $date_maximum = get_term_meta($coupon_id, 'date_maximum', true);

            $this->main->response(array('success'=>0, 'code'=>'COUPON_NOT_MEET_MAXIMUM_DATES', 'message'=>sprintf(esc_html__('This coupon can be applied to bookings with maximum %s dates.', 'mec'), $date_maximum)));
        }
        // Coupon is not for this category!
        elseif($validity == -6) $this->main->response(array('success'=>0, 'code'=>'COUPON_NOT_FOR_THIS_CATEGORY', 'message'=>__('Discount is not valid for this category!', 'mec')));
        // Coupon is valid
        else
        {
            $discount = $this->book->coupon_apply($coupon, $transaction_id);
            $transaction = $this->book->get_transaction($transaction_id);

            $price_details = '';
            foreach($transaction['price_details']['details'] as $detail)
            {
                $price_details .= '<li class="mec-book-price-detail mec-book-price-detail-type-'.esc_attr($detail['type']).'">
                    '.($detail['type'] === 'tickets' ? '<span class="mec-book-price-detail-icon">'.$this->main->svg('form/subtotal-icon').'</span>' : '').'
                    <div class="mec-ticket-name-description-wrapper">
                        <span class="mec-book-price-detail-description">'.esc_html($detail['description']).'</span>
                        <span class="mec-book-price-detail-amount">'.esc_html($this->main->render_price($detail['amount'], $event_id)).'</span>
                    </div>
                </li>';
            }

            // Stripe Update Payment Intent
            $payment_intent_id = (isset($_POST['stripe_piid']) and trim($_POST['stripe_piid'])) ? sanitize_text_field($_POST['stripe_piid']) : null;
            if($payment_intent_id and $discount)
            {
                $stripe_connect = new MEC_gateway_stripe_connect();
                $stripe = new MEC_gateway_stripe();

                if($stripe_connect->enabled()) $stripe_connect->update_intent_amount($transaction_id, $payment_intent_id, $transaction['payable']);
                else if($stripe->enabled()) $stripe->update_intent_amount($transaction_id, $payment_intent_id, $transaction['payable']);
            }

            $this->main->response([
                'success' => 1,
                'message' => sprintf(esc_html__('Coupon is valid and you get %s discount.', 'mec'), $this->main->render_price($discount, $event_id)),
                'data' => [
                    'discount_raw' => $discount,
                    'discount' => $this->main->render_price($discount, $event_id),
                    'total_raw' => $transaction['total'],
                    'total' => $this->main->render_price($transaction['total'], $event_id),
                    'price_raw' => $transaction['payable'],
                    'price' => $this->main->render_price($transaction['payable'], $event_id),
                    'price_details' => $price_details,
                    'transaction_id' => $transaction_id
                ]
            ]);
        }
    }
}