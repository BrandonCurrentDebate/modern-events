<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Tickets class.
 * @author Webnus <info@webnus.net>
 */
class MEC_tickets extends MEC_base
{
    /**
     * @var MEC_main
     */
    public $main;
    public $settings;

    /**
     * Constructor method
     * @author Webnus <info@webnus.net>
     */
    public function __construct()
    {
        // Import MEC Main
        $this->main = $this->getMain();

        // MEC Settings
        $this->settings = $this->main->get_settings();
    }

    public function builder($args)
    {
        $object_id = $args['object_id'] ?? null;
        $tickets = $args['tickets'] ?? [];
        $name_prefix = $args['name_prefix'] ?? 'mec[tickets]';
        $basic_class = $args['basic_class'] ?? 'mec-basvanced-basic';
        $advanced_class = $args['advanced_class'] ?? 'mec-basvanced-advanced w-hidden';
        $price_per_date_display = $args['perice_per_date_display'] ?? true;

        // MEC Main
        $main = $this->getMain();

        // Settings
        $settings = $main->get_settings();

        // This date format used for datepicker
        $datepicker_format = (isset($settings['datepicker_format']) and trim($settings['datepicker_format'])) ? $settings['datepicker_format'] : 'Y-m-d';

        // Private Description
        $private_description_status = (!isset($settings['booking_private_description']) || $settings['booking_private_description']);
        if(is_admin()) $private_description_status = true;

        // Variations Per Ticket
        $variations_per_ticket_status = isset($settings['ticket_variations_per_ticket']) && $settings['ticket_variations_per_ticket'];
        if(isset($settings['ticket_variations_status']) and !$settings['ticket_variations_status']) $variations_per_ticket_status = false;

        // Ticket Availability Date
        $availability_dates_status = isset($settings['booking_ticket_availability_dates']) && $settings['booking_ticket_availability_dates'];

        // Ticket Times Status
        $ticket_times_status = !((isset($settings['disable_ticket_times']) and $settings['disable_ticket_times']));

        // Family Tickets Status
        $family_ticket_status = isset($settings['booking_family_ticket']) && $settings['booking_family_ticket'];
        ?>
        <div id="mec_meta_box_tickets_form">
            <div class="mec-form-row">
                <button class="button" type="button" id="mec_add_ticket_button"><?php esc_html_e('Add Ticket', 'mec'); ?></button>
            </div>
            <div id="mec_tickets">
                <?php
                $i = 0;
                $tvi = 100;
                foreach($tickets as $key => $ticket)
                {
                    if(!is_numeric($key)) continue;
                    $i = max($i, $key);
                    ?>
                    <div class="mec-box mec_ticket_row" id="mec_ticket_row<?php echo esc_attr($key); ?>">
                        <button class="button remove mec_ticket_remove_button" type="button" onclick="mec_ticket_remove(<?php echo esc_attr($key); ?>);"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true" focusable="false" width="1em" height="1em" style="-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); transform: rotate(360deg);" preserveAspectRatio="xMidYMid meet" viewBox="0 0 20 20"><path d="M14.95 6.46L11.41 10l3.54 3.54l-1.41 1.41L10 11.42l-3.53 3.53l-1.42-1.42L8.58 10L5.05 6.47l1.42-1.42L10 8.58l3.54-3.53z"/></svg></button>
                        <div class="mec-ticket-id mec-label" title="<?php esc_attr_e('Ticket ID', 'mec'); ?>"><span class="mec-ticket-id-title"><?php esc_attr_e('ID', 'mec'); ?>: </span><?php echo esc_attr($key); ?></div>
                        <div class="mec-form-row <?php echo $basic_class; ?>">
                            <input type="text" class="mec-col-12" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][name]"
                                   placeholder="<?php esc_attr_e('Ticket Name', 'mec'); ?>"
                                   value="<?php echo(isset($ticket['name']) ? esc_attr($ticket['name']) : ''); ?>"/>
                        </div>

                        <div class="<?php echo $advanced_class; ?> w-hidden">
                            <?php do_action('mec_ticket_properties', $key, $ticket, $object_id); ?>
                        </div>

                        <?php if($ticket_times_status): ?>
                            <div class="mec-form-row wn-ticket-time <?php echo $advanced_class; ?>">
                                <div class="mec-ticket-start-time mec-col-12">
                                    <span class="mec-ticket-time mec-label"><?php esc_html_e('Start Time', 'mec'); ?></span>
                                    <?php $main->timepicker(array(
                                        'method' => ($settings['time_format'] ?? 12),
                                        'time_hour' => ($ticket['ticket_start_time_hour'] ?? 8),
                                        'time_minutes' => ($ticket['ticket_start_time_minute'] ?? 0),
                                        'time_ampm' => ($ticket['ticket_start_time_ampm'] ?? 'AM'),
                                        'name' => $name_prefix.'['.esc_attr($key).']',
                                        'hour_key' => 'ticket_start_time_hour',
                                        'minutes_key' => 'ticket_start_time_minute',
                                        'ampm_key' => 'ticket_start_time_ampm',
                                        'include_h0' => true,
                                    )); ?>
                                </div>
                                <div class="mec-ticket-end-time mec-ticket-start-time mec-col-12">
                                    <span class="mec-ticket-time mec-label"><?php esc_html_e('End Time', 'mec'); ?></span>
                                    <?php $main->timepicker(array(
                                        'method' => ($settings['time_format'] ?? 12),
                                        'time_hour' => ($ticket['ticket_end_time_hour'] ?? 6),
                                        'time_minutes' => ($ticket['ticket_end_time_minute'] ?? 0),
                                        'time_ampm' => ($ticket['ticket_end_time_ampm'] ?? 'PM'),
                                        'name' => $name_prefix.'['.esc_attr($key).']',
                                        'hour_key' => 'ticket_end_time_hour',
                                        'minutes_key' => 'ticket_end_time_minute',
                                        'ampm_key' => 'ticket_end_time_ampm',
                                    )); ?>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="mec-form-row <?php echo $basic_class; ?>">
                                <textarea type="text" class="mec-col-11"
                                          name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][description]"
                                          placeholder="<?php esc_attr_e('Description', 'mec'); ?>"><?php echo(isset($ticket['description']) ? esc_textarea($ticket['description']) : ''); ?></textarea>
                        </div>
                        <?php if($private_description_status): ?>
                            <div class="mec-form-row <?php echo $advanced_class; ?>">
                                <textarea type="text" class="mec-col-11"
                                          name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][private_description]"
                                          placeholder="<?php esc_attr_e('Private Description', 'mec'); ?>"><?php echo(isset($ticket['private_description']) ? esc_textarea($ticket['private_description']) : ''); ?></textarea>
                                <span class="mec-tooltip">
                                    <div class="box top">
                                        <h5 class="title"><?php esc_html_e('Private Description', 'mec'); ?></h5>
                                        <div class="content"><p><?php esc_attr_e("The value can be displayed on the email notifications by placing the %%ticket_private_description%% placeholder into the email content.", 'mec'); ?></p></div>
                                    </div>
                                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                                </span>
                            </div>
                        <?php endif; ?>
                        <div class="mec-form-row <?php echo $basic_class; ?>">
                                <span class="mec-col-4">
                                    <input type="number" min="0" step="0.01" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][price]"
                                           placeholder="<?php esc_attr_e('Price', 'mec'); ?>"
                                           value="<?php echo ((isset($ticket['price']) and trim($ticket['price'])) ? esc_attr($ticket['price']) : 0); ?>"/>
                                    <span class="mec-tooltip">
                                        <div class="box top">
                                            <h5 class="title"><?php esc_html_e('Price', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e('Only numbers are allowed; Enter only the price without any symbols or characters. Enter 0 for free tickets.', 'mec'); ?>
                                                    <a href="https://webnus.net/dox/modern-events-calendar/add-a-booking-system/"
                                                       target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </span>
                            <span class="mec-col-8">
                                    <input type="text" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][price_label]"
                                           placeholder="<?php esc_attr_e('Price Label', 'mec'); ?>"
                                           value="<?php echo(isset($ticket['price_label']) ? esc_attr($ticket['price_label']) : ''); ?>"
                                           class="mec-col-12"/>
                                    <span class="mec-tooltip">
                                        <div class="box top">
                                            <h5 class="title"><?php esc_html_e('Price Label', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e('How shoould the price  be displayed in the booking module? Here you can insert the price with a currency symbol. e.g. $16', 'mec'); ?>
                                                    <a href="https://webnus.net/dox/modern-events-calendar/add-a-booking-system/"
                                                       target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </span>
                        </div>
                        <div class="mec-form-row <?php echo $basic_class; ?>">
                            <div class="mec-col-10">
                                <input class="mec-col-4 mec-available-tickets" type="text" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][limit]"
                                       placeholder="<?php esc_attr_e('Available Tickets', 'mec'); ?>"
                                       value="<?php echo (isset($ticket['limit']) ? esc_attr($ticket['limit']) : '100'); ?>"/>
                                <label class="mec-col-3 label-checkbox" for="mec_tickets_unlimited_<?php echo esc_attr($key); ?>"
                                       id="mec_bookings_limit_unlimited_label<?php echo esc_attr($key); ?>">
                                    <input type="hidden" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][unlimited]" value="0"/>
                                    <input id="mec_tickets_unlimited_<?php echo esc_attr($key); ?>" type="checkbox" value="1"
                                           name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][unlimited]"
                                        <?php
                                        if (isset($ticket['unlimited']) and $ticket['unlimited']) {
                                            echo 'checked="checked"';
                                        }
                                        ?>
                                    />
                                    <?php esc_html_e('Unlimited', 'mec'); ?>
                                </label>
                                <?php if($family_ticket_status): ?>
                                    <input class="mec-col-4 mec-ticket-number-of-seats" type="number" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][seats]"
                                           placeholder="<?php esc_attr_e('Number of Seats', 'mec'); ?>"
                                           value="<?php echo (isset($ticket['seats']) ? (int) esc_attr($ticket['seats']) : '1'); ?>" min="0" step="1"/>
                                    <span class="mec-tooltip">
                                        <div class="box top">
                                            <h5 class="title"><?php esc_html_e('Number of Seats', 'mec'); ?></h5>
                                            <div class="content">
                                                <p><?php esc_attr_e('The number of seats that take off from the total availability when booked. If you are creating a family ticket for 4 people then you can set it to 4.', 'mec'); ?></p>
                                            </div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                <?php else: ?>
                                    <input type="hidden" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][seats]" value="1"/>
                                <?php endif; ?>
                            </div>
                        </div>
                        <div class="mec-form-row <?php echo $advanced_class; ?>">
                            <div class="mec-col-4">
                                <input type="number" min="0" step="1" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][minimum_ticket]" value="<?php echo (isset($ticket['minimum_ticket']) ? esc_attr($ticket['minimum_ticket']) : '0'); ?>" placeholder="<?php esc_html_e('Minimum Ticket e.g. 3', 'mec'); ?>">
                                <span class="mec-tooltip">
                                        <div class="box top">
                                            <h5 class="title"><?php esc_html_e('Minimum Ticket', 'mec'); ?></h5>
                                            <div class="content">
                                                <p><?php esc_attr_e('The minimum number of tickets a user needs to book.', 'mec'); ?></p>
                                            </div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                            </div>
                            <div class="mec-col-4">
                                <input type="number" min="0" step="1" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][maximum_ticket]" value="<?php echo (isset($ticket['maximum_ticket']) ? esc_attr($ticket['maximum_ticket']) : ''); ?>" placeholder="<?php esc_html_e('Maximum Ticket e.g. 1', 'mec'); ?>">
                                <span class="mec-tooltip">
                                        <div class="box top">
                                            <h5 class="title"><?php esc_html_e('Maximum Ticket', 'mec'); ?></h5>
                                            <div class="content">
                                                <p><?php esc_attr_e('The maximum number of tickets a user can book.', 'mec'); ?></p>
                                            </div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                            </div>
                        </div>
                        <div class="mec-form-row <?php echo $advanced_class; ?>">
                            <?php ob_start(); ?>
                            <input type="number" class="mec-stop-selling-tickets" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][stop_selling_value]" value="<?php echo((isset($ticket['stop_selling_value']) and trim($ticket['stop_selling_value'])) ? esc_attr($ticket['stop_selling_value']) : '0'); ?>" placeholder="<?php esc_html_e('e.g. 0', 'mec'); ?>">
                            <select name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][stop_selling_type]">
                                <option value="day" <?php echo(isset($ticket['stop_selling_type']) and trim($ticket['stop_selling_type']) == 'day') ? 'selected="selected"' : ''; ?>><?php esc_html_e("Day", "mec"); ?></option>
                                <option value="hour" <?php echo(isset($ticket['stop_selling_type']) and trim($ticket['stop_selling_type']) == 'hour') ? 'selected="selected"' : ''; ?>><?php esc_html_e("Hour", "mec"); ?></option>
                            </select>
                            <?php echo sprintf(
                                esc_html__('%s Stop selling ticket %s %s %s before event start. %s', 'mec'),
                                '<span class="mec-label">',
                                '</span>',
                                ob_get_clean(),
                                '<span class="mec-label">',
                                '</span>'
                            ); ?>
                        </div>
                        <div class="<?php echo $advanced_class; ?>">
                            <?php do_action('custom_field_ticket', $ticket, $key); ?>
                        </div>
                        <?php if($price_per_date_display): ?>
                        <div id="mec_price_per_dates_container" class="<?php echo $advanced_class; ?>">
                            <div class="mec-form-row">
                                <h5><?php esc_html_e('Price per Date', 'mec'); ?></h5>
                                <button class="button mec_add_price_date_button" type="button"
                                        data-key="<?php echo esc_attr($key); ?>"><?php esc_html_e('Add', 'mec'); ?></button>
                            </div>
                            <div id="mec-ticket-price-dates-<?php echo esc_attr($key); ?>">
                                <?php $j = 0; if(isset($ticket['dates']) and count($ticket['dates'])) : ?>
                                    <?php
                                    foreach ($ticket['dates'] as $p => $price_date) :
                                        if (!is_numeric($p)) {
                                            continue;
                                        }
                                        $j = max($j, $p);
                                        ?>
                                        <div id="mec_ticket_price_raw_<?php echo esc_attr($key); ?>_<?php echo esc_attr($p); ?>">
                                            <div class="mec-form-row">
                                                <input class="mec-col-2 mec_date_picker_dynamic_format" type="text"
                                                       name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][<?php echo esc_attr($p); ?>][start]"
                                                       value="<?php echo isset($price_date['start']) ? esc_attr(\MEC\Base::get_main()->standardize_format($price_date['start'], $datepicker_format)) : esc_attr(\MEC\Base::get_main()->standardize_format(date('Y-m-d'), $datepicker_format)); ?>"
                                                       placeholder="<?php esc_attr_e('Start', 'mec'); ?>"/>
                                                <input class="mec-col-2 mec_date_picker_dynamic_format" type="text"
                                                       name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][<?php echo esc_attr($p); ?>][end]"
                                                       value="<?php echo isset($price_date['end']) ? esc_attr(\MEC\Base::get_main()->standardize_format($price_date['end'], $datepicker_format)) : esc_attr(\MEC\Base::get_main()->standardize_format(date('Y-m-d', strtotime( '+10 days')), $datepicker_format)); ?>"
                                                       placeholder="<?php esc_attr_e('End', 'mec'); ?>"/>
                                                <input class="mec-col-3" type="number"
                                                       name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][<?php echo esc_attr($p); ?>][price]"
                                                       value="<?php echo isset($price_date['price']) ? esc_attr($price_date['price']) : ''; ?>"
                                                       placeholder="<?php esc_attr_e('Price', 'mec'); ?>" min="0" step="0.01"/>
                                                <input class="mec-col-3" type="text"
                                                       name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][<?php echo esc_attr($p); ?>][label]"
                                                       value="<?php echo isset($price_date['label']) ? esc_attr($price_date['label']) : ''; ?>"
                                                       placeholder="<?php esc_attr_e('Label', 'mec'); ?>"/>
                                                <button class="button mec_ticket_price_remove_button mec-dash-remove-btn" type="button"
                                                        onclick="mec_ticket_price_remove(<?php echo esc_attr($key); ?>, <?php echo esc_attr($p); ?>)"><?php esc_html_e('Remove', 'mec'); ?></button>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>
                            <input type="hidden" id="mec_new_ticket_price_key_<?php echo esc_attr($key); ?>"
                                   value="<?php echo ($j + 1); ?>"/>
                            <div class="mec-util-hidden mec_new_ticket_price_raw" id="mec_new_ticket_price_raw_<?php echo esc_attr($key); ?>">
                                <div id="mec_ticket_price_raw_<?php echo esc_attr($key); ?>_:j:">
                                    <div class="mec-form-row">
                                        <input class="mec-col-2 new_added" type="text"
                                               name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][:j:][start]"
                                               value="<?php echo esc_attr(\MEC\Base::get_main()->standardize_format( date( 'Y-m-d' ), $datepicker_format )); ?>"
                                               placeholder="<?php esc_attr_e('Start', 'mec'); ?>"/>
                                        <input class="mec-col-2 new_added" type="text"
                                               name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][:j:][end]"
                                               value="<?php echo esc_attr(\MEC\Base::get_main()->standardize_format( date( 'Y-m-d', strtotime( '+10 days' ) ), $datepicker_format )); ?>"
                                               placeholder="<?php esc_attr_e('End', 'mec'); ?>"/>
                                        <input class="mec-col-3" type="number"
                                               name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][:j:][price]"
                                               placeholder="<?php esc_attr_e('Price', 'mec'); ?>" min="0" step="0.01"/>
                                        <input class="mec-col-3" type="text"
                                               name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][dates][:j:][label]"
                                               placeholder="<?php esc_attr_e('Label', 'mec'); ?>"/>
                                        <button class="button mec_ticket_price_remove_button mec-dash-remove-btn" type="button"
                                                onclick="mec_ticket_price_remove(<?php echo esc_attr($key); ?>, :j:)"><?php esc_html_e('Remove', 'mec'); ?></button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>

                        <?php if($variations_per_ticket_status): ?>
                            <?php
                            $event_inheritance = $ticket['variations_event_inheritance'] ?? 1;
                            if(trim($event_inheritance) == '') $event_inheritance = 1;

                            // Ticket Variations Object
                            $TicketVariations = $main->getTicketVariations();
                            ?>
                            <div id="mec_variations_per_ticket_container" class="<?php echo $advanced_class; ?>">
                                <div class="mec-form-row">
                                    <h4><?php esc_html_e('Variations Per Ticket', 'mec'); ?></h4>
                                    <div id="mec_variations_per_ticket_form<?php echo esc_attr($key); ?>">
                                        <div class="mec-form-row">
                                            <label class="label-checkbox">
                                                <input type="hidden" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][variations_event_inheritance]" value="0"/>
                                                <input onchange="jQuery('#mec_variations_per_ticket_container_toggle<?php echo esc_attr($key); ?>').toggle();" value="1" type="checkbox" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][variations_event_inheritance]" <?php echo ($event_inheritance ? 'checked="checked"' : ''); ?>> <?php esc_html_e('Inherit from event options', 'mec'); ?>
                                            </label>
                                        </div>
                                        <div id="mec_variations_per_ticket_container_toggle<?php echo esc_attr($key); ?>" class="<?php echo ($event_inheritance ? 'mec-util-hidden' : ''); ?>">
                                            <div class="mec-form-row">
                                                <button class="button mec_add_variation_per_ticket_button" type="button" id="mec_add_variation_per_ticket_button<?php echo esc_attr($key); ?>" onclick="add_variation_per_ticket(<?php echo esc_attr($key); ?>);"><?php esc_html_e('Add', 'mec'); ?></button>
                                            </div>
                                            <div id="mec_ticket_variations_list<?php echo esc_attr($key); ?>">
                                                <?php
                                                $ticket_variations = ((isset($ticket['variations']) and is_array($ticket['variations'])) ? $ticket['variations'] : array());
                                                foreach($ticket_variations as $tvk => $ticket_variation)
                                                {
                                                    if(!is_numeric($tvk)) continue;

                                                    $tvi = max($tvi, $tvk);
                                                    $TicketVariations->item(array(
                                                        'name_prefix' => $name_prefix.'['.esc_attr($key).'][variations]',
                                                        'id_prefix' => 'variation_per_ticket'.esc_attr($key),
                                                        'i' => $tvi,
                                                        'value' => $ticket_variation,
                                                    ));
                                                }
                                                ?>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mec-util-hidden" id="mec_new_variation_per_ticket_raw<?php echo esc_attr($key); ?>">
                                        <?php
                                        $TicketVariations->item(array(
                                            'name_prefix' => $name_prefix.'['.esc_attr($key).'][variations]',
                                            'id_prefix' => 'variation_per_ticket'.esc_attr($key),
                                            'i' => ':v:',
                                            'value' => array(),
                                        ));
                                        ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                        <?php if($availability_dates_status): ?>
                            <?php
                                $availability_start = $ticket['availability_start'] ?? '';
                                $availability_end = $ticket['availability_end'] ?? '';

                                if(trim($availability_start) && !trim($availability_end)) $availability_start = '';
                                if(trim($availability_end) && !trim($availability_start)) $availability_end = '';
                            ?>
                        <div id="mec_ticket_availability_dates_container" class="<?php echo $advanced_class; ?>">
                            <div class="mec-form-row">
                                <h5><?php esc_html_e('Availability Date', 'mec'); ?></h5>
                                <p class="description"><?php esc_html_e('If you leave the following fields empty then the ticket will be available at any time.'); ?></p><br />
                                <p class="description" style="color:red"><?php esc_html_e('Please note that this is just a timeframe, and if your events or occurrences fall within this period, the ticket will be displayed.'); ?></p>
                                <div>
                                    <input title="<?php esc_attr_e('Availability Start', 'mec'); ?>" placeholder="<?php esc_attr_e('Availability Start', 'mec'); ?>" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][availability_start]" value="<?php echo $availability_start; ?>" type="text" class="mec-date-picker-start">
                                    <input title="<?php esc_attr_e('Availability End', 'mec'); ?>" placeholder="<?php esc_attr_e('Availability End', 'mec'); ?>" name="<?php echo $name_prefix; ?>[<?php echo esc_attr($key); ?>][availability_end]" value="<?php echo $availability_end; ?>" type="text" class="mec-date-picker-end">
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                    <?php
                }
                ?>
            </div>
            <input type="hidden" id="mec_new_variation_per_ticket_key" value="<?php echo ($tvi + 1); ?>"/>
        </div>
        <input type="hidden" id="mec_new_ticket_key" value="<?php echo ($i + 1); ?>"/>
        <div class="mec-util-hidden" id="mec_new_ticket_raw">
            <div class="mec-box mec_ticket_row" id="mec_ticket_row:i:">
                <button class="button remove mec_ticket_remove_button" type="button" onclick="mec_ticket_remove(:i:);"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true" focusable="false" width="1em" height="1em" style="-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); transform: rotate(360deg);" preserveAspectRatio="xMidYMid meet" viewBox="0 0 20 20"><path d="M14.95 6.46L11.41 10l3.54 3.54l-1.41 1.41L10 11.42l-3.53 3.53l-1.42-1.42L8.58 10L5.05 6.47l1.42-1.42L10 8.58l3.54-3.53z"/></svg></button>
                <div class="mec-ticket-id" title="<?php esc_attr_e('Ticket ID', 'mec'); ?>"><span class="mec-ticket-id-title"><?php esc_attr_e('ID', 'mec'); ?>: </span>:i:</div>
                <div class="mec-form-row <?php echo $basic_class; ?>">
                    <input class="mec-col-12" type="text" name="<?php echo $name_prefix; ?>[:i:][name]"
                           placeholder="<?php esc_attr_e('Ticket Name', 'mec'); ?>"/>
                </div>
                <div class="<?php echo $advanced_class; ?>">
                    <?php do_action('mec_ticket_properties', ':i:', [], $object_id); ?>
                </div>
                <?php if($ticket_times_status): ?>
                    <div class="mec-form-row wn-ticket-time <?php echo $advanced_class; ?>">
                        <div class="mec-ticket-start-time mec-col-12">
                            <span class="mec-ticket-time mec-label"><?php esc_html_e('Start Time', 'mec'); ?></span>
                            <?php $main->timepicker(array(
                                'method' => ($settings['time_format'] ?? 12),
                                'time_hour' => 8,
                                'time_minutes' => 0,
                                'time_ampm' => 'AM',
                                'name' => $name_prefix.'[:i:]',
                                'hour_key' => 'ticket_start_time_hour',
                                'minutes_key' => 'ticket_start_time_minute',
                                'ampm_key' => 'ticket_start_time_ampm',
                                'include_h0' => true,
                            )); ?>
                        </div>
                        <div class="mec-ticket-end-time mec-ticket-start-time mec-col-12">
                            <span class="mec-ticket-time mec-label"><?php esc_html_e('End Time', 'mec'); ?></span>
                            <?php $main->timepicker(array(
                                'method' => ($settings['time_format'] ?? 12),
                                'time_hour' => 6,
                                'time_minutes' => 0,
                                'time_ampm' => 'PM',
                                'name' => $name_prefix.'[:i:]',
                                'hour_key' => 'ticket_end_time_hour',
                                'minutes_key' => 'ticket_end_time_minute',
                                'ampm_key' => 'ticket_end_time_ampm',
                            )); ?>
                        </div>
                    </div>
                <?php endif; ?>
                <div class="mec-form-row <?php echo $basic_class; ?>">
                        <textarea class="mec-col-11" type="text" name="<?php echo $name_prefix; ?>[:i:][description]"
                                  placeholder="<?php esc_attr_e('Description', 'mec'); ?>"></textarea>
                </div>
                <?php if($private_description_status): ?>
                    <div class="mec-form-row <?php echo $advanced_class; ?>">
                        <textarea type="text" class="mec-col-11" name="<?php echo $name_prefix; ?>[:i:][private_description]"
                                  placeholder="<?php esc_attr_e('Private Description', 'mec'); ?>"></textarea>
                        <span class="mec-tooltip">
                            <div class="box top">
                                <h5 class="title"><?php esc_html_e('Private Description', 'mec'); ?></h5>
                                <div class="content"><p><?php esc_attr_e("The value can be displayed on the email notifications by placing the %%ticket_private_description%% placeholder into the email content.", 'mec'); ?></p></div>
                            </div>
                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                        </span>
                    </div>
                <?php endif; ?>
                <div class="mec-form-row <?php echo $basic_class; ?>">
						<span class="mec-col-4">
							<input type="number" min="0" step="0.01" name="<?php echo $name_prefix; ?>[:i:][price]" placeholder="<?php esc_attr_e('Price', 'mec'); ?>" value="0">
							<span class="mec-tooltip">
								<div class="box top">
									<h5 class="title"><?php esc_html_e('Price', 'mec'); ?></h5>
									<div class="content"><p><?php esc_attr_e('Only numbers are allowed; Enter only the price without any symbols or characters. Enter 0 for free tickets.', 'mec'); ?>
                                            <a href="https://webnus.net/dox/modern-events-calendar/add-a-booking-system/"
                                               target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
								</div>
								<i title="" class="dashicons-before dashicons-editor-help"></i>
							</span>
						</span>
                    <span class="mec-col-8">
							<input type="text" name="<?php echo $name_prefix; ?>[:i:][price_label]" placeholder="<?php esc_attr_e('Price Label', 'mec'); ?>" class="mec-col-12">
							<span class="mec-tooltip">
								<div class="box top">
									<h5 class="title"><?php esc_html_e('Price Label', 'mec'); ?></h5>
									<div class="content"><p><?php esc_attr_e('How should the price  be displayed in the booking module? Here you can insert the price with a currency symbol. e.g. $16', 'mec'); ?>
                                            <a href="https://webnus.net/dox/modern-events-calendar/add-a-booking-system/"
                                               target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
								</div>
								<i title="" class="dashicons-before dashicons-editor-help"></i>
							</span>
						</span>
                </div>
                <div class="mec-form-row <?php echo $basic_class; ?>">
                    <div class="mec-col-10">
                        <input class="mec-col-4 mec-available-tickets" type="text" name="<?php echo $name_prefix; ?>[:i:][limit]"
                               placeholder="<?php esc_attr_e('Available Tickets', 'mec'); ?>"/>
                        <label class="mec-col-3 label-checkbox" for="mec_tickets_unlimited_:i:"
                               id="mec_bookings_limit_unlimited_label">
                            <input type="hidden" name="<?php echo $name_prefix; ?>[:i:][unlimited]" value="0"/>
                            <input id="mec_tickets_unlimited_:i:" type="checkbox" value="1"
                                   name="<?php echo $name_prefix; ?>[:i:][unlimited]"/>
                            <?php esc_html_e('Unlimited', 'mec'); ?>
                        </label>
                        <?php if($family_ticket_status): ?>
                            <input class="mec-col-4 mec-ticket-number-of-seats" type="number" name="<?php echo $name_prefix; ?>[:i:][seats]"
                                   placeholder="<?php esc_attr_e('Number of Seats', 'mec'); ?>"
                                   value="1" min="0" step="1"/>
                            <span class="mec-tooltip">
                                <div class="box top">
                                    <h5 class="title"><?php esc_html_e('Number of Seats', 'mec'); ?></h5>
                                    <div class="content">
                                        <p><?php esc_attr_e('The number of seats that take off from the total availability when booked. If you are creating a family ticket for 4 people then you can set it to 4.', 'mec'); ?></p>
                                    </div>
                                </div>
                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                            </span>
                        <?php else: ?>
                            <input type="hidden" name="<?php echo $name_prefix; ?>[:i:][seats]" value="1"/>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="mec-form-row <?php echo $advanced_class; ?>">
                    <div class="mec-col-4">
                        <input type="number" min="0" step="1" name="<?php echo $name_prefix; ?>[:i:][minimum_ticket]" value="1" placeholder="<?php esc_html_e('Minimum Ticket e.g. 3', 'mec'); ?>">
                        <span class="mec-tooltip">
                                <div class="box top">
                                    <h5 class="title"><?php esc_html_e('Minimum Ticket', 'mec'); ?></h5>
                                    <div class="content">
                                        <p><?php esc_attr_e('The minimum number of tickets  a user needs to book.', 'mec'); ?></p>
                                    </div>
                                </div>
                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                            </span>
                    </div>
                    <div class="mec-col-4">
                        <input type="number" min="0" step="1" name="<?php echo $name_prefix; ?>[:i:][maximum_ticket]" value="" placeholder="<?php esc_html_e('Maximum Ticket e.g. 1', 'mec'); ?>">
                        <span class="mec-tooltip">
                                <div class="box top">
                                    <h5 class="title"><?php esc_html_e('Maximum Ticket', 'mec'); ?></h5>
                                    <div class="content">
                                        <p><?php esc_attr_e('The maximum number of tickets a user can book.', 'mec'); ?></p>
                                    </div>
                                </div>
                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                            </span>
                    </div>
                </div>
                <div class="mec-form-row <?php echo $advanced_class; ?>">
                    <?php ob_start(); ?>
                    <input type="number" class="mec-stop-selling-tickets" name="<?php echo $name_prefix; ?>[:i:][stop_selling_value]" value="0" placeholder="<?php esc_html_e('e.g. 0', 'mec'); ?>">
                    <select name="<?php echo $name_prefix; ?>[:i:][stop_selling_type]">
                        <option value="day"><?php esc_html_e("Day", "mec"); ?></option>
                        <option value="hour"><?php esc_html_e("Hour", "mec"); ?></option>
                    </select>
                    <?php echo sprintf(
                        esc_html__('%s Stop selling ticket %s %s %s before event start. %s', 'mec'),
                        '<span class="mec-label">',
                        '</span>',
                        ob_get_clean(),
                        '<span class="mec-label">',
                        '</span>'
                    ); ?>
                </div>
                <div class="<?php echo $advanced_class; ?>">
                    <?php do_action('custom_field_dynamic_ticket'); ?>
                </div>
                <?php if($price_per_date_display): ?>
                <div id="mec_price_per_dates_container_:i:" class="<?php echo $advanced_class; ?>">
                    <div class="mec-form-row">
                        <h4><?php esc_html_e('Price per Date', 'mec'); ?></h4>
                        <button class="button mec_add_price_date_button" type="button"
                                data-key=":i:"><?php esc_html_e('Add', 'mec'); ?></button>
                    </div>
                    <div id="mec-ticket-price-dates-:i:">
                    </div>
                    <input type="hidden" id="mec_new_ticket_price_key_:i:" value="1"/>
                    <div class="mec-util-hidden" id="mec_new_ticket_price_raw_:i:">
                        <div id="mec_ticket_price_raw_:i:_:j:">
                            <div class="mec-form-row">
                                <input class="mec-col-2 new_added" type="text"
                                       name="<?php echo $name_prefix; ?>[:i:][dates][:j:][start]"
                                       value="<?php echo esc_attr($main->standardize_format(date('Y-m-d'), $datepicker_format)); ?>"
                                       placeholder="<?php esc_attr_e('Start', 'mec'); ?>"/>
                                <input class="mec-col-2 new_added" type="text"
                                       name="<?php echo $name_prefix; ?>[:i:][dates][:j:][end]"
                                       value="<?php echo esc_attr($main->standardize_format(date('Y-m-d', strtotime('+10 days')), $datepicker_format)); ?>"
                                       placeholder="<?php esc_attr_e('End', 'mec'); ?>"/>
                                <input class="mec-col-3" type="number" name="<?php echo $name_prefix; ?>[:i:][dates][:j:][price]"
                                       placeholder="<?php esc_attr_e('Price', 'mec'); ?>" min="0" step="0.01"/>
                                <input class="mec-col-3" type="text" name="<?php echo $name_prefix; ?>[:i:][dates][:j:][label]"
                                       placeholder="<?php esc_attr_e('Label', 'mec'); ?>"/>
                                <button class="button mec_ticket_price_remove_button mec-dash-remove-btn" type="button"
                                        onclick="mec_ticket_price_remove(:i:, :j:)"><?php esc_html_e('Remove', 'mec'); ?></button>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <?php if($variations_per_ticket_status): ?>
                    <?php
                    // Ticket Variations Object
                    $TicketVariations = $main->getTicketVariations();
                    ?>
                    <div id="mec_variations_per_ticket_container" class="<?php echo $advanced_class; ?>">
                        <div class="mec-form-row">
                            <h4><?php esc_html_e('Variations Per Ticket', 'mec'); ?></h4>
                            <div id="mec_variations_per_ticket_form:i:">
                                <div class="mec-form-row">
                                    <label class="label-checkbox">
                                        <input type="hidden" name="<?php echo $name_prefix; ?>[:i:][variations_event_inheritance]" value="0"/>
                                        <input onchange="jQuery('#mec_variations_per_ticket_container_toggle:i:').toggle();" value="1" type="checkbox" name="<?php echo $name_prefix; ?>[:i:][variations_event_inheritance]" checked="checked"> <?php esc_html_e('Inherit from event options', 'mec'); ?>
                                    </label>
                                </div>
                                <div id="mec_variations_per_ticket_container_toggle:i:" class="mec-util-hidden">
                                    <div class="mec-form-row">
                                        <button class="button mec_add_variation_per_ticket_button" type="button" id="mec_add_variation_per_ticket_button:i:" onclick="add_variation_per_ticket(:i:);"><?php esc_html_e('Add', 'mec'); ?></button>
                                    </div>
                                    <div id="mec_ticket_variations_list:i:"></div>
                                </div>
                            </div>
                            <input type="hidden" id="mec_new_variation_per_ticket_key:i:" value="1"/>
                            <div class="mec-util-hidden" id="mec_new_variation_per_ticket_raw:i:">
                                <?php
                                $TicketVariations->item(array(
                                    'name_prefix' => $name_prefix.'[:i:][variations]',
                                    'id_prefix' => 'variation_per_ticket:i:',
                                    'i' => ':v:',
                                    'value' => array(),
                                ));
                                ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if($availability_dates_status): ?>
                    <div id="mec_ticket_availability_dates_container" class="<?php echo $advanced_class; ?>">
                        <div class="mec-form-row">
                            <h5><?php esc_html_e('Availability Date', 'mec'); ?></h5>
                            <p class="description"><?php esc_html_e('If you leave the following fields empty then the ticket will be available at any time.'); ?></p><br />
                            <p class="description" style="color:red"><?php esc_html_e('Please note that this is just a timeframe, and if your events or occurrences fall within this period, the ticket will be displayed.'); ?></p>
                            <div>
                                <input title="<?php esc_attr_e('Availability Start', 'mec'); ?>" placeholder="<?php esc_attr_e('Availability Start', 'mec'); ?>" name="<?php echo $name_prefix; ?>[:i:][availability_start]" value="" type="text" class="mec-date-picker-start">
                                <input title="<?php esc_attr_e('Availability End', 'mec'); ?>" placeholder="<?php esc_attr_e('Availability End', 'mec'); ?>" name="<?php echo $name_prefix; ?>[:i:][availability_end]" value="" type="text" class="mec-date-picker-end">
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }
}