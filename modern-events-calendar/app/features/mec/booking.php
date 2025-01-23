<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_feature_mec $this */

$multilingual = $this->main->is_multilingual();
$locale = $this->main->get_backend_active_locale();

$settings = $this->main->get_settings();
$ml_settings = $this->main->get_ml_settings(NULL, $locale);

$fees = $settings['fees'] ?? [];
$ticket_variations = $settings['ticket_variations'] ?? [];

// WordPress Pages
$pages = get_pages();

// User Roles
$roles = array_reverse(wp_roles()->roles);

$bfixed_fields = $this->main->get_bfixed_fields();
if(!is_array($bfixed_fields)) $bfixed_fields = [];

// Booking form
$mec_email  = false;
$mec_name   = false;

$reg_fields = $this->main->get_reg_fields();
if(!is_array($reg_fields)) $reg_fields = [];

foreach($reg_fields as $field)
{
	if(isset($field['type']))
	{
		if($field['type'] == 'name') $mec_name = true;
		if($field['type'] == 'mec_email') $mec_email = true;
	}
	else break;
}

if(!$mec_name)
{
	array_unshift(
		$reg_fields,
		array(
			'mandatory' => '0',
			'type'      => 'name',
			'label'     => esc_html__('Name', 'mec'),
        )
	);
}

if(!$mec_email)
{
	array_unshift(
		$reg_fields,
		array(
			'mandatory' => '0',
			'type'      => 'mec_email',
			'label'     => esc_html__('Email', 'mec'),
        )
	);
}

// Payment Gateways
$gateways = $this->main->get_gateways();
$gateways_options = $this->main->get_gateways_options();
?>
<div class="wns-be-container wns-be-container-sticky">
    <div id="wns-be-infobar">
        <div class="mec-search-settings-wrap">
            <i class="mec-sl-magnifier"></i>
            <input id="mec-search-settings" type="text" title="" placeholder="<?php esc_html_e('Search...', 'mec'); ?>">
        </div>
        <a id="" class="dpr-btn dpr-save-btn"><?php esc_html_e('Save Changes', 'mec'); ?></a>
    </div>

    <div class="wns-be-sidebar">
        <?php $this->main->get_sidebar_menu('booking'); ?>
    </div>

    <div class="wns-be-main">
        <div id="wns-be-notification"></div>
        <div id="wns-be-content">
            <div class="wns-be-group-tab">
                <div class="mec-container">

                    <form id="mec_booking_form">

                        <div id="booking_option" class="mec-options-fields active">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Booking', 'mec'); ?></h4>

                            <?php if(!$this->main->getPRO()): ?>
                            <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                            <?php else: ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][booking_status]" value="0" />
                                    <input onchange="jQuery('#mec_booking_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][booking_status]" <?php if(isset($settings['booking_status']) and $settings['booking_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable booking module', 'mec'); ?>
                                </label>
                                <p><?php esc_attr_e("After enabling and saving the settings, reloading the page will add 'payment Gateways' to the settings and a new menu item on the Dashboard", 'mec'); ?></p>
                            </div>
                            <div id="mec_booking_container_toggle" class="<?php if((isset($settings['booking_status']) and !$settings['booking_status']) or !isset($settings['booking_status'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-backend-tab-wrap mec-basvanced-toggle" data-for="#mec_booking_container_toggle">
                                    <div class="mec-backend-tab">
                                        <div class="mec-backend-tab-item mec-b-active-tab"><?php esc_html_e('Basic', 'mec'); ?></div>
                                        <div class="mec-backend-tab-item"><?php esc_html_e('Advanced', 'mec'); ?></div>
                                    </div>
                                </div>
                                <div class="mec-basvanced-basic">
                                    <h5 class="title"><?php esc_html_e('Date Options', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_date_format1"><?php esc_html_e('Date Format', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="text" id="mec_settings_booking_date_format1" name="mec[settings][booking_date_format1]" value="<?php echo ((isset($ml_settings['booking_date_format1']) and trim($ml_settings['booking_date_format1']) != '') ? $ml_settings['booking_date_format1'] : 'Y-m-d'); ?>" />
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Date Format', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Specify the date format of the event's date on the booking module.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#1-_Date_Options/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_maximum_dates"><?php esc_html_e('Maximum Dates', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="number" id="mec_settings_booking_maximum_dates" name="mec[settings][booking_maximum_dates]" value="<?php echo ((isset($settings['booking_maximum_dates']) and trim($settings['booking_maximum_dates']) != '') ? $settings['booking_maximum_dates'] : '6'); ?>" placeholder="<?php esc_attr_e('Default is 6', 'mec'); ?>" min="1" max="100" step="1" />
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Maximum Dates', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Specify the number of dates available in the date selection dropdown menu for recurring events.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#1-_Date_Options/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <h5 class="title"><?php esc_html_e('Date Selection Options', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_date_selection"><?php esc_html_e('Date Selection', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_date_selection" name="mec[settings][booking_date_selection]">
                                                <option value="dropdown" <?php echo ((!isset($settings['booking_date_selection']) || $settings['booking_date_selection'] == 'dropdown') ? 'selected' : ''); ?>><?php esc_html_e('Dropdown', 'mec'); ?></option>
                                                <option value="calendar" <?php echo ((isset($settings['booking_date_selection']) && $settings['booking_date_selection'] == 'calendar') ? 'selected' : ''); ?>><?php esc_html_e('Calendar', 'mec'); ?></option>
                                                <option value="checkboxes" <?php echo ((isset($settings['booking_date_selection']) && $settings['booking_date_selection'] == 'checkboxes') ? 'selected' : ''); ?>><?php esc_html_e('Checkboxes', 'mec'); ?></option>
                                                <option value="express-calendar" <?php echo ((isset($settings['booking_date_selection']) && $settings['booking_date_selection'] == 'express-calendar') ? 'selected' : ''); ?>><?php esc_html_e('Express Calendar', 'mec'); ?></option>
                                            </select>
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Date Selection', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Specify the type of date selection field in the booking module.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#2-_Date_Selection_Options/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_omit_end_date"><?php esc_html_e('Omit End Date', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_omit_end_date" name="mec[settings][booking_omit_end_date]">
                                                <option value="0" <?php echo ((!isset($settings['booking_omit_end_date']) || $settings['booking_omit_end_date'] === '0') ? 'selected' : ''); ?>><?php esc_html_e('No', 'mec'); ?></option>
                                                <option value="1" <?php echo ((isset($settings['booking_omit_end_date']) && $settings['booking_omit_end_date'] === '1') ? 'selected' : ''); ?>><?php esc_html_e('If Possible', 'mec'); ?></option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_date_selection_per_event"><?php esc_html_e('Date Selection Per Event', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_date_selection_per_event" name="mec[settings][booking_date_selection_per_event]">
                                                <option value="0" <?php echo (!isset($settings['booking_date_selection_per_event']) || $settings['booking_date_selection_per_event'] == 0) ? 'selected' : ''; ?>><?php esc_html_e('No', 'mec'); ?></option>
                                                <option value="1" <?php echo (isset($settings['booking_date_selection_per_event']) && $settings['booking_date_selection_per_event'] == 1) ? 'selected' : ''; ?>><?php esc_html_e('Yes', 'mec'); ?></option>
                                            </select>
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Date Selection Per Event', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If enabled, you can change the date selection method per event.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <h5 class="title"><?php esc_html_e('Interval Options', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_show_booking_form_interval"><?php esc_html_e('Show Booking Form Interval', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="number" id="mec_settings_show_booking_form_interval" name="mec[settings][show_booking_form_interval]" value="<?php echo ((isset($settings['show_booking_form_interval']) and trim($settings['show_booking_form_interval']) != '0') ? $settings['show_booking_form_interval'] : '0'); ?>" placeholder="<?php esc_attr_e('Minutes (e.g 5)', 'mec'); ?>" />
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Show Booking Form Interval', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("You can show the booking form only at certain times before the event starts. If you set this option to 30 then the booking form will open only 30 minutes before starting the event! One day is 1440 minutes.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <h5 class="title"><?php esc_html_e('User Registration', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_registration"><?php esc_html_e('Registration', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_registration" name="mec[settings][booking_registration]" onchange="jQuery('#mec_settings_booking_registration_wrapper').toggleClass('w-hidden');">
                                                <option <?php echo ((isset($settings['booking_registration']) and $settings['booking_registration'] == '1') ? 'selected="selected"' : ''); ?> value="1"><?php echo esc_html__('Enabled', 'mec'); ?></option>
                                                <option <?php echo ((isset($settings['booking_registration']) and $settings['booking_registration'] == '0') ? 'selected="selected"' : ''); ?> value="0"><?php echo esc_html__('Disabled', 'mec'); ?></option>
                                            </select>
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Registration', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("By enabaling this option MEC will create a WordPress User for the main attendee. It's recommended to keep it enabled.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <div id="mec_settings_booking_registration_wrapper" class="<?php echo (!isset($settings['booking_registration']) || $settings['booking_registration']) ? "" : "w-hidden"; ?>">
                                        <div class="mec-form-row">
                                            <label class="mec-col-3" for="mec_settings_booking_user_role"><?php esc_html_e('User Role', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <select id="mec_settings_booking_user_role" name="mec[settings][booking_user_role]">
                                                    <option value="">----</option>
                                                    <?php foreach($roles as $role => $r): ?>
                                                        <option <?php echo ((isset($settings['booking_user_role']) and $settings['booking_user_role'] == $role) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($role); ?>"><?php echo esc_html($r['name']); ?></option>
                                                    <?php endforeach; ?>
                                                </select>
                                                <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('User Role', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("MEC creates a user for the main attendee after each booking. The default role of the user is subscriber but you can change it if needed.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#4-_User_Registration/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                            </div>
                                        </div>
                                        <div class="mec-form-row">
                                            <label class="mec-col-3" for="mec_settings_booking_userpass"><?php esc_html_e('Username & Password', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <select id="mec_settings_booking_userpass" name="mec[settings][booking_userpass]">
                                                    <option value="auto" <?php echo ((isset($settings['booking_userpass']) and trim($settings['booking_userpass']) == 'auto') ? 'selected="selected"' : ''); ?>><?php echo esc_html__('Auto', 'mec'); ?></option>
                                                    <option value="manual" <?php echo ((isset($settings['booking_userpass']) and trim($settings['booking_userpass']) == 'manual') ? 'selected="selected"' : ''); ?>><?php echo esc_html__('Manual', 'mec'); ?></option>
                                                </select>
                                                <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Username & Password', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If you set it to the manual option, users can insert a username and password during the booking for registration; otherwise, MEC will use their email and an auto-generated password.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                            </div>
                                        </div>
                                    </div>

                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Limitation', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_limit"><?php esc_html_e('Limit', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="number" id="mec_settings_booking_limit" name="mec[settings][booking_limit]" value="<?php echo ((isset($settings['booking_limit']) and trim($settings['booking_limit']) != '') ? $settings['booking_limit'] : ''); ?>" placeholder="<?php esc_attr_e('Default is empty', 'mec'); ?>" />
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Booking Limit', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("The total number of tickets that a user can book. It is useful if you're providing free tickets. Leave it empty for an unlimited booking.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_ip_restriction"><?php esc_html_e('IP restriction', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_ip_restriction" name="mec[settings][booking_ip_restriction]">
                                                <option value="1" <?php echo ((isset($settings['booking_ip_restriction']) and trim($settings['booking_ip_restriction']) == 1) ? 'selected="selected"' : ''); ?>><?php echo esc_html__('Enabled', 'mec'); ?></option>
                                                <option value="0" <?php echo ((isset($settings['booking_ip_restriction']) and trim($settings['booking_ip_restriction']) == 0) ? 'selected="selected"' : ''); ?>><?php echo esc_html__('Disabled', 'mec'); ?></option>
                                            </select>
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('IP restriction', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If you set a limit for the total tickets that users can book, MEC will use the IP and email to prevent users to book high tickets. You can disable the IP restriction if you don't need it.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_lock_prefilled"><?php esc_html_e('Lock Pre-filled Fields', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_lock_prefilled" name="mec[settings][booking_lock_prefilled]">
                                                <option value="0" <?php echo (isset($settings['booking_lock_prefilled']) and $settings['booking_lock_prefilled'] == '0') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Disabled', 'mec'); ?></option>
                                                <option value="1" <?php echo (isset($settings['booking_lock_prefilled']) and $settings['booking_lock_prefilled'] == '1') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Enabled', 'mec'); ?></option>
                                                <option value="2" <?php echo (isset($settings['booking_lock_prefilled']) and $settings['booking_lock_prefilled'] == '2') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Enabled Only for Main Attendee', 'mec'); ?></option>
                                            </select>
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Lock Pre-filled Fields', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("When users are logged in, the name and email fields will be pre-filled but users can change them. If you enable the lock, logged-in users cannot change the pre-filled fields.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#5-_Limitation/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                </div>
                                <div class="mec-basvanced-advanced w-hidden">
                                    <h5 class="title"><?php esc_html_e('General', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label for="mec_settings_booking_start_from_first_upcoming_date">
                                                <input type="hidden" name="mec[settings][booking_start_from_first_upcoming_date]" value="0" />
                                                <input type="checkbox" name="mec[settings][booking_start_from_first_upcoming_date]" id="mec_settings_booking_start_from_first_upcoming_date" <?php echo isset($settings['booking_start_from_first_upcoming_date']) && $settings['booking_start_from_first_upcoming_date'] == '1' ? 'checked="checked"' : ''; ?> value="1" />
                                                <?php esc_html_e('Start the dates in booking module from first upcoming date instead of referred date', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label for="mec_settings_booking_unique_emails">
                                                <input type="hidden" name="mec[settings][booking_unique_emails]" value="0" />
                                                <input type="checkbox" name="mec[settings][booking_unique_emails]" id="mec_settings_booking_unique_emails" <?php echo isset($settings['booking_unique_emails']) && $settings['booking_unique_emails'] == '1' ? 'checked="checked"' : ''; ?> value="1" />
                                                <?php esc_html_e('Do not accept duplicate emails in the attendees form', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                    <h5 class="title"><?php esc_html_e('Ticket Options', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label for="mec_settings_booking_family_ticket">
                                            <input type="hidden" name="mec[settings][booking_family_ticket]" value="0" />
                                            <input type="checkbox" name="mec[settings][booking_family_ticket]" id="mec_settings_booking_family_ticket" <?php echo ((isset($settings['booking_family_ticket']) and $settings['booking_family_ticket'] == '1') ? 'checked="checked"' : ''); ?> value="1" />
                                            <?php esc_html_e('Family Tickets', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box right">
                                                <h5 class="title"><?php esc_html_e('Family Tickets', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("By default all tickets are for selling one seat. By enabling family tickets you can create tickets with higher seats.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                    <div class="mec-form-row">
                                        <label for="mec_settings_booking_ticket_availability_dates">
                                            <input type="hidden" name="mec[settings][booking_ticket_availability_dates]" value="0" />
                                            <input type="checkbox" name="mec[settings][booking_ticket_availability_dates]" id="mec_settings_booking_ticket_availability_dates" <?php echo ((isset($settings['booking_ticket_availability_dates']) and $settings['booking_ticket_availability_dates'] == '1') ? 'checked="checked"' : ''); ?> value="1" />
                                            <?php esc_html_e('Availability Date', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box right">
                                                <h5 class="title"><?php esc_html_e('Availability Date', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("By default all tickets are available for all occurrences. By enabling availability date option you can set the tickets availability for certain dates.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Last Few Tickets Flag', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_last_few_tickets_percentage"><?php esc_html_e('Percentage', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="number" id="mec_settings_booking_last_few_tickets_percentage" name="mec[settings][booking_last_few_tickets_percentage]" value="<?php echo ((isset($settings['booking_last_few_tickets_percentage']) and trim($settings['booking_last_few_tickets_percentage']) != '') ? max($settings['booking_last_few_tickets_percentage'], 1) : '15'); ?>" placeholder="<?php esc_attr_e('Default is 15', 'mec'); ?>" min="1" max="100" step="1" />
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Last Few Tickets Percentage', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("MEC will show the \"Last Few Ticket\" flags on events when the remaning tickets are less than this percentage.", 'mec'); ?></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][last_few_tickets_percentage_per_event]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][last_few_tickets_percentage_per_event]" <?php if(isset($settings['last_few_tickets_percentage_per_event']) and $settings['last_few_tickets_percentage_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Ability to change last few tickets percentage per event', 'mec'); ?>
                                        </label>
                                    </div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Thank You Page', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_thankyou_page"><?php esc_html_e('Thank You Page', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_thankyou_page" name="mec[settings][booking_thankyou_page]">
                                                <option value="">----</option>
                                                <?php foreach($pages as $page): ?>
                                                    <option <?php echo ((isset($settings['booking_thankyou_page']) and $settings['booking_thankyou_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Thank You Page', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("The user will be redirected to this page after a successfull booking. Leave it empty if you are not intrested.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#3-_Thank_You_Page/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_thankyou_page_time"><?php esc_html_e('Thank You Page Time Interval', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="number" id="mec_settings_booking_thankyou_page_time" name="mec[settings][booking_thankyou_page_time]" value="<?php echo ((isset($settings['booking_thankyou_page_time']) and trim($settings['booking_thankyou_page_time']) != '0') ? $settings['booking_thankyou_page_time'] : '2000'); ?>" placeholder="<?php esc_attr_e('2000 mean 2 seconds', 'mec'); ?>" />
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Thank You Page Time Interval', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("Specify the amount of delay before being redirected to the thank you page. (in milliseconds)", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#3-_Thank_You_Page/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][thankyou_page_per_event]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][thankyou_page_per_event]" <?php if(isset($settings['thankyou_page_per_event']) and $settings['thankyou_page_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Ability to change thank you page per event', 'mec'); ?>
                                        </label>
                                    </div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Transaction ID', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_tid_generation_method"><?php esc_html_e('Generation Method', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_tid_generation_method" name="mec[settings][booking_tid_gen_method]" onchange="jQuery('#mec_settings_booking_tid_ordered_generation').toggleClass('mec-util-hidden');">
                                                <option <?php echo ((isset($settings['booking_tid_gen_method']) and $settings['booking_tid_gen_method'] == 'random') ? 'selected="selected"' : ''); ?> value="random"><?php echo esc_html__('Random', 'mec'); ?></option>
                                                <option <?php echo ((isset($settings['booking_tid_gen_method']) and $settings['booking_tid_gen_method'] == 'ordered') ? 'selected="selected"' : ''); ?> value="ordered"><?php echo esc_html__('Ordered Numbers', 'mec'); ?></option>
                                            </select>
                                        </div>
                                    </div>
                                    <div id="mec_settings_booking_tid_ordered_generation" class="<?php echo (!isset($settings['booking_tid_gen_method']) || $settings['booking_tid_gen_method'] == 'random') ? 'mec-util-hidden' : ''; ?>">
                                        <div class="mec-form-row">
                                            <label class="mec-col-3" for="mec_settings_booking_tid_start_from"><?php esc_html_e('Start From', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <input type="number" id="mec_settings_booking_tid_start_from" name="mec[settings][booking_tid_start_from]" value="<?php echo (isset($settings['booking_tid_start_from']) ? esc_attr($settings['booking_tid_start_from']) : 10000); ?>" min="1" step="1">
                                            </div>
                                        </div>
                                    </div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Simplify Booking Form', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_skip_step1"><?php esc_html_e('Skip Step 1', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_skip_step1" name="mec[settings][booking_skip_step1]">
                                                <option <?php echo ((isset($settings['booking_skip_step1']) and $settings['booking_skip_step1'] == '0') ? 'selected="selected"' : ''); ?> value="0"><?php echo esc_html__('Disabled', 'mec'); ?></option>
                                                <option <?php echo ((isset($settings['booking_skip_step1']) and $settings['booking_skip_step1'] == '1') ? 'selected="selected"' : ''); ?> value="1"><?php echo esc_html__('If Possible', 'mec'); ?></option>
                                            </select>
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Skip Step 1', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("If there is no choice for users in the first step of the booking module, this step will be skipped. In other words, if the event has only one date and the total user booking limit option is set to one, this step will be skipped.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#5-_Simplify_Booking_Form/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Who can book?', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label for="mec_settings_booking_wcb_all">
                                            <input type="hidden" name="mec[settings][booking_wcb_all]" value="0" />
                                            <input type="checkbox" name="mec[settings][booking_wcb_all]" id="mec_settings_booking_wcb_all" <?php echo (!isset($settings['booking_wcb_all']) || $settings['booking_wcb_all'] == '1') ? 'checked="checked"' : ''; ?> value="1" onchange="jQuery('#mec_settings_booking_booking_wcb_options').toggleClass('mec-util-hidden');" />
                                            <?php esc_html_e('All Users', 'mec'); ?>
                                        </label>
                                    </div>
                                    <div id="mec_settings_booking_booking_wcb_options" class="<?php echo (!isset($settings['booking_wcb_all']) || $settings['booking_wcb_all'] == '1') ? 'mec-util-hidden' : ''; ?>" style="margin: 0 0 40px 0; padding: 20px 20px 4px; border: 1px solid #ddd;">
                                        <?php foreach($roles as $role_key => $role): $wcb_value = $settings['booking_wcb_' . $role_key] ?? 1; ?>
                                            <div class="mec-form-row">
                                                <div class="mec-col-12">
                                                    <label for="mec_settings_booking_wcb_<?php echo esc_attr($role_key); ?>">
                                                        <input type="hidden" name="mec[settings][booking_wcb_<?php echo esc_attr($role_key); ?>]" value="0" />
                                                        <input type="checkbox" name="mec[settings][booking_wcb_<?php echo esc_attr($role_key); ?>]" id="mec_settings_booking_wcb_<?php echo esc_attr($role_key); ?>" <?php echo ((!isset($settings['booking_wcb_'.$role_key]) or (isset($settings['booking_wcb_'.$role_key]) and $settings['booking_wcb_'.$role_key] == '1')) ? 'checked="checked"' : ''); ?> value="1" />
                                                        <?php echo esc_html($role['name']); ?>
                                                    </label>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                    <?php do_action('add_booking_variables', $settings); ?>
                                </div>
                                <div class="mec-basvanced-basic">
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Email verification', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label for="mec_settings_booking_auto_verify_free">
                                                <input type="hidden" name="mec[settings][booking_auto_verify_free]" value="0" />
                                                <input type="checkbox" name="mec[settings][booking_auto_verify_free]" id="mec_settings_booking_auto_verify_free" <?php echo ((isset($settings['booking_auto_verify_free']) and $settings['booking_auto_verify_free'] == '1') ? 'checked="checked"' : ''); ?> value="1" />
                                                <?php esc_html_e('Auto verification for free bookings', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label for="mec_settings_booking_auto_verify_paid">
                                                <input type="hidden" name="mec[settings][booking_auto_verify_paid]" value="0" />
                                                <input type="checkbox" name="mec[settings][booking_auto_verify_paid]" id="mec_settings_booking_auto_verify_paid" <?php echo ((isset($settings['booking_auto_verify_paid']) and $settings['booking_auto_verify_paid'] == '1') ? 'checked="checked"' : ''); ?> value="1" />
                                                <?php esc_html_e('Auto verification for paid bookings', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Booking Confirmation', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label for="mec_settings_booking_auto_confirm_free">
                                                <input type="hidden" name="mec[settings][booking_auto_confirm_free]" value="0" />
                                                <input type="checkbox" name="mec[settings][booking_auto_confirm_free]" id="mec_settings_booking_auto_confirm_free" <?php echo ((isset($settings['booking_auto_confirm_free']) and $settings['booking_auto_confirm_free'] == '1') ? 'checked="checked"' : ''); ?> value="1" />
                                                <?php esc_html_e('Auto confirmation for free bookings', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label for="mec_settings_booking_auto_confirm_paid">
                                                <input type="hidden" name="mec[settings][booking_auto_confirm_paid]" value="0" />
                                                <input type="checkbox" name="mec[settings][booking_auto_confirm_paid]" id="mec_settings_booking_auto_confirm_paid" <?php echo ((isset($settings['booking_auto_confirm_paid']) and $settings['booking_auto_confirm_paid'] == '1') ? 'checked="checked"' : ''); ?> value="1" />
                                                <?php esc_html_e('Auto confirmation for paid bookings', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label for="mec_settings_booking_auto_confirm_send_email">
                                                <input type="hidden" name="mec[settings][booking_auto_confirm_send_email]" value="0" />
                                                <input type="checkbox" name="mec[settings][booking_auto_confirm_send_email]" id="mec_settings_booking_auto_confirm_send_email" <?php echo ((isset($settings['booking_auto_confirm_send_email']) and $settings['booking_auto_confirm_send_email'] == '1') ? 'checked="checked"' : ''); ?> value="1" />
                                                <?php esc_html_e('Send confirmation email in auto confirmation mode', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>

                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Booking Cancellation', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_cancellation_period_from"><?php esc_html_e('Cancellation Period', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <div class="cancellation-period-box">
                                                <input type="number" id="mec_settings_cancellation_period_from" name="mec[settings][cancellation_period_from]" value="<?php echo ((isset($settings['cancellation_period_from']) and trim($settings['cancellation_period_from']) != '') ? $settings['cancellation_period_from'] : ''); ?>" placeholder="<?php esc_attr_e('From e.g 48', 'mec'); ?>" />
                                                <input type="number" id="mec_settings_cancellation_period_time" name="mec[settings][cancellation_period_time]" value="<?php echo ((isset($settings['cancellation_period_time']) and trim($settings['cancellation_period_time']) != '') ? $settings['cancellation_period_time'] : ''); ?>" placeholder="<?php esc_attr_e('To e.g 24', 'mec'); ?>" />
                                            </div>
                                            <select name="mec[settings][cancellation_period_p]" title="<?php esc_attr_e('Period', 'mec'); ?>">
                                                <option value="hour" <?php echo (isset($settings['cancellation_period_p']) and $settings['cancellation_period_p'] == 'hour') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Hour(s)', 'mec'); ?></option>
                                                <option value="day" <?php echo (isset($settings['cancellation_period_p']) and $settings['cancellation_period_p'] == 'day') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Day(s)', 'mec'); ?></option>
                                            </select>
                                            <select name="mec[settings][cancellation_period_type]" title="<?php esc_attr_e('Type', 'mec'); ?>">
                                                <option value="before" <?php echo (isset($settings['cancellation_period_type']) and $settings['cancellation_period_type'] == 'before') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Before', 'mec'); ?></option>
                                                <option value="after" <?php echo (isset($settings['cancellation_period_type']) and $settings['cancellation_period_type'] == 'after') ? 'selected="selected"' : ''; ?>><?php esc_html_e('After', 'mec'); ?></option>
                                            </select>
                                            <div class="mec-label">
                                                <?php esc_html_e('Event Start', 'mec'); ?>
                                                <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Cancellation Period', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("You can restrict the option to cancel bookings. Leave empty for cancellation at any time. For example if you insert 48 to 24 hours before the event starts then bookers are able to cancel their booking only on this time period.", 'mec'); ?></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_cancel_page"><?php esc_html_e('Cancellation Page', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_booking_cancel_page" name="mec[settings][booking_cancel_page]">
                                                <option value="">----</option>
                                                <?php foreach($pages as $page): ?>
                                                    <option <?php echo ((isset($settings['booking_cancel_page']) and $settings['booking_cancel_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Cancellation Page', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("Users will be redirected to this page after the booking cancellation. Leave it empty if you are not intrested.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#8-_Booking_Cancellation/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_booking_cancel_page_time"><?php esc_html_e('Cancellation Page Time Interval', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="number" id="mec_settings_booking_cancel_page_time" name="mec[settings][booking_cancel_page_time]" value="<?php echo ((isset($settings['booking_cancel_page_time']) and trim($settings['booking_cancel_page_time']) != '0') ? $settings['booking_cancel_page_time'] : '2000'); ?>" placeholder="<?php esc_attr_e('2000 means 2 seconds', 'mec'); ?>" />
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Cancellation Page Time Interval', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("Specify the amount of delay before being redirected to the cancellation page. (in milliseconds)", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#8-_Booking_Cancellation/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                <div class="mec-basvanced-advanced w-hidden">
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Booking Shortcode', 'mec'); ?></h5>

                                    <?php if(!$this->main->getPRO()): ?>
                                    <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                                    <?php else: ?>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <p><?php echo sprintf(esc_html__("Booking module is available in the event details page but if you like to embed booking module of certain event into a custom WP page or post or any shortcode compatible widgets, all you need to do is to insert %s shortcode into the page content and place the event id instead of 1.", 'mec'), '<code>[mec-booking event-id="1"]</code>'); ?></p>
                                            <p><?php echo sprintf(esc_html__('Also, you can insert %s if you like to show only one of the available tickets in booking module. Instead of 1 you should insert the ticket ID. This parameter is optional.', 'mec'), '<strong>ticket-id="1"</strong>'); ?></p>
                                        </div>
                                    </div>
                                    <?php endif; ?>

                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Upload Field', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_booking_form_upload_field_mime_types"><?php esc_html_e('Mime types', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="text" id="mec_booking_form_upload_field_mime_types" name="mec[settings][upload_field_mime_types]" placeholder="jpeg,jpg,png,pdf" value="<?php echo ((isset($settings['upload_field_mime_types']) and trim($settings['upload_field_mime_types']) != '') ? $settings['upload_field_mime_types'] : ''); ?>" />
                                        </div>
                                        <p class="description"><?php echo esc_html__('Split mime types with ",".', 'mec'); ?> <br /> <?php esc_attr_e("Default: jpeg,jpg,png,pdf", 'mec'); ?></p>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_booking_form_upload_field_max_upload_size"><?php esc_html_e('Maximum file size', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="number" id="mec_booking_form_upload_field_max_upload_size" name="mec[settings][upload_field_max_upload_size]" value="<?php echo ((isset($settings['upload_field_max_upload_size']) and trim($settings['upload_field_max_upload_size']) != '') ? $settings['upload_field_max_upload_size'] : ''); ?>" />
                                        </div>
                                        <p class="description"><?php echo esc_html__('The unit is Megabyte "MB"', 'mec'); ?></p>
                                    </div>

                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Partial Payment', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label>
                                                <input type="hidden" name="mec[settings][booking_partial_payment]" value="0" />
                                                <input id="mec_booking_partial_payment" onchange="jQuery('#mec_booking_partial_payment_options').toggleClass('w-hidden');" value="1" type="checkbox" name="mec[settings][booking_partial_payment]" <?php if(isset($settings['booking_partial_payment']) and $settings['booking_partial_payment']) echo 'checked="checked"'; ?> /><?php esc_html_e('Accept partial payment', 'mec'); ?>
                                            </label>
                                            <span class="mec-tooltip">
                                                <div class="box">
                                                    <h5 class="title"><?php esc_html_e('Partial Payment', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("You can accept a partial of payment upon booking and manage the rest of payment on your own. For example receive 20% of booking amount online and manage the rest in cash or other payment systems.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#9-_Partial_Payment/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div id="mec_booking_partial_payment_options" class="<?php if(!isset($settings['booking_partial_payment']) or (isset($settings['booking_partial_payment']) and !$settings['booking_partial_payment'])) echo 'w-hidden'; ?>">
                                        <div class="mec-form-row">
                                            <label class="mec-col-3" for="mec_booking_payable"><?php esc_html_e('Payable', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <input type="number" min="1" id="mec_booking_payable" name="mec[settings][booking_payable]" value="<?php echo ((isset($settings['booking_payable']) and trim($settings['booking_payable']) != '') ? $settings['booking_payable'] : '100'); ?>" />
                                                <select id="mec_booking_payable_type" name="mec[settings][booking_payable_type]" title="<?php esc_attr_e('Payable Type', 'mec'); ?>">
                                                    <option value="percent" <?php echo ((isset($settings['booking_payable_type']) and $settings['booking_payable_type'] === 'percent') ? 'selected' : ''); ?>><?php esc_attr_e('Percent (%)', 'mec'); ?></option>
                                                    <option value="amount" <?php echo ((isset($settings['booking_payable_type']) and $settings['booking_payable_type'] === 'amount') ? 'selected' : ''); ?>><?php esc_attr_e('Amount ($)', 'mec'); ?></option>
                                                </select>
                                            </div>
                                        </div>
                                        <div class="mec-form-row">
                                            <div class="mec-col-12">
                                                <label>
                                                    <input type="hidden" name="mec[settings][booking_payable_per_event]" value="0" />
                                                    <input id="mec_booking_payable_per_event" value="1" type="checkbox" name="mec[settings][booking_payable_per_event]" <?php if(isset($settings['booking_payable_per_event']) and $settings['booking_payable_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Ability to edit payable options per event', 'mec'); ?>
                                                </label>
                                            </div>
                                        </div>
                                    </div>

                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Discount Per User Roles', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label>
                                                <input type="hidden" name="mec[settings][discount_per_user_role_status]" value="0" />
                                                <input id="mec_booking_discount_per_user_role_status" value="1" type="checkbox" name="mec[settings][discount_per_user_role_status]" <?php if(isset($settings['discount_per_user_role_status']) and $settings['discount_per_user_role_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Discount per User Role', 'mec'); ?>
                                            </label>
                                            <span class="mec-tooltip">
                                                <div class="box">
                                                    <h5 class="title"><?php esc_html_e('Discount per User Role', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("If enabled, you can set discount for users based on their roles.", 'mec'); ?></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>

                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Webhooks', 'mec'); ?></h5>

                                    <?php if(!$this->main->getPRO()): ?>
                                        <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                                    <?php else: ?>
                                        <div class="mec-form-row">
                                            <label>
                                                <input type="hidden" name="mec[settings][webhooks_status]" value="0" />
                                                <input value="1" type="checkbox" name="mec[settings][webhooks_status]" <?php if(isset($settings['webhooks_status']) and $settings['webhooks_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable webhooks module', 'mec'); ?>
                                            </label>
                                            <p><?php esc_attr_e("After enabling and saving the settings, you should reload the page to see a new menu on the Dashboard > Webhooks", 'mec'); ?></p>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <?php do_action( 'mec_booking_settings_end',$this->settings ) ?>
                            <?php endif; ?>
                        </div>

                        <?php if(isset($this->settings['booking_status']) and $this->settings['booking_status']): ?>

                        <?php do_action('mec_reg_menu_start', $this->main, $this->settings); ?>

                        <div id="booking_elements" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Booking Elements', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_booking_first_for_all">
                                        <input type="hidden" name="mec[settings][booking_first_for_all]" value="0" />
                                        <input type="checkbox" name="mec[settings][booking_first_for_all]" id="mec_settings_booking_first_for_all" <?php echo ((!isset($settings['booking_first_for_all']) or (isset($settings['booking_first_for_all']) and $settings['booking_first_for_all'] == '1')) ? 'checked="checked"' : ''); ?> value="1" />
                                        <?php esc_html_e('Enable Express Attendees Form', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                            <div class="box">
                                                <h5 class="title"><?php esc_html_e('Enable Express Attendees Form', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Apply the info from the first attendee to all the purchased tickets by that user. Uncheck if you want every ticket to have its own attendee’s info.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#Enable_Express_Attendees_Form/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_attendee_counter">
                                        <input type="hidden" name="mec[settings][attendee_counter]" value="0" />
                                        <input type="checkbox" name="mec[settings][attendee_counter]" id="mec_settings_attendee_counter"
                                            <?php echo ((isset($settings['attendee_counter']) and $settings['attendee_counter'] == '1') ? 'checked="checked"' : ''); ?>
                                               value="1" />
                                        <?php esc_html_e('Attendee Counter', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_booking_display_total_tickets">
                                        <input type="hidden" name="mec[settings][booking_display_total_tickets]" value="0" />
                                        <input type="checkbox" name="mec[settings][booking_display_total_tickets]" id="mec_settings_booking_display_total_tickets"
                                            <?php echo ((isset($settings['booking_display_total_tickets']) and $settings['booking_display_total_tickets'] == '1') ? 'checked="checked"' : ''); ?>
                                               value="1" />
                                        <?php esc_html_e('Display Total Tickets', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                            <div class="box">
                                                <h5 class="title"><?php esc_html_e('Display Total Tickets', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If enabled, the total number of selected tickets will be displayed next to the booking button in the  first step of the booking.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#Display_Total_Tickets/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_booking_display_progress_bar">
                                        <input type="hidden" name="mec[settings][booking_display_progress_bar]" value="0" />
                                        <input type="checkbox" name="mec[settings][booking_display_progress_bar]" id="mec_settings_booking_display_progress_bar"
                                            <?php echo ((isset($settings['booking_display_progress_bar']) and $settings['booking_display_progress_bar'] == '1') ? 'checked="checked"' : ''); ?>
                                               value="1" />
                                        <?php esc_html_e('Display Progress Bar', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                        <div class="box">
                                            <h5 class="title"><?php esc_html_e('Display Progress Bar', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("If enabled, a progress bar will be added to the booking module indicating the current step and the next steps. It won't get displayed if there is only 1 step.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#Display_Progress_Bar/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_booking_invoice">
                                        <input type="hidden" name="mec[settings][booking_invoice]" value="0" />
                                        <input type="checkbox" name="mec[settings][booking_invoice]" id="mec_settings_booking_invoice"
                                            <?php echo ((!isset($settings['booking_invoice']) or (isset($settings['booking_invoice']) and $settings['booking_invoice'] == '1')) ? 'checked="checked"' : ''); ?>
                                               value="1" />
                                        <?php esc_html_e('Enable Invoice', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_booking_ongoing">
                                        <input type="hidden" name="mec[settings][booking_ongoing]" value="0" />
                                        <input type="checkbox" name="mec[settings][booking_ongoing]" id="mec_settings_booking_ongoing"
                                            <?php echo ((isset($settings['booking_ongoing']) and $settings['booking_ongoing'] == '1') ? 'checked="checked"' : ''); ?>
                                               value="1" />
                                        <?php esc_html_e('Enable Booking for Ongoing Events', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_booking_downloadable_file_status">
                                        <input type="hidden" name="mec[settings][downloadable_file_status]" value="0" />
                                        <input type="checkbox" name="mec[settings][downloadable_file_status]" id="mec_settings_booking_downloadable_file_status"
                                            <?php echo ((isset($settings['downloadable_file_status']) and $settings['downloadable_file_status'] == '1') ? 'checked="checked"' : ''); ?>
                                               value="1" />
                                        <?php esc_html_e('Enable Downloadable File', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                            <div class="box">
                                                <h5 class="title"><?php esc_html_e('Downloadable File', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("By enabling this feature, You can upload a file for each event and the attendees will be able to download it after booking.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#Enable_Downloadable_File/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_booking_disable_ticket_times">
                                        <input type="hidden" name="mec[settings][disable_ticket_times]" value="0" />
                                        <input type="checkbox" name="mec[settings][disable_ticket_times]" id="mec_settings_booking_disable_ticket_times"
                                            <?php echo ((isset($settings['disable_ticket_times']) and $settings['disable_ticket_times'] == '1') ? 'checked="checked"' : ''); ?>
                                               value="1" />
                                        <?php esc_html_e('Disable Ticket Times', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div id="booking_tickets_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Global Tickets', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label for="mec_settings_booking_default_tickets_status">
                                    <input type="hidden" name="mec[settings][default_tickets_status]" value="0" />
                                    <input type="checkbox" name="mec[settings][default_tickets_status]" id="mec_settings_booking_default_tickets_status" <?php echo (isset($settings['default_tickets_status']) && $settings['default_tickets_status'] == '1') ? 'checked="checked"' : ''; ?> value="1" onchange="jQuery('#mec_settings_booking_default_tickets_wrapper').toggleClass('mec-util-hidden');" />
                                    <?php esc_html_e('Enable', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_settings_booking_default_tickets_wrapper" class="<?php echo (isset($settings['default_tickets_status']) && $settings['default_tickets_status'] == '1') ? '' : 'mec-util-hidden'; ?>">
                                <div class="mec-backend-tab-wrap mec-basvanced-toggle" data-for="#mec_settings_booking_default_tickets_wrapper" data-method="addition">
                                    <div class="mec-backend-tab">
                                        <div class="mec-backend-tab-item mec-b-active-tab"><?php esc_html_e('Basic', 'mec'); ?></div>
                                        <div class="mec-backend-tab-item"><?php esc_html_e('Advanced', 'mec'); ?></div>
                                    </div>
                                </div>
                                <?php $this->main->getTickets()->builder([
                                    'tickets' => $settings['tickets'] ?? [],
                                    'name_prefix' => 'mec[settings][tickets]',
                                    'object_id' => null,
                                ]); ?>
                            </div>
                        </div>

                        <div id="coupon_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Coupons', 'mec'); ?></h4>

                            <?php if(!$this->main->getPRO()): ?>
                            <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                            <?php else: ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][coupons_status]" value="0" />
                                    <input onchange="jQuery('#mec_coupons_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][coupons_status]" <?php if(isset($settings['coupons_status']) and $settings['coupons_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable coupons module', 'mec'); ?>
                                </label>
                                <p><?php esc_attr_e("After enabling and saving the settings, you should reload the page to see a new menu on the Dashboard > Booking", 'mec'); ?></p>
                            </div>
                            <div id="mec_coupons_container_toggle" class="<?php if((isset($settings['coupons_status']) and !$settings['coupons_status']) or !isset($settings['coupons_status'])) echo 'mec-util-hidden'; ?>">
                            </div>
                            <?php endif; ?>
                        </div>

                        <div id="taxes_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Taxes / Fees', 'mec'); ?></h4>

                            <?php if(!$this->main->getPRO()): ?>
                            <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                            <?php else: ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][taxes_fees_status]" value="0" />
                                    <input onchange="jQuery('#mec_taxes_fees_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][taxes_fees_status]" <?php if(isset($settings['taxes_fees_status']) and $settings['taxes_fees_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable taxes / fees module', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_taxes_fees_container_toggle" class="<?php if((isset($settings['taxes_fees_status']) and !$settings['taxes_fees_status']) or !isset($settings['taxes_fees_status'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <button class="button" type="button" id="mec_add_fee_button"><?php esc_html_e('Add Fee', 'mec'); ?></button>
                                </div>
                                <div class="mec-form-row" id="mec_fees_list">
                                    <?php $i = 0; foreach($fees as $key=>$fee): if(!is_numeric($key)) continue; $i = max($i, $key); ?>
                                    <div class="mec-box" id="mec_fee_row<?php echo esc_attr($i); ?>">
                                        <div class="mec-form-row">
                                            <input class="mec-col-12" type="text" name="mec[settings][fees][<?php echo esc_attr($i); ?>][title]" placeholder="<?php esc_attr_e('Fee Title', 'mec'); ?>" value="<?php echo (isset($fee['title']) ? esc_attr($fee['title']) : ''); ?>" />
                                        </div>
                                        <div class="mec-form-row">
                                            <span class="mec-col-4">
                                                <input type="text" name="mec[settings][fees][<?php echo esc_attr($i); ?>][amount]" placeholder="<?php esc_attr_e('Amount', 'mec'); ?>" value="<?php echo (isset($fee['amount']) ? esc_attr($fee['amount']) : 0); ?>" />
                                                <span class="mec-tooltip">
                                                    <div class="box top">
                                                        <h5 class="title"><?php esc_html_e('Amount', 'mec'); ?></h5>
                                                        <div class="content"><p><?php esc_attr_e("Fee amount, considered as fixed amount if you set the type to amount otherwise considered as percentage", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#Taxes_Fees/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                    </div>
                                                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                                                </span>
                                            </span>
                                            <span class="mec-col-4">
                                                <select name="mec[settings][fees][<?php echo esc_attr($i); ?>][type]">
                                                    <option value="percent" <?php echo ((isset($fee['type']) and $fee['type'] == 'percent') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Percent', 'mec'); ?></option>
                                                    <option value="amount" <?php echo ((isset($fee['type']) and $fee['type'] == 'amount') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Amount (Per Ticket)', 'mec'); ?></option>
                                                    <option value="amount_per_date" <?php echo ((isset($fee['type']) and $fee['type'] == 'amount_per_date') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Amount (Per Date)', 'mec'); ?></option>
                                                    <option value="amount_per_booking" <?php echo ((isset($fee['type']) and $fee['type'] == 'amount_per_booking') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Amount (Per Booking)', 'mec'); ?></option>
                                                </select>
                                            </span>
                                            <button class="button" type="button" id="mec_remove_fee_button<?php echo esc_attr($i); ?>" onclick="mec_remove_fee(<?php echo esc_attr($i); ?>);"><?php esc_html_e('Remove', 'mec'); ?></button>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </div>
                                <input type="hidden" id="mec_new_fee_key" value="<?php echo ($i+1); ?>" />
                                <div class="mec-util-hidden" id="mec_new_fee_raw">
                                    <div class="mec-box" id="mec_fee_row:i:">
                                        <div class="mec-form-row">
                                            <input class="mec-col-12" type="text" name="mec[settings][fees][:i:][title]" placeholder="<?php esc_attr_e('Fee Title', 'mec'); ?>" />
                                        </div>
                                        <div class="mec-form-row">
                                            <span class="mec-col-4">
                                                <input type="text" name="mec[settings][fees][:i:][amount]" placeholder="<?php esc_attr_e('Amount', 'mec'); ?>" value="0" />
                                                <span class="mec-tooltip">
                                                    <div class="box top">
                                                        <h5 class="title"><?php esc_html_e('Amount', 'mec'); ?></h5>
                                                        <div class="content"><p><?php esc_attr_e("Fee amount, considered as fixed amount if you set the type to amount otherwise considered as percentage", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking-settings/#Taxes_Fees/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                    </div>
                                                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                                                </span>
                                            </span>
                                            <span class="mec-col-4">
                                                <select name="mec[settings][fees][:i:][type]">
                                                    <option value="percent"><?php esc_html_e('Percent', 'mec'); ?></option>
                                                    <option value="amount"><?php esc_html_e('Amount (Per Ticket)', 'mec'); ?></option>
                                                    <option value="amount_per_date"><?php esc_html_e('Amount (Per Date)', 'mec'); ?></option>
                                                    <option value="amount_per_booking"><?php esc_html_e('Amount (Per Booking)', 'mec'); ?></option>
                                                </select>
                                            </span>
                                            <button class="button" type="button" id="mec_remove_fee_button:i:" onclick="mec_remove_fee(:i:);"><?php esc_html_e('Remove', 'mec'); ?></button>
                                        </div>
                                    </div>
                                </div>

                                <?php if(!isset($settings['wc_status']) || !$settings['wc_status']): ?>
                                <div class="mec-form-row">
                                    <h5><?php echo esc_html__('Disable Fees per Gateways', 'mec'); ?></h5>
                                        <?php foreach($gateways as $gateway): ?>
                                        <div class="mec-form-row">
                                            <span class="mec-col-12">
                                                <label>
                                                    <input type="hidden" name="mec[settings][fees_disabled_gateways][<?php echo esc_attr($gateway->id()); ?>]" value="0">
                                                    <input type="checkbox" name="mec[settings][fees_disabled_gateways][<?php echo esc_attr($gateway->id()); ?>]" value="1" <?php echo ((isset($settings['fees_disabled_gateways']) and isset($settings['fees_disabled_gateways'][$gateway->id()]) and $settings['fees_disabled_gateways'][$gateway->id()]) ? 'checked="checked"' : ''); ?>>
                                                    <?php echo esc_html($gateway->title()); ?>
                                                </label>
                                            </span>
                                        </div>
                                        <?php endforeach; ?>
                                </div>
                                <?php endif; ?>

                                <div class="mec-form-row">
                                    <h5><?php echo esc_html__('Tax Method', 'mec'); ?></h5>
                                    <div class="mec-col-12">
                                        <select id="mec_gateways_wc_autoorder_complete" name="mec[settings][tax_inclusion]">
                                            <option value="excluded" <?php echo((isset($settings['tax_inclusion']) && $settings['tax_inclusion'] === 'excluded') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Tax Excluded', 'mec'); ?></option>
                                            <option value="included" <?php echo((isset($settings['tax_inclusion']) && $settings['tax_inclusion'] === 'included') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Tax Included', 'mec'); ?></option>
                                        </select>
                                        <p><?php esc_attr_e("In most cases, the tax is exclusive. You can select inclusive, if you're inserting the price of tickets, tax included.", 'mec'); ?></p>
                                    </div>
                                </div>
                            </div>
                            <?php endif; ?>
                        </div>

                        <div id="ticket_variations_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Ticket Variations & Options', 'mec'); ?></h4>

                            <?php if(!$this->main->getPRO()): ?>
                                <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                            <?php else: ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][ticket_variations_status]" value="0" />
                                        <input onchange="jQuery('#mec_ticket_variations_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][ticket_variations_status]" <?php if(isset($settings['ticket_variations_status']) and $settings['ticket_variations_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable ticket variations module', 'mec'); ?>
                                    </label>
                                </div>
                                <div id="mec_ticket_variations_container_toggle" class="<?php if((isset($settings['ticket_variations_status']) and !$settings['ticket_variations_status']) or !isset($settings['ticket_variations_status'])) echo 'mec-util-hidden'; ?>">
                                    <div class="mec-form-row">
                                        <button class="button" type="button" id="mec_add_ticket_variation_button"><?php esc_html_e('Add Variation / Option', 'mec'); ?></button>
                                    </div>
                                    <div class="mec-form-row" id="mec_ticket_variations_list">
                                        <?php
                                            $TicketVariations = $this->getTicketVariations();
                                            $i = 0;
                                            foreach($ticket_variations as $key => $ticket_variation)
                                            {
                                                if(!is_numeric($key)) continue;
                                                $i = max($i, $key);

                                                $TicketVariations->item([
                                                    'i' => $i,
                                                    'name_prefix' => 'mec[settings][ticket_variations]',
                                                    'value' => $ticket_variation,
                                                ]);
                                            }
                                        ?>
                                    </div>
                                    <input type="hidden" id="mec_new_ticket_variation_key" value="<?php echo ($i+1); ?>" />
                                    <div class="mec-util-hidden" id="mec_new_ticket_variation_raw">
                                        <?php
                                            $TicketVariations->item([
                                                'i' => ':i:',
                                                'name_prefix' => 'mec[settings][ticket_variations]',
                                                'value' => [],
                                            ]);
                                        ?>
                                    </div>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][ticket_variations_per_ticket]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][ticket_variations_per_ticket]" <?php if(isset($settings['ticket_variations_per_ticket']) and $settings['ticket_variations_per_ticket']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable variations per ticket', 'mec'); ?>
                                        </label>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <h5><?php esc_html_e('Ticket Variations Shortcode', 'mec'); ?></h5>
                                            <p><?php echo sprintf(esc_html__('If you need to display ticket variations of an event outside the booking module you can use %s shortcode where the number 10 is the event id.', 'mec'), '<code>[mec-ticket-variations event-id="10"]</code>'); ?></p>
                                        </div>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>

                        <div id="booking_form_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Booking Form', 'mec'); ?></h4>
                            <div class="mec-booking-per-attendee-fields">
                                <h5 class="mec-form-subtitle"><?php esc_html_e('Per Attendee Fields', 'mec'); ?></h5>
                                <div class="mec-container">
                                    <?php do_action('before_mec_reg_fields_form'); ?>
                                    <?php do_action('mec_reg_fields_form_start'); ?>
                                    <div class="mec-form-row" id="mec_reg_form_container">
                                        <?php /** Don't remove this hidden field **/ ?>
                                        <input type="hidden" name="mec[reg_fields]" value="" />

                                        <ul id="mec_reg_form_fields">
                                            <?php
                                            $i = 0;
                                            foreach($reg_fields as $key => $reg_field)
                                            {
                                                if(!is_numeric($key)) continue;
                                                $i = max( $i, $key );

                                                if($reg_field['type'] == 'text') echo MEC_kses::form($this->main->field_text($key, $reg_field));
                                                elseif($reg_field['type'] == 'name') echo MEC_kses::form($this->main->field_name($key, $reg_field));
                                                elseif($reg_field['type'] == 'mec_email') echo MEC_kses::form($this->main->field_mec_email($key, $reg_field));
                                                elseif($reg_field['type'] == 'email') echo MEC_kses::form($this->main->field_email($key, $reg_field));
                                                elseif($reg_field['type'] == 'date') echo MEC_kses::form($this->main->field_date($key, $reg_field));
                                                elseif($reg_field['type'] == 'file') echo MEC_kses::form($this->main->field_file($key, $reg_field));
                                                elseif($reg_field['type'] == 'tel') echo MEC_kses::form($this->main->field_tel($key, $reg_field));
                                                elseif($reg_field['type'] == 'textarea') echo MEC_kses::form($this->main->field_textarea($key, $reg_field));
                                                elseif($reg_field['type'] == 'p') echo MEC_kses::form($this->main->field_p($key, $reg_field));
                                                elseif($reg_field['type'] == 'checkbox') echo MEC_kses::form($this->main->field_checkbox($key, $reg_field));
                                                elseif($reg_field['type'] == 'radio') echo MEC_kses::form($this->main->field_radio($key, $reg_field));
                                                elseif($reg_field['type'] == 'select') echo MEC_kses::form($this->main->field_select($key, $reg_field));
                                                elseif($reg_field['type'] == 'agreement') echo MEC_kses::form($this->main->field_agreement($key, $reg_field));
                                            }
                                            ?>
                                        </ul>
                                        <div id="mec_reg_form_field_types">
                                            <button type="button" class="button red" data-type="name"><?php esc_html_e( 'MEC Name', 'mec'); ?></button>
                                            <button type="button" class="button red" data-type="mec_email"><?php esc_html_e( 'MEC Email', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="text"><?php esc_html_e( 'Text', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="email"><?php esc_html_e( 'Email', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="date"><?php esc_html_e( 'Date', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="tel"><?php esc_html_e( 'Tel', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="file"><?php esc_html_e( 'File', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="textarea"><?php esc_html_e( 'Textarea', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="checkbox"><?php esc_html_e( 'Checkboxes', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="radio"><?php esc_html_e( 'Radio Buttons', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="select"><?php esc_html_e( 'Dropdown', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="agreement"><?php esc_html_e( 'Agreement', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="p"><?php esc_html_e( 'Paragraph', 'mec'); ?></button>
                                        </div>
                                        <?php do_action('mec_reg_fields_form_end'); ?>
                                    </div>
                                    <?php do_action('after_mec_reg_fields_form'); ?>
                                </div>
                                <input type="hidden" id="mec_new_reg_field_key" value="<?php echo ($i + 1); ?>" />
                                <div class="mec-util-hidden">
                                    <div id="mec_reg_field_text">
                                        <?php echo MEC_kses::form($this->main->field_text(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_email">
                                        <?php echo MEC_kses::form($this->main->field_email(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_mec_email">
                                        <?php echo MEC_kses::form($this->main->field_mec_email(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_name">
                                        <?php echo MEC_kses::form($this->main->field_name(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_tel">
                                        <?php echo MEC_kses::form($this->main->field_tel(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_date">
                                        <?php echo MEC_kses::form($this->main->field_date(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_file">
                                        <?php echo MEC_kses::form($this->main->field_file(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_textarea">
                                        <?php echo MEC_kses::form($this->main->field_textarea(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_checkbox">
                                        <?php echo MEC_kses::form($this->main->field_checkbox(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_radio">
                                        <?php echo MEC_kses::form($this->main->field_radio(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_select">
                                        <?php echo MEC_kses::form($this->main->field_select(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_agreement">
                                        <?php echo MEC_kses::form($this->main->field_agreement(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_p">
                                        <?php echo MEC_kses::form($this->main->field_p(':i:')); ?>
                                    </div>
                                    <div id="mec_reg_field_option">
                                        <?php echo MEC_kses::form($this->main->field_option(':fi:', ':i:')); ?>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-booking-fixed-fields">
                                <h5 class="mec-form-subtitle"><?php esc_html_e('Fixed Fields', 'mec'); ?></h5>
                                <div class="mec-container">
                                    <?php do_action('before_mec_bfixed_fields_form'); ?>
                                    <?php do_action('mec_bfixed_fields_form_start'); ?>
                                    <div class="mec-form-row" id="mec_bfixed_form_container">
                                        <?php /** Don't remove this hidden field **/ ?>
                                        <input type="hidden" name="mec[bfixed_fields]" value="" />

                                        <ul id="mec_bfixed_form_fields">
                                            <?php
                                            $b = 0;
                                            foreach($bfixed_fields as $key => $bfixed_field)
                                            {
                                                if(!is_numeric($key)) continue;
                                                $b = max($b, $key);

                                                if( !isset($bfixed_field['type']) ) continue;

                                                if($bfixed_field['type'] == 'text') echo MEC_kses::form($this->main->field_text($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'name') echo MEC_kses::form($this->main->field_name($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'mec_email') echo MEC_kses::form($this->main->field_mec_email($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'email') echo MEC_kses::form($this->main->field_email($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'date') echo MEC_kses::form($this->main->field_date($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'file') echo MEC_kses::form($this->main->field_file($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'tel') echo MEC_kses::form($this->main->field_tel($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'textarea') echo MEC_kses::form($this->main->field_textarea($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'p') echo MEC_kses::form($this->main->field_p($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'checkbox') echo MEC_kses::form($this->main->field_checkbox($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'radio') echo MEC_kses::form($this->main->field_radio($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'select') echo MEC_kses::form($this->main->field_select($key, $bfixed_field, 'bfixed'));
                                                elseif($bfixed_field['type'] == 'agreement') echo MEC_kses::form($this->main->field_agreement($key, $bfixed_field, 'bfixed'));
                                            }
                                            ?>
                                        </ul>
                                        <div id="mec_bfixed_form_field_types">
                                            <button type="button" class="button" data-type="text"><?php esc_html_e( 'Text', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="email"><?php esc_html_e( 'Email', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="date"><?php esc_html_e( 'Date', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="tel"><?php esc_html_e( 'Tel', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="textarea"><?php esc_html_e( 'Textarea', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="checkbox"><?php esc_html_e( 'Checkboxes', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="radio"><?php esc_html_e( 'Radio Buttons', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="select"><?php esc_html_e( 'Dropdown', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="agreement"><?php esc_html_e( 'Agreement', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="p"><?php esc_html_e( 'Paragraph', 'mec'); ?></button>
                                        </div>
                                        <?php do_action('mec_bfixed_fields_form_end'); ?>
                                    </div>
                                    <div class="mec-form-row">
                                        <?php wp_nonce_field('mec_options_form'); ?>
                                        <button  style="display: none;" id="mec_reg_fields_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e( 'Save Changes', 'mec'); ?></button>
                                    </div>
                                    <?php do_action('after_mec_bfixed_fields_form'); ?>
                                </div>
                                <input type="hidden" id="mec_new_bfixed_field_key" value="<?php echo ($b + 1); ?>" />
                                <div class="mec-util-hidden">
                                    <div id="mec_bfixed_field_text">
                                        <?php echo MEC_kses::form($this->main->field_text(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_email">
                                        <?php echo MEC_kses::form($this->main->field_email(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_tel">
                                        <?php echo MEC_kses::form($this->main->field_tel(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_date">
                                        <?php echo MEC_kses::form($this->main->field_date(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_textarea">
                                        <?php echo MEC_kses::form($this->main->field_textarea(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_checkbox">
                                        <?php echo MEC_kses::form($this->main->field_checkbox(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_radio">
                                        <?php echo MEC_kses::form($this->main->field_radio(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_select">
                                        <?php echo MEC_kses::form($this->main->field_select(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_agreement">
                                        <?php echo MEC_kses::form($this->main->field_agreement(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_p">
                                        <?php echo MEC_kses::form($this->main->field_p(':i:', array(), 'bfixed')); ?>
                                    </div>
                                    <div id="mec_bfixed_field_option">
                                        <?php echo MEC_kses::form($this->main->field_option(':fi:', ':i:', array(), 'bfixed')); ?>
                                    </div>
                                </div>
                            </div>

                            <?php do_action( 'mec_booking_form_option', $settings ); ?>
                        </div>

                        <div id="payment_gateways_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Payment Gateways', 'mec'); ?></h4>
                            <div class="mec-container">

                                <?php if(class_exists('WooCommerce')): ?>
                                <div class="mec-form-row" style="margin-bottom: 30px;">
                                    <div class="mec-col-12">
                                        <label>
                                            <input type="hidden" name="mec[settings][wc_status]" value="0" />
                                            <input id="mec_gateways_wc_status" onchange="jQuery('#mec_payment_options_wrapper, #mec_gateways_wc_status_guide').toggleClass('w-hidden');" value="1" type="checkbox" name="mec[settings][wc_status]" <?php if(isset($settings['wc_status']) and $settings['wc_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Use WooCommerce as Payment System', 'mec'); ?>
                                        </label>
                                        <p><?php esc_html_e("By enabling this feature, tickets will be added to WooCommerce cart and all payment process would be done by WooCommerce so all of MEC payment related modules will be disabled. To configure your desired gateways and booking fields etc, you need to configure WooCommerce on your website.", 'mec'); ?></p>
                                        <div id="mec_gateways_wc_status_guide" class="<?php if(!isset($settings['wc_status']) or (isset($settings['wc_status']) and !$settings['wc_status'])) echo 'w-hidden'; ?>">

                                            <?php if(isset($settings['mec_cart_status']) and $settings['mec_cart_status']): ?>
                                            <p class="mec-error" id="mec_wc_status_mec_cart_error"><?php esc_html_e("Please disable MEC Cart first otherwise you're not able to use WooCommerce feature.", 'mec'); ?></p>
                                            <?php endif; ?>

                                            <p><?php esc_html_e("You cannot use following MEC features so you should use WooCommerc and its add-ons if you need them.", 'mec'); ?></p>
                                            <ul>
                                                <li><?php esc_html_e('Payment Gateways', 'mec'); ?></li>
                                                <li><?php esc_html_e('Price per Dates of Tickets', 'mec'); ?></li>
                                                <li><?php esc_html_e('Coupons', 'mec'); ?></li>
                                                <li><?php esc_html_e('Ticket Variations', 'mec'); ?></li>
                                                <li><?php esc_html_e('Taxes / Fees', 'mec'); ?></li>
                                                <li><?php esc_html_e('Discount Per Roles', 'mec'); ?></li>
                                            </ul>

                                            <div class="mec-form-row" style="margin-top: 40px;">
                                                <label class="mec-col-3" for="mec_gateways_wc_autoorder_complete"><?php esc_html_e('Automatically complete WooCommerce orders', 'mec'); ?></label>
                                                <div class="mec-col-9">
                                                    <select id="mec_gateways_wc_autoorder_complete" name="mec[settings][wc_autoorder_complete]">
                                                        <option value="1" <?php echo((isset($settings['wc_autoorder_complete']) and $settings['wc_autoorder_complete'] == '1') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Enabled', 'mec'); ?></option>
                                                        <option value="0" <?php echo((isset($settings['wc_autoorder_complete']) and $settings['wc_autoorder_complete'] == '0') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Disabled', 'mec'); ?></option>
                                                    </select>
                                                    <span class="mec-tooltip">
                                                        <div class="box left">
                                                            <h5 class="title"><?php esc_html_e('Auto WooCommerce orders', 'mec'); ?></h5>
                                                            <div class="content"><p><?php esc_attr_e('It applies only to the orders that are related to MEC.', 'mec'); ?>
                                                            <a href="https://webnus.net/dox/modern-events-calendar/woocommerce/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                        </div>
                                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                                    </span>
                                                </div>
                                            </div>
                                            <div class="mec-form-row">
                                                <label class="mec-col-3" for="mec_gateways_wc_after_add"><?php esc_html_e('After Add to Cart', 'mec'); ?></label>
                                                <div class="mec-col-9">
                                                    <select id="mec_gateways_wc_after_add" name="mec[settings][wc_after_add]">
                                                        <option value="cart" <?php echo((isset($settings['wc_after_add']) and $settings['wc_after_add'] == 'cart') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Redirect to Cart', 'mec'); ?></option>
                                                        <option value="checkout" <?php echo((isset($settings['wc_after_add']) and $settings['wc_after_add'] == 'checkout') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Redirect to Checkout', 'mec'); ?></option>
                                                        <option value="optional_cart" <?php echo((isset($settings['wc_after_add']) and $settings['wc_after_add'] == 'optional_cart') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Optional View Cart Button', 'mec'); ?></option>
                                                        <option value="optional_chckout" <?php echo((isset($settings['wc_after_add']) and $settings['wc_after_add'] == 'optional_chckout') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Optional Checkout Button', 'mec'); ?></option>
                                                    </select>
                                                </div>
                                            </div>
                                            <div class="mec-form-row">
                                                <label class="mec-col-3" for="mec_gateways_wc_booking_form"><?php esc_html_e('MEC Booking Form', 'mec'); ?></label>
                                                <div class="mec-col-9">
                                                    <select id="mec_gateways_wc_booking_form" name="mec[settings][wc_booking_form]">
                                                        <option value="0" <?php echo((isset($settings['wc_booking_form']) and $settings['wc_booking_form'] == '0') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Disabled', 'mec'); ?></option>
                                                        <option value="1" <?php echo((isset($settings['wc_booking_form']) and $settings['wc_booking_form'] == '1') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Enabled', 'mec'); ?></option>
                                                    </select>
                                                    <span class="mec-tooltip">
                                                        <div class="box left">
                                                            <h5 class="title"><?php esc_html_e('Booking Form', 'mec'); ?></h5>
                                                            <div class="content"><p><?php esc_attr_e('If enabled then users should fill the booking form in MEC and then they will be redirected to checkout.', 'mec'); ?>
                                                            <a href="https://webnus.net/dox/modern-events-calendar/woocommerce/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                        </div>
                                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <?php endif; ?>

                                <div id="mec_payment_options_wrapper" class="<?php if(isset($settings['wc_status']) and $settings['wc_status'] and class_exists('WooCommerce')) echo 'w-hidden'; ?>">
                                    <div class="mec-form-row" id="mec_gateways_form_container">
                                        <ul>
                                            <?php foreach($gateways as $gateway): ?>
                                            <li id="mec_gateway_id<?php echo esc_attr($gateway->id()); ?>">
                                                <?php $gateway->options_form(); ?>
                                            </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                    <div class="mec-form-row" style="margin-top: 30px;">
                                        <div class="mec-col-12">
                                            <label>
                                                <input type="hidden" name="mec[gateways][op_status]" value="0" />
                                                <input id="mec_gateways_op_status" value="1" type="checkbox" name="mec[gateways][op_status]" <?php if(isset($gateways_options['op_status']) and $gateways_options['op_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable Organizer Payment Module', 'mec'); ?>
                                            </label>
                                            <span class="mec-tooltip">
                                                <div class="box">
                                                    <h5 class="title"><?php esc_html_e('Organizer Payment', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("By enabling this module, organizers can insert their payment credentials to receive the payments directly. This feature needs the Stripe connect payment gateway to work.", 'mec'); ?></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label>
                                                <input type="hidden" name="mec[gateways][gateways_per_event]" value="0" />
                                                <input id="mec_gateways_gateways_per_event" value="1" type="checkbox" name="mec[gateways][gateways_per_event]" <?php if(isset($gateways_options['gateways_per_event']) and $gateways_options['gateways_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Disable / Enable payment gateways per event', 'mec'); ?>
                                            </label>
                                            <span class="mec-tooltip">
                                                <div class="box">
                                                    <h5 class="title"><?php esc_html_e('Payment Gateways Per Event', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("By enabling this module, event submitters will be able to disable/enable payment gateways per event on the FES Form and on the event add/edit page.", 'mec'); ?></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label>
                                                <input type="hidden" name="mec[settings][skip_payment_step_for_free_bookings]" value="0" />
                                                <input id="mec_gateways_gateways_per_event" value="1" type="checkbox" name="mec[settings][skip_payment_step_for_free_bookings]" <?php if(!isset($settings['skip_payment_step_for_free_bookings']) or (isset($settings['skip_payment_step_for_free_bookings']) and $settings['skip_payment_step_for_free_bookings'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Skip payment step for free bookings', 'mec'); ?>
                                            </label>
                                            <span class="mec-tooltip">
                                                <div class="box">
                                                    <h5 class="title"><?php esc_html_e('Skip Payment Step', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("If enabled, it will skip payment step for free bookings. You can disable it if you're required by law.", 'mec'); ?></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <label>
                                                <input type="hidden" name="mec[settings][booking_auto_refund]" value="0" />
                                                <input id="mec_gateways_auto_refund" value="1" type="checkbox" name="mec[settings][booking_auto_refund]" <?php if(isset($settings['booking_auto_refund']) and $settings['booking_auto_refund']) echo 'checked="checked"'; ?> /><?php esc_html_e('Automatically refund the payment', 'mec'); ?>
                                            </label>
                                            <span class="mec-tooltip">
                                                <div class="box">
                                                    <h5 class="title"><?php esc_html_e('Auto Refund', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("Automatically refund the payment when a booking paid by gateways like Stripe gets canceled.", 'mec'); ?></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row" style="margin-top: 30px;">
                                        <div class="mec-col-12">
                                            <label class="mec-col-3" for="mec_settings_gateways_debug_email"><?php esc_html_e('Debug Paypal Standard Gateway', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <input type="text" id="mec_settings_gateways_debug_email" name="mec[settings][gateways_debug_email]" value="<?php echo ((isset($settings['gateways_debug_email']) and trim($settings['gateways_debug_email']) != '') ? $settings['gateways_debug_email'] : ''); ?>" />
                                                <p style="color: red;"><?php echo esc_html__("If you are encountering problems with the PayPal Standard gateway, you can enter your email here to receive a debug email that contains information received from the PayPal API. Please be aware that this email may contain sensitive information, so proceed with caution.", 'mec'); ?></p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <?php wp_nonce_field('mec_options_form'); ?>
                                    <button style="display: none;" id="mec_gateways_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Save Changes', 'mec'); ?></button>
                                </div>
                            </div>
                        </div>

                        <div id="cart_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('MEC Cart', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label>
                                        <input type="hidden" name="mec[settings][mec_cart_status]" value="0" />
                                        <input id="mec_gateways_mec_cart_status" onchange="jQuery('#mec_gateways_mec_cart_status_guide, #mec_wc_status_mec_cart_error').toggleClass('w-hidden');" value="1" type="checkbox" name="mec[settings][mec_cart_status]" <?php if(isset($settings['mec_cart_status']) and $settings['mec_cart_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Use MEC Cart System', 'mec'); ?>
                                    </label>
                                    <p><?php esc_html_e("If you don't want to use WooCommerce for any reason you can use MEC Cart for adding a simple cart and checkout system to your website.", 'mec'); ?></p>
                                    <div id="mec_gateways_mec_cart_status_guide" class="<?php if(!isset($settings['mec_cart_status']) or (isset($settings['mec_cart_status']) and !$settings['mec_cart_status'])) echo 'w-hidden'; ?>">
                                        <p style="margin-top: 20px;"><?php esc_html_e("You cannot use following MEC features while using MEC Cart.", 'mec'); ?></p>
                                        <ul>
                                            <li><?php esc_html_e('WooCommerce as Payment Gateway', 'mec'); ?></li>
                                            <li><?php esc_html_e('Currency Per Event', 'mec'); ?></li>
                                            <li><?php esc_html_e('Disable Gateways Per Event', 'mec'); ?></li>
                                            <li><?php esc_html_e('Thank You Page Per Event', 'mec'); ?></li>
                                            <li><?php esc_html_e('Stripe Connect Gateway', 'mec'); ?></li>
                                            <li><?php esc_html_e('Pay By WooCommerce Gateway', 'mec'); ?></li>
                                            <li><?php esc_html_e('Organizer Payment Module', 'mec'); ?></li>
                                        </ul>

                                        <div class="mec-form-row" style="margin-top: 40px;">
                                            <label class="mec-col-3" for="mec_settings_cart_page"><?php esc_html_e('Cart Page', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <select id="mec_settings_cart_page" name="mec[settings][cart_page]">
                                                    <option value="">----</option>
                                                    <?php foreach($pages as $page): ?>
                                                        <option <?php echo ((isset($settings['cart_page']) and $settings['cart_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                                    <?php endforeach; ?>
                                                </select>
                                                <p class="description"><?php echo sprintf(esc_html__('Put %s shortcode into the page.', 'mec'), '<code>[mec-cart]</code>'); ?></p>
                                            </div>
                                        </div>
                                        <div class="mec-form-row">
                                            <label class="mec-col-3" for="mec_settings_checkout_page"><?php esc_html_e('Checkout Page', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <select id="mec_settings_checkout_page" name="mec[settings][checkout_page]">
                                                    <option value="">----</option>
                                                    <?php foreach($pages as $page): ?>
                                                        <option <?php echo ((isset($settings['checkout_page']) and $settings['checkout_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                                    <?php endforeach; ?>
                                                </select>
                                                <p class="description"><?php echo sprintf(esc_html__('Put %s shortcode into the page.', 'mec'), '<code>[mec-checkout]</code>'); ?></p>
                                            </div>
                                        </div>
                                        <div class="mec-form-row">
                                            <label class="mec-col-3" for="mec_settings_cart_after_add"><?php esc_html_e('After Add to Cart', 'mec'); ?></label>
                                            <div class="mec-col-9">
                                                <select id="mec_settings_cart_after_add" name="mec[settings][cart_after_add]">
                                                    <option value="cart" <?php echo((isset($settings['cart_after_add']) and $settings['cart_after_add'] == 'cart') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Redirect to Cart', 'mec'); ?></option>
                                                    <option value="checkout" <?php echo((isset($settings['cart_after_add']) and $settings['cart_after_add'] == 'checkout') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Redirect to Checkout', 'mec'); ?></option>
                                                    <option value="optional_cart" <?php echo((isset($settings['cart_after_add']) and $settings['cart_after_add'] == 'optional_cart') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Optional View Cart Button', 'mec'); ?></option>
                                                    <option value="optional_chckout" <?php echo((isset($settings['cart_after_add']) and $settings['cart_after_add'] == 'optional_chckout') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Optional Checkout Button', 'mec'); ?></option>
                                                </select>
                                            </div>
                                        </div>
                                        <div class="mec-form-row">
                                            <div class="mec-col-12">
                                                <label>
                                                    <input type="hidden" name="mec[settings][mec_cart_invoice]" value="0" />
                                                    <input id="mec_gateways_mec_cart_invoice" value="1" type="checkbox" name="mec[settings][mec_cart_invoice]" <?php if(isset($settings['mec_cart_invoice']) and $settings['mec_cart_invoice']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable Cart Invoice', 'mec'); ?>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <?php endif; // If Booking Enabled ?>

                        <div class="mec-options-fields">
                            <?php wp_nonce_field('mec_options_form'); ?>
                            <?php if($multilingual): ?>
                            <input name="mec_locale" type="hidden" value="<?php echo esc_attr($locale); ?>" />
                            <?php endif; ?>
                            <button style="display: none;" id="mec_booking_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Save Changes', 'mec'); ?></button>
                        </div>
                    </form>

                </div>
            </div>
        </div>
    </div>

    <div id="wns-be-footer">
        <a id="" class="dpr-btn dpr-save-btn"><?php esc_html_e('Save Changes', 'mec'); ?></a>
    </div>

</div>

<?php $this->factory->params('footer', '<script>
jQuery(document).ready(function()
{
    jQuery(".dpr-save-btn").on("click", function(event)
    {
        event.preventDefault();
        jQuery("#mec_booking_form_button").trigger("click");
    });
});

jQuery("#mec_gateways_form_container .mec-required").on("change", function()
{
    var val = jQuery(this).val();
    if(val)
    {
        // Remove Focus Style
        jQuery(this).removeClass("mec-mandatory");
    }
});

jQuery("#mec_booking_form").on("submit", function(event)
{
    event.preventDefault();

    var validated = true;
    var first_field;

    jQuery("#mec_gateways_form_container").find(".mec-required").each(function()
    {
        // Remove Focus Style
        jQuery(this).removeClass("mec-mandatory");

        var val = jQuery(this).val();
        if(jQuery(this).is(":visible") && !val)
        {
            // Add Focus Style
            jQuery(this).addClass("mec-mandatory");

            validated = false;
            if(!first_field) first_field = this;
        }
    });

    if(!validated && first_field)
    {
        jQuery(first_field).focus();
        jQuery("html, body").animate(
        {
            scrollTop: (jQuery(first_field).offset().top - 200)
        }, 500);

        return false;
    }

    // Add loading Class to the button
    jQuery(".dpr-save-btn").addClass("loading").text("'.esc_js(esc_attr__('Saved', 'mec')).'");
    jQuery("<div class=\"wns-saved-settings\">'.esc_js(esc_attr__('Settings Saved!', 'mec')).'</div>").insertBefore("#wns-be-content");

    if(jQuery(".mec-purchase-verify").text() != "'.esc_js(esc_attr__('Verified', 'mec')).'")
    {
        jQuery(".mec-purchase-verify").text("'.esc_js(esc_attr__('Checking ...', 'mec')).'");
    }

    var settings = jQuery("#mec_booking_form").serialize();
    jQuery.ajax(
    {
        type: "POST",
        url: ajaxurl,
        data: "action=mec_save_settings&"+settings,
        beforeSend: function () {
            jQuery(".wns-be-main").append("<div class=\"mec-loarder-wrap mec-settings-loader\"><div class=\"mec-loarder\"><div></div><div></div><div></div></div></div>");
        },
        success: function(data)
        {
            // Remove the loading Class to the button
            setTimeout(function()
            {
                jQuery(".dpr-save-btn").removeClass("loading").text("'.esc_js(esc_attr__('Save Changes', 'mec')).'");
                jQuery(".wns-saved-settings").remove();
                jQuery(".mec-loarder-wrap").remove();
                if(jQuery(".mec-purchase-verify").text() != "'.esc_js(esc_attr__('Verified', 'mec')).'")
                {
                    jQuery(".mec-purchase-verify").text("'.esc_js(esc_attr__('Please Refresh Page', 'mec')).'");
                }
            }, 1000);
        },
        error: function(jqXHR, textStatus, errorThrown)
        {
            // Remove the loading Class to the button
            setTimeout(function()
            {
                jQuery(".dpr-save-btn").removeClass("loading").text("'.esc_js(esc_attr__('Save Changes', 'mec')).'");
                jQuery(".wns-saved-settings").remove();
                jQuery(".mec-loarder-wrap").remove();
            }, 1000);
        }
    });
});
</script>');