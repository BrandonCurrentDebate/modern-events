<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_feature_mec $this */

$multilingual = $this->main->is_multilingual();
$locale = $this->main->get_backend_active_locale();

$settings = $this->main->get_settings();
$ml_settings = $this->main->get_ml_settings(NULL, $locale);

// WordPress Pages
$pages = get_pages();

// Event Fields
$event_fields = $this->main->get_event_fields();

$mec_categories = get_terms(array(
    'taxonomy' => 'mec_category',
    'hide_empty' => false,
));
?>
<div class="wns-be-container wns-be-container-sticky">
    <div id="wns-be-infobar">
        <div class="mec-search-settings-wrap">
            <i class="mec-sl-magnifier"></i>
            <input id="mec-search-settings" type="text" placeholder="<?php esc_html_e('Search...' , 'mec'); ?>">
        </div>
        <a id="" class="dpr-btn dpr-save-btn"><?php esc_html_e('Save Changes', 'mec'); ?></a>
    </div>

    <div class="wns-be-sidebar">
        <?php $this->main->get_sidebar_menu('fes'); ?>
    </div>

    <div class="wns-be-main">
        <div id="wns-be-notification"></div>
        <div id="wns-be-content">
            <div class="wns-be-group-tab">
                <div class="mec-container">

                    <form id="mec_booking_form">

                        <div id="fes_general_options" class="mec-options-fields active">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Frontend Event Submission', 'mec'); ?></h4>

                            <div class="mec-backend-tab-wrap mec-basvanced-toggle" data-for="#fes_general_options">
                                <div class="mec-backend-tab">
                                    <div class="mec-backend-tab-item mec-b-active-tab"><?php esc_html_e('Basic', 'mec'); ?></div>
                                    <div class="mec-backend-tab-item"><?php esc_html_e('Advanced', 'mec'); ?></div>
                                </div>
                            </div>

                            <div class="mec-basvanced-basic">
                                <?php do_action('mec_settings_fes_form', $settings); ?>

                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_list_page"><?php esc_html_e('Events List Page', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_list_page" name="mec[settings][fes_list_page]">
                                            <option value="">----</option>
                                            <?php foreach($pages as $page): ?>
                                                <option <?php echo ((isset($settings['fes_list_page']) and $settings['fes_list_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                        <p class="description"><?php echo sprintf(esc_html__('Put %s shortcode into the page.', 'mec'), '<code>[MEC_fes_list]</code>'); ?></p>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_form_page"><?php esc_html_e('Add/Edit Events Page', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_form_page" name="mec[settings][fes_form_page]">
                                            <option value="">----</option>
                                            <?php foreach($pages as $page): ?>
                                                <option <?php echo ((isset($settings['fes_form_page']) and $settings['fes_form_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                        <p class="description"><?php echo sprintf(esc_html__('Put %s shortcode into the page.', 'mec'), '<code>[MEC_fes_form]</code>'); ?></p>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_new_event_status"><?php esc_html_e('New Events Status', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_new_event_status" name="mec[settings][fes_new_event_status]">
                                            <option value=""><?php esc_html_e('Let WordPress decide', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_new_event_status']) and $settings['fes_new_event_status'] == 'pending') ? 'selected="selected"' : ''); ?> value="pending"><?php esc_html_e('Pending', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_new_event_status']) and $settings['fes_new_event_status'] == 'publish') ? 'selected="selected"' : ''); ?> value="publish"><?php esc_html_e('Publish', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('New Events Status', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("What should be the default status of events registered by users?", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/frontend-event-submission/#4-_New_Events_Status/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-basvanced-advanced w-hidden">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_display_date_in_list"><?php esc_html_e('Display Event Date in List', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_display_date_in_list" name="mec[settings][fes_display_date_in_list]">
                                            <option <?php echo ((isset($settings['fes_display_date_in_list']) and $settings['fes_display_date_in_list'] == '0') ? 'selected="selected"' : ''); ?> value="0"><?php esc_html_e('No', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_display_date_in_list']) and $settings['fes_display_date_in_list'] == '1') ? 'selected="selected"' : ''); ?> value="1"><?php esc_html_e('Yes', 'mec'); ?></option>
                                        </select>
                                    </div>
                                </div>
                                <!-- Start FES Thank You Page -->
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_thankyou_page"><?php esc_html_e('Thank You Page', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_thankyou_page" name="mec[settings][fes_thankyou_page]">
                                            <option value="">----</option>
                                            <?php foreach($pages as $page): ?>
                                                <option <?php echo ((isset($settings['fes_thankyou_page']) and $settings['fes_thankyou_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Thank You Page', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Users will be redirect to this page after a successful event submission. Leave it empty if you want it to be disabled.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_thankyou_page_url"><?php esc_html_e('Thank You Page URL', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="url" id="mec_settings_fes_thankyou_page_url" name="mec[settings][fes_thankyou_page_url]" value="<?php echo ((isset($settings['fes_thankyou_page_url']) and trim($settings['fes_thankyou_page_url']) != '') ? esc_url($settings['fes_thankyou_page_url']) : ''); ?>" placeholder="<?php echo esc_attr('http://yoursite/com/desired-url/'); ?>" />
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Thank You Page URL', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("It is possible to be redirected to a specific URL after a successful event submission. Filling this option will disable the 'Thank You Page' option above.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/frontend-event-submission/#General_Advanced_Tab/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_default_category"><?php esc_html_e('Default Category', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select name="mec[settings][fes_default_category]" id="mec_settings_fes_default_category">
                                            <option value="">-----</option>
                                            <?php if(is_array($mec_categories) and count($mec_categories)): ?>
                                                <?php foreach($mec_categories as $mec_category): ?>
                                                    <option value="<?php echo $mec_category->term_id; ?>" <?php echo (isset($settings['fes_default_category']) and $settings['fes_default_category'] == $mec_category->term_id) ? 'selected="selected"' : ''; ?>><?php echo $mec_category->name; ?></option>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Default Category', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If the author has not selected a specific category for the recorded event using frontend event submission form, MEC will assigne this category to it by default.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <!-- End FES Thank You Page -->
                                <!-- Start FES Thank You Page Time -->
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_thankyou_page_time"><?php esc_html_e('Thank You Page Time Interval', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="number" id="mec_settings_fes_thankyou_page_time" name="mec[settings][fes_thankyou_page_time]" value="<?php echo ((isset($settings['fes_thankyou_page_time']) and trim($settings['fes_thankyou_page_time']) != '0') ? intval($settings['fes_thankyou_page_time']) : '2000'); ?>" placeholder="<?php esc_attr_e('2000 mean 2 seconds', 'mec'); ?>" />
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Thank You Page Time Interval', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Specify the amount of delay before being redirected to the thank you page. (in milliseconds)", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <!-- End FES Thank You Page Time -->
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_max_file_size"><?php esc_html_e('Maximum File Size', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="number" id="mec_settings_fes_max_file_size" name="mec[settings][fes_max_file_size]" value="<?php echo ((isset($settings['fes_max_file_size']) and trim($settings['fes_max_file_size']) != '0') ? intval($settings['fes_max_file_size']) : '5000'); ?>" placeholder="<?php esc_attr_e('in KB', 'mec'); ?>" />
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Maximum File Size', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Maximum acceptable size for files uploaded by users. (in KiloBytes)", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_disclaimer"><?php esc_html_e('Disclaimer Message', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <textarea name="mec[settings][fes_disclaimer]" id="mec_settings_fes_disclaimer" rows="7" placeholder="<?php esc_attr_e('Leave empty to disable', 'mec'); ?>"><?php echo ((isset($settings['fes_disclaimer']) and trim($settings['fes_disclaimer'])) ? $settings['fes_disclaimer'] : ''); ?></textarea>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Disclaimer', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("This message would display as a disclaimer message on the event details page. Leave it empty if you are not interested.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div id="fes_acl_options" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Access Level', 'mec'); ?></h4>
                            <?php $roles = array_reverse(wp_roles()->roles); ?>
                            <div class="mec-form-row">
                                <div class="mec-col-3">
                                    <label><?php esc_html_e('Access Role', 'mec'); ?></label>
                                    <span class="mec-tooltip">
                                        <div class="box right">
                                            <h5 class="title"><?php esc_html_e('Access Role', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("Which user roles can add events through FES Form?", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/frontend-event-submission/#1-_Access_Role/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </div>
                                <div class="mec-col-9">
                                    <input name="mec[settings][fes_access_roles][]" type="hidden" value="">
                                    <?php foreach($roles as $role => $r): ?>
                                    <ul>
                                        <li>
                                            <label><input name="mec[settings][fes_access_roles][]" type="checkbox" <?php echo (!isset($settings['fes_access_roles']) or (is_array($settings['fes_access_roles']) and in_array($role, $settings['fes_access_roles']))) ? 'checked' : '' ?> value="<?php echo esc_attr($role); ?>"><?php echo esc_html($r['name']); ?></label>
                                        </li>
                                    </ul>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_guest_status]" value="0" />
                                    <input onchange="jQuery('#mec_fes_guest_status_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][fes_guest_status]" <?php if(isset($settings['fes_guest_status']) and $settings['fes_guest_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable event submission by guest (Not logged in) users', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_fes_guest_status_container_toggle" class="<?php if((isset($settings['fes_guest_status']) and !$settings['fes_guest_status']) or !isset($settings['fes_guest_status'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_guest_name_email]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_guest_name_email]" <?php if(!isset($settings['fes_guest_name_email']) or (isset($settings['fes_guest_name_email']) and $settings['fes_guest_name_email'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable mandatory email and name for guest user', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_guest_user_creation]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_guest_user_creation]" <?php if(isset($settings['fes_guest_user_creation']) and $settings['fes_guest_user_creation']) echo 'checked="checked"'; ?> /><?php esc_html_e('Automatically create users after event publish and assign event to the created user', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div id="fes_section_options" class="mec-options-fields">
                        <h4 class="mec-form-subtitle"><?php esc_html_e('Frontend Event Submission Sections', 'mec'); ?></h4>
                            <?php if(isset($settings['trailer_url_status']) and $settings['trailer_url_status']): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_trailer_url]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_trailer_url]" <?php if(isset($settings['fes_section_trailer_url']) and $settings['fes_section_trailer_url']) echo 'checked="checked"'; ?> /><?php esc_html_e('Trailer URL', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_data_fields]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_data_fields]" <?php if(!isset($settings['fes_section_data_fields']) or (isset($settings['fes_section_data_fields']) and $settings['fes_section_data_fields'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Data Fields', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_countdown_method]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_countdown_method]" <?php if(!isset($settings['fes_section_countdown_method']) or (isset($settings['fes_section_countdown_method']) and $settings['fes_section_countdown_method'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Countdown Method', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_style_per_event]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_style_per_event]" <?php if(isset($settings['fes_section_style_per_event']) and $settings['fes_section_style_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Style Per Event', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_event_links]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_event_links]" <?php if(!isset($settings['fes_section_event_links']) || $settings['fes_section_event_links']) echo 'checked="checked"'; ?> onchange="jQuery('#mec_settings_fes_event_links_options_wrapper').toggleClass('mec-util-hidden');" /><?php esc_html_e('Event Links', 'mec'); ?>
                                </label>
                            </div>
                            <div class="<?php echo ((!isset($settings['fes_section_event_links']) || $settings['fes_section_event_links']) ? '' : 'mec-util-hidden'); ?>" id="mec_settings_fes_event_links_options_wrapper">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_event_link_target"><?php esc_html_e('Link Target', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_event_link_target" name="mec[settings][fes_event_link_target]">
                                            <option value="_self" <?php echo ($settings['fes_event_link_target'] == '_self' ? 'selected="selected"' : ''); ?>><?php esc_html_e('Current Window', 'mec'); ?></option>
                                            <option value="_blank" <?php echo ($settings['fes_event_link_target'] == '_blank' ? 'selected="selected"' : ''); ?>><?php esc_html_e('New Window', 'mec'); ?></option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_cost]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_cost]" <?php if(!isset($settings['fes_section_cost']) or (isset($settings['fes_section_cost']) and $settings['fes_section_cost'])) echo 'checked="checked"'; ?> /> <?php echo esc_html($this->main->m('event_cost', esc_html__('Event Cost', 'mec'))); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_featured_image]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_featured_image]" <?php if(!isset($settings['fes_section_featured_image']) or (isset($settings['fes_section_featured_image']) and $settings['fes_section_featured_image'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Featured Image', 'mec'); ?>
                                </label>
                            </div>

                            <?php if(isset($settings['event_gallery_status']) and $settings['event_gallery_status']): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_event_gallery]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_event_gallery]" <?php if(!isset($settings['fes_section_event_gallery']) or (isset($settings['fes_section_event_gallery']) and $settings['fes_section_event_gallery'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Gallery', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <?php if(isset($settings['related_events_per_event']) and $settings['related_events_per_event']): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_related_events]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_related_events]" <?php if(!isset($settings['fes_section_related_events']) || $settings['fes_section_related_events']) echo 'checked="checked"'; ?> /><?php esc_html_e('Related Events', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <?php if(isset($settings['banner_status']) && $settings['banner_status'] && (!isset($settings['banner_force_featured_image']) || !$settings['banner_force_featured_image'])): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_banner]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_banner]" <?php if(!isset($settings['fes_section_banner']) || $settings['fes_section_banner']) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Banner', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_categories]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_categories]" <?php if(!isset($settings['fes_section_categories']) || $settings['fes_section_categories']) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Categories', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_labels]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_labels]" <?php if(!isset($settings['fes_section_labels']) || $settings['fes_section_labels']) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Labels', 'mec'); ?>
                                </label>
                            </div>
                            <?php if(!isset($settings['event_visibility_status']) || $settings['event_visibility_status']): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_shortcode_visibility]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_shortcode_visibility]" <?php if(!isset($settings['fes_section_shortcode_visibility']) || $settings['fes_section_shortcode_visibility']) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Visibility', 'mec'); ?>
                                </label>
                                <span class="mec-tooltip">
                                    <div class="box right">
                                        <h5 class="title"><?php esc_html_e('Event Visibility', 'mec'); ?></h5>
                                        <div class="content"><p><?php esc_attr_e("This option allows you to hide/show the event from/in MEC shortcodes to the FES Form.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/frontend-event-submission/#Frontend_Event_Submission_Sections/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                    </div>
                                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                                </span>
                            </div>
                            <?php endif; ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_event_color]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_event_color]" <?php if(!isset($settings['fes_section_event_color']) or (isset($settings['fes_section_event_color']) and $settings['fes_section_event_color'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Color', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_tags]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_tags]" <?php if(!isset($settings['fes_section_tags']) || $settings['fes_section_tags']) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Tags', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_location]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_location]" <?php if(!isset($settings['fes_section_location']) || $settings['fes_section_location']) echo 'checked="checked"'; ?> onchange="jQuery('#mec_settings_fes_location_options_wrapper').toggle();" /><?php esc_html_e('Event Location', 'mec'); ?>
                                </label>
                            </div>
                            <div class="<?php echo ((!isset($settings['fes_section_location']) || $settings['fes_section_location']) ? '' : 'mec-util-hidden'); ?>" id="mec_settings_fes_location_options_wrapper">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_add_location"><?php esc_html_e('Ability to Add New Location', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_add_location" name="mec[settings][fes_add_location]">
                                            <option <?php echo ((isset($settings['fes_add_location']) and $settings['fes_add_location'] == '1') ? 'selected="selected"' : ''); ?> value="1"><?php esc_html_e('Yes', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_add_location']) and $settings['fes_add_location'] == '0') ? 'selected="selected"' : ''); ?> value="0"><?php esc_html_e('No', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Ability to Add New Location', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If enabled, then users are able to add their own new locations.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_other_locations]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_other_locations]" <?php if(!isset($settings['fes_section_other_locations']) or (isset($settings['fes_section_other_locations']) and $settings['fes_section_other_locations'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Other Locations', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_organizer]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_organizer]" <?php if(!isset($settings['fes_section_organizer']) or (isset($settings['fes_section_organizer']) and $settings['fes_section_organizer'])) echo 'checked="checked"'; ?> onchange="jQuery('#mec_settings_fes_organizer_options_wrapper').toggle();" /><?php esc_html_e('Event Organizer', 'mec'); ?>
                                </label>
                            </div>
                            <div class="<?php echo ((!isset($settings['fes_section_organizer']) or (isset($settings['fes_section_organizer']) and $settings['fes_section_organizer'])) ? '' : 'mec-util-hidden'); ?>" id="mec_settings_fes_organizer_options_wrapper">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_use_all_organizers"><?php esc_html_e('Ability to Use All Organizers', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_use_all_organizers" name="mec[settings][fes_use_all_organizers]">
                                            <option <?php echo ((isset($settings['fes_use_all_organizers']) and $settings['fes_use_all_organizers'] == '1') ? 'selected="selected"' : ''); ?> value="1"><?php esc_html_e('Yes', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_use_all_organizers']) and $settings['fes_use_all_organizers'] == '0') ? 'selected="selected"' : ''); ?> value="0"><?php esc_html_e('No', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Use All Organizers', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Users are able to see the list of ogranizers and use them for their event. Set it to \"No\" if you want to disable this functionality and the \"Other Organizers\" feature.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_add_organizer"><?php esc_html_e('Ability to Add New Organizer', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_add_organizer" name="mec[settings][fes_add_organizer]">
                                            <option <?php echo ((isset($settings['fes_add_organizer']) and $settings['fes_add_organizer'] == '1') ? 'selected="selected"' : ''); ?> value="1"><?php esc_html_e('Yes', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_add_organizer']) and $settings['fes_add_organizer'] == '0') ? 'selected="selected"' : ''); ?> value="0"><?php esc_html_e('No', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Ability to Add New Organizer', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If enabled, then users are able to add their own new organizers.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_speaker]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_speaker]" <?php if(isset($settings['fes_section_speaker']) and $settings['fes_section_speaker']) echo 'checked="checked"'; ?> /><?php esc_html_e('Speakers', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_sponsor]" value="0" />
                                    <input value="1" onchange="jQuery('#mec_fes_sponsor_section_options').toggle();" type="checkbox" name="mec[settings][fes_section_sponsor]" <?php if(isset($settings['fes_section_sponsor']) and $settings['fes_section_sponsor']) echo 'checked="checked"'; ?> /><?php esc_html_e('Sponsors', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_fes_sponsor_section_options" class="<?php echo isset($settings['fes_section_sponsor']) && $settings['fes_section_sponsor'] ? '' : 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_add_sponsor"><?php esc_html_e('Ability to Add New Sponsors', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_add_sponsor" name="mec[settings][fes_add_sponsor]">
                                            <option <?php echo ((isset($settings['fes_add_sponsor']) and $settings['fes_add_sponsor'] == '1') ? 'selected="selected"' : ''); ?> value="1"><?php esc_html_e('Yes', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_add_sponsor']) and $settings['fes_add_sponsor'] == '0') ? 'selected="selected"' : ''); ?> value="0"><?php esc_html_e('No', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Ability to Add New Sponsors', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If enabled, then users are able to add their own new sponsors.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_hourly_schedule]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_hourly_schedule]" <?php if(!isset($settings['fes_section_hourly_schedule']) or (isset($settings['fes_section_hourly_schedule']) and $settings['fes_section_hourly_schedule'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Hourly Schedule', 'mec'); ?>
                                </label>
                            </div>

                            <?php if($this->getPRO()): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_booking]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_booking]" <?php if(!isset($settings['fes_section_booking']) or (isset($settings['fes_section_booking']) and $settings['fes_section_booking'])) echo 'checked="checked"'; ?> onchange="jQuery('#mec_fes_booking_section_options').toggle();" /><?php esc_html_e('Booking Options', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_fes_booking_section_options" style="margin: 0 0 40px 0; padding: 20px 20px 4px; border: 1px solid #ddd;" class="<?php echo ((!isset($settings['fes_section_booking']) or (isset($settings['fes_section_booking']) and $settings['fes_section_booking'])) ? '' : 'mec-util-hidden'); ?>">
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_tbl]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_tbl]" <?php if(!isset($settings['fes_section_booking_tbl']) or (isset($settings['fes_section_booking_tbl']) and $settings['fes_section_booking_tbl'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Total Booking Limit', 'mec'); ?>
                                    </label>
                                </div>
                                <?php if(isset($settings['booking_date_selection_per_event']) and $settings['booking_date_selection_per_event']): ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_dspe]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_dspe]" <?php if(!isset($settings['fes_section_booking_dspe']) or (isset($settings['fes_section_booking_dspe']) and $settings['fes_section_booking_dspe'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Date Selection Per Event', 'mec'); ?>
                                    </label>
                                </div>
                                <?php endif; ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_mtpb]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_mtpb]" <?php if(!isset($settings['fes_section_booking_mtpb']) or (isset($settings['fes_section_booking_mtpb']) and $settings['fes_section_booking_mtpb'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Minimum Tickets Per Booking', 'mec'); ?>
                                    </label>
                                </div>
                                <?php if(!isset($settings['discount_per_user_role_status']) or (isset($settings['discount_per_user_role_status']) and $settings['discount_per_user_role_status'])): ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_dpur]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_dpur]" <?php if(!isset($settings['fes_section_booking_dpur']) or (isset($settings['fes_section_booking_dpur']) and $settings['fes_section_booking_dpur'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Discount Per User Roles', 'mec'); ?>
                                    </label>
                                </div>
                                <?php endif; ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_bao]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_bao]" <?php if(!isset($settings['fes_section_booking_bao']) or (isset($settings['fes_section_booking_bao']) and $settings['fes_section_booking_bao'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Book All Occurrences', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_io]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_io]" <?php if(!isset($settings['fes_section_booking_io']) or (isset($settings['fes_section_booking_io']) and $settings['fes_section_booking_io'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Interval Options', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_aa]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_aa]" <?php if(!isset($settings['fes_section_booking_aa']) or (isset($settings['fes_section_booking_aa']) and $settings['fes_section_booking_aa'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Automatic Approval', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_tubl]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_tubl]" <?php if(!isset($settings['fes_section_booking_tubl']) or (isset($settings['fes_section_booking_tubl']) and $settings['fes_section_booking_tubl'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Total User Booking Limits', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_lftp]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_lftp]" <?php if(!isset($settings['fes_section_booking_lftp']) or (isset($settings['fes_section_booking_lftp']) and $settings['fes_section_booking_lftp'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Last Few Tickets Percentage', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_typ]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_typ]" <?php if(!isset($settings['fes_section_booking_typ']) or (isset($settings['fes_section_booking_typ']) and $settings['fes_section_booking_typ'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Thank You Page', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_bbl]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_bbl]" <?php if(!isset($settings['fes_section_booking_bbl']) or (isset($settings['fes_section_booking_bbl']) and $settings['fes_section_booking_bbl'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Booking Button Label', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_tickets]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_tickets]" <?php if(!isset($settings['fes_section_tickets']) or (isset($settings['fes_section_tickets']) and $settings['fes_section_tickets'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Ticket Options', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][booking_private_description]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][booking_private_description]" <?php if(!isset($settings['booking_private_description']) or (isset($settings['booking_private_description']) and $settings['booking_private_description'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Private Description', 'mec'); ?>
                                </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_reg_form]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_reg_form]" <?php if(!isset($settings['fes_section_reg_form']) or (isset($settings['fes_section_reg_form']) and $settings['fes_section_reg_form'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Booking Form', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_fees]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_fees]" <?php if(!isset($settings['fes_section_fees']) or (isset($settings['fes_section_fees']) and $settings['fes_section_fees'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Fees / Taxes Options', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_ticket_variations]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_ticket_variations]" <?php if(!isset($settings['fes_section_ticket_variations']) or (isset($settings['fes_section_ticket_variations']) and $settings['fes_section_ticket_variations'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Ticket Variations / Options', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_att]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_att]" <?php if(!isset($settings['fes_section_booking_att']) or (isset($settings['fes_section_booking_att']) and $settings['fes_section_booking_att'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Attendees', 'mec'); ?>
                                    </label>
                                </div>
                                <?php if($this->getPartialPayment()->is_payable_per_event_enabled()): ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_booking_pp]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_booking_pp]" <?php if(!isset($settings['fes_section_booking_pp']) or (isset($settings['fes_section_booking_pp']) and $settings['fes_section_booking_pp'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Partial Payment Options', 'mec'); ?>
                                    </label>
                                </div>
                                <?php endif; ?>
                            </div>
                            <?php endif; ?>

                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_schema]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_schema]" <?php if(!isset($settings['fes_section_schema']) or (isset($settings['fes_section_schema']) and $settings['fes_section_schema'])) echo 'checked="checked"'; ?> /><?php esc_html_e('SEO Schema', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_excerpt]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_excerpt]" <?php if(isset($settings['fes_section_excerpt']) and $settings['fes_section_excerpt']) echo 'checked="checked"'; ?> /><?php esc_html_e('Excerpt', 'mec'); ?>
                                </label>
                            </div>

                            <?php if(isset($settings['downloadable_file_status']) and $settings['downloadable_file_status']): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_downloadable_file]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_downloadable_file]" <?php if(!isset($settings['fes_section_downloadable_file']) or (isset($settings['fes_section_downloadable_file']) and $settings['fes_section_downloadable_file'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Downloadable File', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <?php if(isset($settings['public_download_module']) and $settings['public_download_module']): ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_section_public_download_module]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_section_public_download_module]" <?php if(!isset($settings['fes_section_public_download_module']) or (isset($settings['fes_section_public_download_module']) and $settings['fes_section_public_download_module'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Public Download Module', 'mec'); ?>
                                    </label>
                                </div>
                            <?php endif; ?>

                            <?php if(isset($settings['faq_status']) and $settings['faq_status']): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_faq]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_faq]" <?php if(!isset($settings['fes_section_faq']) or (isset($settings['fes_section_faq']) and $settings['fes_section_faq'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Event FAQ', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <?php if(isset($settings['per_occurrences_status']) and $settings['per_occurrences_status']): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_occurrences]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_occurrences]" <?php if(!isset($settings['fes_section_occurrences']) or (isset($settings['fes_section_occurrences']) and $settings['fes_section_occurrences'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Occurrences', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <?php if(is_plugin_active('mec-virtual-events/mec-virtual-events.php')): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_virtual_events]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_virtual_events]" <?php if(!isset($settings['fes_section_virtual_events']) or (isset($settings['fes_section_virtual_events']) and $settings['fes_section_virtual_events'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Virtual Event', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <?php if(is_plugin_active('mec-zoom-integration/mec-zoom-integration.php')): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_section_zoom_integration]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_section_zoom_integration]" <?php if(!isset($settings['fes_section_zoom_integration']) or (isset($settings['fes_section_zoom_integration']) and $settings['fes_section_zoom_integration'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Zoom Event', 'mec'); ?>
                                </label>
                            </div>
                            <?php endif; ?>

                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_note]" value="0" />
                                    <input onchange="jQuery('#mec_fes_note_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][fes_note]" <?php if(isset($settings['fes_note']) and $settings['fes_note']) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Note', 'mec'); ?>
                                </label>
                                <span class="mec-tooltip">
                                    <div class="box right">
                                        <h5 class="title"><?php esc_html_e('Event Note', 'mec'); ?></h5>
                                        <div class="content"><p><?php esc_attr_e("Users can put a note for editors while they're submitting the event. Also you can put %%event_note%% into the new event notification in order to get users' notes in email.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/frontend-event-submission/#Frontend_Event_Submission_Sections/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                    </div>
                                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                                </span>
                            </div>
                            <div id="mec_fes_note_container_toggle" class="<?php if((isset($settings['fes_note']) and !$settings['fes_note']) or !isset($settings['fes_note'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_note_visibility"><?php esc_html_e('Note visibility', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_note_visibility" name="mec[settings][fes_note_visibility]">
                                            <option <?php echo ((isset($settings['fes_note_visibility']) and $settings['fes_note_visibility'] == 'always') ? 'selected="selected"' : ''); ?> value="always"><?php esc_html_e('Always', 'mec'); ?></option>
                                            <option <?php echo ((isset($settings['fes_note_visibility']) and $settings['fes_note_visibility'] == 'pending') ? 'selected="selected"' : ''); ?> value="pending"><?php esc_html_e('While event is not published', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Note visibility', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("When should event note be displayed in FES Form and Backend?", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/frontend-event-submission/#Frontend_Event_Submission_Sections/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_agreement]" value="0" />
                                    <input onchange="jQuery('#mec_fes_agreement_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][fes_agreement]" <?php if(isset($settings['fes_agreement']) and $settings['fes_agreement']) echo 'checked="checked"'; ?> /><?php esc_html_e('Agreement Checkbox (GDPR Compatibility)', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_fes_agreement_container_toggle" class="<?php if((isset($settings['fes_agreement']) and !$settings['fes_agreement']) or !isset($settings['fes_agreement'])) echo 'mec-util-hidden'; ?>" style="border: 1px solid #ddd; padding: 20px 20px 4px;">
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][fes_agreement_checked]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][fes_agreement_checked]" <?php if(isset($settings['fes_agreement_checked']) and $settings['fes_agreement_checked']) echo 'checked="checked"'; ?> /><?php esc_html_e('Checked by Default', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_agreement_page"><?php esc_html_e('Agreement Page', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_fes_agreement_page" name="mec[settings][fes_agreement_page]">
                                            <option value="">----</option>
                                            <?php foreach($pages as $page): ?>
                                            <option <?php echo ((isset($settings['fes_agreement_page']) and $settings['fes_agreement_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                </div>
                            </div>

                            <?php do_action( 'mec-settings-page-fes-form-sections-end', $settings ); ?>
                        </div>

                        <div id="fes_req_fields_options" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Required Fields', 'mec'); ?></h4>

                            <?php foreach(array(
                                'body' => esc_html__('Event Description', 'mec'),
                                'excerpt' => esc_html__('Excerpt', 'mec'),
                                'dates' => esc_html__('Dates', 'mec'),
                                'cost' => esc_html__('Cost', 'mec'),
                                'event_link' => esc_html__('Event Link', 'mec'),
                                'more_info_link' => esc_html__('More Info Link', 'mec'),
                                'category' => esc_html__('Category', 'mec'),
                                'location' => esc_html__('Location', 'mec'),
                                'featured_image' => esc_html__('Featured Image', 'mec'),
                                'label' => esc_html__('Label', 'mec')) as $req_field => $label): ?>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][fes_required_<?php echo esc_attr($req_field); ?>]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][fes_required_<?php echo esc_attr($req_field); ?>]" <?php if(isset($settings['fes_required_'.$req_field]) and $settings['fes_required_'.$req_field]) echo 'checked="checked"'; ?> /> <?php echo esc_html($label); ?>
                                </label>
                            </div>
                            <?php endforeach; ?>
                        </div>

                        <div class="mec-options-fields">
                            <?php wp_nonce_field('mec_options_form'); ?>
                            <?php if($multilingual): ?>
                            <input name="mec_locale" type="hidden" value="<?php echo esc_attr($locale); ?>" />
                            <?php endif; ?>
                            <button style="display: none;" id="mec_fes_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Save Changes', 'mec'); ?></button>
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
        jQuery("#mec_fes_form_button").trigger("click");
    });
});

jQuery("#mec_booking_form").on("submit", function(event)
{
    event.preventDefault();

    // Add loading Class to the button
    jQuery(".dpr-save-btn").addClass("loading").text("'.esc_js(esc_attr__('Saved', 'mec')).'");
    jQuery("<div class=\"wns-saved-settings\">'.esc_js(esc_attr__('Settings Saved!', 'mec')).'</div>").insertBefore("#wns-be-content");

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