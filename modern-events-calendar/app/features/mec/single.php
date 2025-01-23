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
        <?php $this->main->get_sidebar_menu('single_event'); ?>
    </div>

    <div class="wns-be-main">
        <div id="wns-be-notification"></div>
        <div id="wns-be-content">
            <div class="wns-be-group-tab">
                <div class="mec-container">

                    <form id="mec_single_form">

                        <div id="event_options" class="mec-options-fields active">

                            <h4 class="mec-form-subtitle"><?php esc_html_e('Single Event Page', 'mec'); ?></h4>

                            <div class="mec-backend-tab-wrap mec-basvanced-toggle" data-for="#event_options">
                                <div class="mec-backend-tab">
                                    <div class="mec-backend-tab-item mec-b-active-tab"><?php esc_html_e('Basic', 'mec'); ?></div>
                                    <div class="mec-backend-tab-item"><?php esc_html_e('Advanced', 'mec'); ?></div>
                                </div>
                            </div>

                            <div class="mec-basvanced-basic">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_single_event_date_format1"><?php esc_html_e('Single Event Date Format', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="text" id="mec_settings_single_event_date_format1" name="mec[settings][single_date_format1]" value="<?php echo ((isset($ml_settings['single_date_format1']) and trim($ml_settings['single_date_format1']) != '') ? esc_attr(stripslashes($ml_settings['single_date_format1'])) : 'M d Y'); ?>" />
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Single Event Date Format', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Specify the date format of the event date on the single event page date and time module.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/single-event-settings/#1-_Single_Event_Date_Format/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_single_event_date_method"><?php esc_html_e('Date Method', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_single_event_date_method" name="mec[settings][single_date_method]">
                                            <option value="next" <?php echo (isset($settings['single_date_method']) and $settings['single_date_method'] == 'next') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Next occurrence date', 'mec'); ?></option>
                                            <option value="referred" <?php echo (isset($settings['single_date_method']) and $settings['single_date_method'] == 'referred') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Referred date', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Date Method', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e('When you click on a recurring event from the archive page and shortcodes, which date should be opened?', 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/single-event-settings/#2-_Date_Method/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_single_event_single_style"><?php esc_html_e('Single Event Style', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_single_event_single_style" name="mec[settings][single_single_style]">
                                            <option value="default" <?php echo (isset($settings['single_single_style']) and $settings['single_single_style'] == 'default') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Default Style', 'mec'); ?></option>
                                            <option value="modern" <?php echo (isset($settings['single_single_style']) and $settings['single_single_style'] == 'modern') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Modern Style', 'mec'); ?></option>
                                            <?php do_action('mec_single_style', $settings); ?>
                                            <?php if(is_plugin_active( 'mec-single-builder/mec-single-builder.php')): ?>
                                            <option value="builder" <?php echo (isset($settings['single_single_style']) and $settings['single_single_style'] == 'builder') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Elementor Single Builder', 'mec'); ?></option>
                                            <?php endif; ?>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Single Event Style', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Choose the single event page style.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/single-event-settings/#3-_Single_Event_Style/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <?php do_action('mec_single_style_setting_after', $this) ?>
                                <?php if($this->main->getPRO() and isset($this->settings['booking_status']) and $this->settings['booking_status']): ?>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_single_event_booking_style"><?php esc_html_e('Booking Style', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_single_event_booking_style" name="mec[settings][single_booking_style]">
                                            <option value="default" <?php echo (isset($settings['single_booking_style']) and $settings['single_booking_style'] == 'default') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Default', 'mec'); ?></option>
                                            <option value="modal" <?php echo (isset($settings['single_booking_style']) and $settings['single_booking_style'] == 'modal') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Modal', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Booking Style', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("You can specify whether the booking widget should be shown as a pop-up (Modal) or as default. Note: The modal booking module will not appear if you set single event view on popup mode in the shortcodes settigns.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/single-event-settings/#4-_Booking_Style/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <?php endif;?>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_single_cost_type"><?php esc_html_e('Event Cost Type', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_single_cost_type" name="mec[settings][single_cost_type]">
                                            <option value="numeric" <?php echo (isset($settings['single_cost_type']) and $settings['single_cost_type'] == 'numeric') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Numeric (Searchable)', 'mec'); ?></option>
                                            <option value="alphabetic" <?php echo (isset($settings['single_cost_type']) and $settings['single_cost_type'] == 'alphabetic') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Alphabetic (Not Searchable)', 'mec'); ?></option>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Event Cost Type', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Choose the Numeric type if you want to include the event cost field into the search form. If you do not need the search option you can choose the Alphabetic type.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/single-event-settings/#5-_Event_Cost_Type/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <div class="mec-basvanced-advanced w-hidden">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_tz_per_event"><?php esc_html_e('Timezone Per Event', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label id="mec_settings_tz_per_event" >
                                            <input type="hidden" name="mec[settings][tz_per_event]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][tz_per_event]" <?php if(isset($settings['tz_per_event']) and $settings['tz_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Timezone Per Event', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("By activating this option, it will be possible to choose the timezone settings for each event separately. The appropriate option will be added to the add/edit event page.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_gutenberg"><?php esc_html_e('Disable Block Editor (Gutenberg)', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label id="mec_settings_gutenberg" >
                                            <input type="hidden" name="mec[settings][gutenberg]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][gutenberg]" <?php if(!isset($settings['gutenberg']) or (isset($settings['gutenberg']) and $settings['gutenberg'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Disable Block Editor', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Block Editor', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Keep this checkbox unchecked to use the new WordPress block editor.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/single-event-settings/#2-_Disable_Block_Editor_Gutenberg/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>

                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_breadcrumbs"><?php esc_html_e('Breadcrumbs', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label id="mec_settings_breadcrumbs" >
                                            <input type="hidden" name="mec[settings][breadcrumbs]" value="0" />
                                            <input type="checkbox" name="mec[settings][breadcrumbs]" id="mec_settings_breadcrumbs" <?php echo ((isset($settings['breadcrumbs']) and $settings['breadcrumbs']) ? 'checked="checked"' : ''); ?> value="1" onchange="jQuery('#mec_settings_breadcrumb_options').toggle();" /><?php esc_html_e('Enable Breadcrumbs', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Breadcrumbs', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Enabling this option will display the breadcrumbs on the single event page", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/single-event-settings/#3-_Breadcrumbs/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>

                                <div id="mec_settings_breadcrumb_options" class="<?php echo isset($settings['breadcrumbs']) && $settings['breadcrumbs'] ? '' : 'mec-util-hidden'; ?>">
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_breadcrumbs_archive_page"><?php esc_html_e('Breadcrumbs Events Page', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select id="mec_settings_breadcrumbs_archive_page" name="mec[settings][breadcrumbs_events_page]">
                                                <option value=""><?php esc_html_e('Archive Page', 'mec'); ?></option>
                                                <?php foreach($pages as $page): ?>
                                                <option value="<?php echo esc_attr($page->ID); ?>" <?php echo $page->ID == $settings['breadcrumbs_events_page'] ? 'selected' : ''; ?>><?php echo esc_html($page->post_title); ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_breadcrumbs_category"><?php esc_html_e('Category in Breadcrumbs', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <label>
                                                <input type="hidden" name="mec[settings][breadcrumbs_category]" value="0" />
                                                <input type="checkbox" name="mec[settings][breadcrumbs_category]" id="mec_settings_breadcrumbs_category" <?php echo !isset($settings['breadcrumbs_category']) || $settings['breadcrumbs_category'] ? 'checked="checked"' : ''; ?> value="1" /><?php esc_html_e('Include Category in Breadcrumbs', 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                </div>

                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_currency_per_event"><?php esc_html_e('Change Currency Per Event', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label for="mec_settings_currency_per_event">
                                            <input type="hidden" name="mec[settings][currency_per_event]" value="0" />
                                            <input type="checkbox" name="mec[settings][currency_per_event]" id="mec_settings_currency_per_event" <?php echo ((isset($settings['currency_per_event']) and $settings['currency_per_event'] == '1') ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable Currency Per Event', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Change Currency Per Event', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("By activating this option, it will be possible to choose the Currency settings for each event separately. The appropriate option will be added to the add/edit event page.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_featured_image_caption"><?php esc_html_e('Featured Image Caption', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label for="mec_settings_featured_image_caption">
                                            <input type="hidden" name="mec[settings][featured_image_caption]" value="0" />
                                            <input type="checkbox" name="mec[settings][featured_image_caption]" id="mec_settings_featured_image_caption" <?php echo ((isset($settings['featured_image_caption']) and $settings['featured_image_caption'] == '1') ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable', 'mec'); ?>
                                        </label>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_public_download_module"><?php esc_html_e('Public Download Module', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label for="mec_settings_public_download_module">
                                            <input type="hidden" name="mec[settings][public_download_module]" value="0" />
                                            <input type="checkbox" name="mec[settings][public_download_module]" id="mec_settings_public_download_module" <?php echo ((isset($settings['public_download_module']) and $settings['public_download_module'] == '1') ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Public Download Module', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If enabled, an upload field will appear in the add/edit event page and if filled, it will appear in the event details page to download.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_remaining_time_label"><?php esc_html_e('Remaining Time Label', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label for="mec_settings_remaining_time_label">
                                            <input type="hidden" name="mec[settings][remaining_time_label]" value="0" />
                                            <input type="checkbox" name="mec[settings][remaining_time_label]" id="mec_settings_remaining_time_label" <?php echo ((isset($settings['remaining_time_label']) and $settings['remaining_time_label'] == '1') ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Remaining Time Label', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e('If enabled, a "remaining time" label will be displayed in the shortcodes, indicating the time remaining until the event occurs. To ensure that labels, including the remaining time label, are displayed, the "Display Normal Labels" option should be enabled.', 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>

                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_sticky_sidebar"><?php esc_html_e('Sticky Sidebar', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label id="mec_settings_sticky_sidebar" >
                                            <input type="hidden" name="mec[settings][sticky_sidebar]" value="0" />
                                            <input type="checkbox" name="mec[settings][sticky_sidebar]" id="mec_settings_sticky_sidebar" <?php echo ((isset($settings['sticky_sidebar']) and $settings['sticky_sidebar']) ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable Sticky Sidebar', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Sticky Sidebar', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If the content you wish to display on the single event page is too long, enable this option to make the sidebar sticky. We don't recommend enabling this option if your sidebar has a lot of data and is a long sidebar.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>

                                <h5 class="mec-form-subtitle"><?php esc_html_e('Style Per Event', 'mec'); ?></h5>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][style_per_event]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][style_per_event]" <?php if(isset($settings['style_per_event']) and $settings['style_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable style per event option', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                        <div class="box right">
                                            <h5 class="title"><?php esc_html_e('Style Per Event', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("If enabled, a style selector will show in event add / edit page to change the event details style per event basis.", 'mec'); ?></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_fes_single_event_style"><?php esc_html_e('FES Auto Style', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select name="mec[settings][fes_single_event_style]" id="mec_settings_fes_single_event_style">
                                            <option value=""><?php esc_html_e('Inherit from global options', 'mec'); ?></option>
                                            <option value="default" <?php echo (isset($settings['fes_single_event_style']) and $settings['fes_single_event_style'] == 'default') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Default Style', 'mec'); ?></option>
                                            <option value="modern" <?php echo (isset($settings['fes_single_event_style']) and $settings['fes_single_event_style'] == 'modern') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Modern Style', 'mec'); ?></option>
                                            <?php do_action('mec_single_style', $settings, 'fes_single_event_style'); ?>
                                            <?php if(is_plugin_active( 'mec-single-builder/mec-single-builder.php')): ?>
                                                <option value="builder" <?php echo (isset($settings['fes_single_event_style']) and $settings['fes_single_event_style'] == 'builder') ? 'selected="selected"' : ''; ?>><?php esc_html_e('Elementor Single Builder', 'mec'); ?></option>
                                            <?php endif; ?>
                                        </select>
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('FES Event Style', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Choose your desired style for events submitted by Frontend Event Submission form.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>

                                <?php if($this->getPRO()): ?>
                                <div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Edit Per Occurrences', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][per_occurrences_status]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][per_occurrences_status]" <?php if(isset($settings['per_occurrences_status']) and $settings['per_occurrences_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Ability to edit some event information per occurrence', 'mec'); ?>
                                        </label>
                                    </div>
                                </div>
                                <?php endif; ?>

                                <h5 class="mec-form-subtitle"><?php esc_html_e('Event Visibility', 'mec'); ?></h5>
                                <div class="mec-form-row">
                                    <div class="mec-col-12">
                                        <label>
                                            <input type="hidden" name="mec[settings][event_visibility_status]" value="0" />
                                            <input id="mec_settings_event_visibility_status" value="1" type="checkbox" name="mec[settings][event_visibility_status]" <?php if(!isset($settings['event_visibility_status']) or (isset($settings['event_visibility_status']) and $settings['event_visibility_status'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Visibility', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                            <div class="box">
                                                <h5 class="title"><?php esc_html_e('Event Visibility', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("If enabled, you can set the visibility of events in shortcodes. You may exclude some events from displaying in shortcodes.", 'mec'); ?></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>

                                <div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Event Banner', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][banner_status]" value="0" />
                                            <input onchange="jQuery('#mec_event_banner_container').toggle();" value="1" type="checkbox" name="mec[settings][banner_status]" <?php if(isset($settings['banner_status']) and $settings['banner_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable Event Banner Feature', 'mec'); ?>
                                        </label>
                                    </div>
                                    <div class="<?php echo !isset($settings['banner_status']) || !$settings['banner_status'] ? 'mec-util-hidden' : ''; ?>" id="mec_event_banner_container">
                                        <div class="mec-form-row">
                                            <label>
                                                <input type="hidden" name="mec[settings][banner_force_featured_image]" value="0" />
                                                <input value="1" type="checkbox" name="mec[settings][banner_force_featured_image]" <?php if(isset($settings['banner_force_featured_image']) and $settings['banner_force_featured_image']) echo 'checked="checked"'; ?> /><?php esc_html_e('Force Featured Image as Event Banner', 'mec'); ?>
                                            </label>
                                            <p class="description" style="border-left: none; padding-left: 0; line-height: 1.5;"><?php esc_html_e('If you enable this option, then the featured image of events will be displayed as event banner by force and event banner options will be ignored.', 'mec'); ?></p>
                                        </div>
                                    </div>
                                </div>

                                <div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('FAQ Module', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][faq_status]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][faq_status]" <?php if(isset($settings['faq_status']) and $settings['faq_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable FAQ module', 'mec'); ?>
                                        </label>
                                    </div>
                                </div>

                                <div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Trailer URL Module', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][trailer_url_status]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][trailer_url_status]" <?php if(isset($settings['trailer_url_status']) and $settings['trailer_url_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable Trailer URL', 'mec'); ?>
                                        </label>
                                    </div>
                                </div>

                                <?php if($this->getPRO()): ?>
                                <div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Content only for bookers', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <p><?php echo sprintf(esc_html__('if you need to show a certain content only for booker users, you can enclose your content using %s shortcode. For example you can use %s code to say "Hi" to bookers.', 'mec'), '<code>[mec-only-booked-users]</code>', '<code>[mec-only-booked-users]Hi[/mec-only-booked-users]</code>'); ?></p>
                                        </div>
                                    </div>
                                </div>
                                <?php endif; ?>

                                <div>
                                    <h5 class="mec-form-subtitle"><?php esc_html_e('Hourly Schedule Shortcode', 'mec'); ?></h5>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <p><?php echo sprintf(esc_html__("hourly schedule is available in the event details page but if you like to embed this module into a custom WP page or post or any shortcode compatible widgets, all you need to do is to insert %s shortcode into the page content and place the event id instead of 1.", 'mec'), '<code>[mec-hourly-schedule event-id="1"]</code>'); ?></p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                        </div>

                        <div id="event_form_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Custom Fields', 'mec'); ?></h4>
                            <div class="mec-container">
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][display_event_fields_backend]" value="0" />
                                        <input onchange="jQuery('#mec_event_fields_container').toggle();" value="1" type="checkbox" name="mec[settings][display_event_fields_backend]" <?php if(!isset($settings['display_event_fields_backend']) or (isset($settings['display_event_fields_backend']) and $settings['display_event_fields_backend'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Event Data', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                            <div class="<?php if(isset($settings['display_event_fields_backend']) and !$settings['display_event_fields_backend'] ) echo 'mec-util-hidden'; ?>" id="mec_event_fields_container">
                                <div class="mec-container">
                                    <div class="mec-form-row" id="mec_event_form_container">
                                        <?php /** Don't remove this hidden field **/ ?>
                                        <input type="hidden" name="mec[event_fields]" value="" />

                                        <ul id="mec_event_form_fields">
                                            <?php
                                            $i = 0;
                                            foreach($event_fields as $key => $event_field)
                                            {
                                                if(!is_numeric($key)) continue;
                                                $i = max($i, $key);

                                                if($event_field['type'] == 'text') echo MEC_kses::form($this->main->field_text($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'email') echo MEC_kses::form($this->main->field_email($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'url') echo MEC_kses::form($this->main->field_url($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'date') echo MEC_kses::form($this->main->field_date($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'tel') echo MEC_kses::form($this->main->field_tel($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'textarea') echo MEC_kses::form($this->main->field_textarea($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'p') echo MEC_kses::form($this->main->field_p($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'checkbox') echo MEC_kses::form($this->main->field_checkbox($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'radio') echo MEC_kses::form($this->main->field_radio($key, $event_field, 'event'));
                                                elseif($event_field['type'] == 'select') echo MEC_kses::form($this->main->field_select($key, $event_field, 'event'));
                                            }
                                            ?>
                                        </ul>
                                        <div id="mec_event_form_field_types">
                                            <button type="button" class="button" data-type="text"><?php esc_html_e('Text', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="email"><?php esc_html_e('Email', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="url"><?php esc_html_e('URL', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="date"><?php esc_html_e('Date', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="tel"><?php esc_html_e('Tel', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="textarea"><?php esc_html_e('Textarea', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="p"><?php esc_html_e('Paragraph', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="checkbox"><?php esc_html_e('Checkboxes', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="radio"><?php esc_html_e('Radio Buttons', 'mec'); ?></button>
                                            <button type="button" class="button" data-type="select"><?php esc_html_e('Dropdown', 'mec'); ?></button>
                                        </div>
                                    </div>
                                </div>
                                <input type="hidden" id="mec_new_event_field_key" value="<?php echo ($i + 1); ?>" />
                                <div class="mec-util-hidden">
                                    <div id="mec_event_field_text">
                                        <?php echo MEC_kses::form($this->main->field_text(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_email">
                                        <?php echo MEC_kses::form($this->main->field_email(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_url">
                                        <?php echo MEC_kses::form($this->main->field_url(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_tel">
                                        <?php echo MEC_kses::form($this->main->field_tel(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_date">
                                        <?php echo MEC_kses::form($this->main->field_date(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_textarea">
                                        <?php echo MEC_kses::form($this->main->field_textarea(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_checkbox">
                                        <?php echo MEC_kses::form($this->main->field_checkbox(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_radio">
                                        <?php echo MEC_kses::form($this->main->field_radio(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_select">
                                        <?php echo MEC_kses::form($this->main->field_select(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_p">
                                        <?php echo MEC_kses::form($this->main->field_p(':i:', array(), 'event')); ?>
                                    </div>
                                    <div id="mec_event_field_option">
                                        <?php echo MEC_kses::form($this->main->field_option(':fi:', ':i:', array(), 'event')); ?>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][display_event_fields]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][display_event_fields]" <?php if(!isset($settings['display_event_fields']) or (isset($settings['display_event_fields']) and $settings['display_event_fields'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Display Event Fields in Single Event Pages', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][event_fields_icon]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][event_fields_icon]" <?php if(isset($settings['event_fields_icon']) and $settings['event_fields_icon']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable ability to select icon for fields.', 'mec'); ?>
                                    </label>
                                    <p style="margin-top: 15px;"><?php echo esc_html__("You should refresh the page to see its effects.", 'mec'); ?></p>
                                </div>
                            </div>
                        </div>

                        <div id="single_sidebar_options" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Sidebar options', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <ul>
                                        <li>
                                            <label for="mec_sso_datetime">
                                                <input type="hidden" name="mec[settings][ss_data_time]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_data_time']) || $settings['ss_data_time']) echo 'checked="checked"'; ?> id="mec_sso_datetime" name="mec[settings][ss_data_time]" value="1" />
                                                <?php esc_html_e('Date Time Module', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_local_time">
                                                <input type="hidden" name="mec[settings][ss_local_time]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_local_time']) || $settings['ss_local_time']) echo 'checked="checked"'; ?> id="mec_sso_local_time" name="mec[settings][ss_local_time]" value="1" />
                                                <?php esc_html_e('Local Time', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_event_cost">
                                                <input type="hidden" name="mec[settings][ss_event_cost]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_event_cost']) || $settings['ss_event_cost']) echo 'checked="checked"'; ?> id="mec_sso_event_cost" name="mec[settings][ss_event_cost]" value="1" />
                                                <?php esc_html_e('Event Cost', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_more_info">
                                                <input type="hidden" name="mec[settings][ss_more_info]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_more_info']) || $settings['ss_more_info']) echo 'checked="checked"'; ?> id="mec_sso_more_info" name="mec[settings][ss_more_info]" value="1" />
                                                <?php esc_html_e('More Info', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_event_label">
                                                <input type="hidden" name="mec[settings][ss_event_label]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_event_label']) || $settings['ss_event_label']) echo 'checked="checked"'; ?> id="mec_sso_event_label" name="mec[settings][ss_event_label]" value="1" />
                                                <?php esc_html_e('Event Label', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_event_location">
                                                <input type="hidden" name="mec[settings][ss_event_location]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_event_location']) || $settings['ss_event_location']) echo 'checked="checked"'; ?> id="mec_sso_event_location" name="mec[settings][ss_event_location]" value="1" />
                                                <?php esc_html_e('Event Location', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_event_categories">
                                                <input type="hidden" name="mec[settings][ss_event_categories]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_event_categories']) || $settings['ss_event_categories']) echo 'checked="checked"'; ?> id="mec_sso_event_categories" name="mec[settings][ss_event_categories]" value="1" />
                                                <?php esc_html_e('Event Categories', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_event_orgnizer">
                                                <input type="hidden" name="mec[settings][ss_event_orgnizer]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_event_orgnizer']) || $settings['ss_event_orgnizer']) echo 'checked="checked"'; ?> id="mec_sso_event_orgnizer" name="mec[settings][ss_event_orgnizer]" value="1" />
                                                <?php esc_html_e('Event Organizer', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_event_speakers">
                                                <input type="hidden" name="mec[settings][ss_event_speakers]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_event_speakers']) || $settings['ss_event_speakers']) echo 'checked="checked"'; ?> id="mec_sso_event_speakers" name="mec[settings][ss_event_speakers]" value="1" />
                                                <?php esc_html_e('Event Speakers', 'mec'); ?>
                                            </label>
                                        </li>
                                        <?php if(isset($settings['sponsors_status']) and $settings['sponsors_status']): ?>
                                            <li>
                                                <label for="mec_sso_event_sponsors">
                                                    <input type="hidden" name="mec[settings][ss_event_sponsors]" value="0" />
                                                    <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_event_sponsors']) || $settings['ss_event_sponsors']) echo 'checked="checked"'; ?> id="mec_sso_event_sponsors" name="mec[settings][ss_event_sponsors]" value="1" />
                                                    <?php esc_html_e('Event Sponsors', 'mec'); ?>
                                                </label>
                                            </li>
                                        <?php endif; ?>
                                        <li>
                                            <label for="mec_sso_register_btn">
                                                <input type="hidden" name="mec[settings][ss_register_btn]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_register_btn']) || $settings['ss_register_btn']) echo 'checked="checked"'; ?> id="mec_sso_register_btn" name="mec[settings][ss_register_btn]" value="1" />
                                                <?php esc_html_e('Register Button', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_attende_module">
                                                <input type="hidden" name="mec[settings][ss_attende_module]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_attende_module']) || $settings['ss_attende_module']) echo 'checked="checked"'; ?> id="mec_sso_attende_module" name="mec[settings][ss_attende_module]" value="1" />
                                                <?php esc_html_e('Attendees Module', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_next_module">
                                                <input type="hidden" name="mec[settings][ss_next_module]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_next_module']) || $settings['ss_next_module']) echo 'checked="checked"'; ?> id="mec_sso_next_module" name="mec[settings][ss_next_module]" value="1" />
                                                <?php esc_html_e('Next Event', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_links_module">
                                                <input type="hidden" name="mec[settings][ss_links_module]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_links_module']) || $settings['ss_links_module']) echo 'checked="checked"'; ?> id="mec_sso_links_module" name="mec[settings][ss_links_module]" value="1" />
                                                <?php esc_html_e('Social Module', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_weather_module">
                                                <input type="hidden" name="mec[settings][ss_weather_module]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_weather_module']) || $settings['ss_weather_module']) echo 'checked="checked"'; ?> id="mec_sso_weather_module" name="mec[settings][ss_weather_module]" value="1" />
                                                <?php esc_html_e('Weather Module', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_google_map">
                                                <input type="hidden" name="mec[settings][ss_google_map]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_google_map']) || $settings['ss_google_map']) echo 'checked="checked"'; ?> id="mec_sso_google_map" name="mec[settings][ss_google_map]" value="1" />
                                                <?php esc_html_e('Google Map', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_qrcode_module">
                                                <input type="hidden" name="mec[settings][ss_qrcode_module]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_qrcode_module']) || $settings['ss_qrcode_module']) echo 'checked="checked"'; ?> id="mec_sso_qrcode_module" name="mec[settings][ss_qrcode_module]" value="1" />
                                                <?php esc_html_e('QR Code', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_public_download_module">
                                                <input type="hidden" name="mec[settings][ss_public_download_module]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_public_download_module']) || $settings['ss_public_download_module']) echo 'checked="checked"'; ?> id="mec_sso_public_download_module" name="mec[settings][ss_public_download_module]" value="1" />
                                                <?php esc_html_e('Public Download', 'mec'); ?>
                                            </label>
                                        </li>
                                        <li>
                                            <label for="mec_sso_custom_fields_module">
                                                <input type="hidden" name="mec[settings][ss_custom_fields_module]" value="0" />
                                                <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_custom_fields_module']) || $settings['ss_custom_fields_module']) echo 'checked="checked"'; ?> id="mec_sso_custom_fields_module" name="mec[settings][ss_custom_fields_module]" value="1" />
                                                <?php esc_html_e('Custom Fields', 'mec'); ?>
                                            </label>
                                        </li>

                                        <?php if(!function_exists('is_plugin_active')) include_once(ABSPATH . 'wp-admin/includes/plugin.php'); ?>
                                        <?php if(is_plugin_active('mec-virtual-events/mec-virtual-events.php')): ?>
                                            <li>
                                                <label for="mec_sso_virtual_events_module">
                                                    <input type="hidden" name="mec[settings][ss_virtual_events_module]" value="0" />
                                                    <input class="checkbox" type="checkbox" <?php if(!isset($settings['ss_virtual_events_module']) || $settings['ss_virtual_events_module']) echo 'checked="checked"'; ?> id="mec_sso_virtual_events_module" name="mec[settings][ss_virtual_events_module]" value="1" />
                                                    <?php esc_html_e('Virtual Event', 'mec'); ?>
                                                </label>
                                            </li>
                                        <?php endif; ?>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div id="single_icons_options" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Icons options', 'mec'); ?></h4>
                            <?php $this->main->icons()->form(
                                'single',
                                'mec[settings]',
                                (isset($settings['icons']) && is_array($settings['icons']) ? $settings['icons'] : [])
                            ); ?>
                        </div>

                        <div class="mec-options-fields">
                            <?php wp_nonce_field('mec_options_form'); ?>
                            <?php if($multilingual): ?>
                            <input name="mec_locale" type="hidden" value="<?php echo esc_attr($locale); ?>" />
                            <?php endif; ?>
                            <button style="display: none;" id="mec_single_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Save Changes', 'mec'); ?></button>
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
        jQuery("#mec_single_form_button").trigger("click");
    });
});

jQuery("#mec_single_form").on("submit", function(event)
{
    event.preventDefault();

    // Add loading Class to the button
    jQuery(".dpr-save-btn").addClass("loading").text("'.esc_js(esc_attr__('Saved', 'mec')).'");
    jQuery("<div class=\"wns-saved-settings\">'.esc_js(esc_attr__('Settings Saved!', 'mec')).'</div>").insertBefore("#wns-be-content");

    if(jQuery(".mec-purchase-verify").text() != "'.esc_js(esc_attr__('Verified', 'mec')).'")
    {
        jQuery(".mec-purchase-verify").text("'.esc_js(esc_attr__('Checking ...', 'mec')).'");
    }

    var settings = jQuery("#mec_single_form").serialize();
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
