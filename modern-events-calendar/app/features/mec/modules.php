<?php
/** no direct access **/
defined('MECEXEC') or die();

$settings = $this->main->get_settings();
$socials = $this->main->get_social_networks();

// WordPress Pages
$pages = get_pages();
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
        <?php $this->main->get_sidebar_menu('modules'); ?>
    </div>

    <div class="wns-be-main">
        <div id="wns-be-notification"></div>
        <div id="wns-be-content">
            <div class="wns-be-group-tab">
                <div class="mec-container">

                    <form id="mec_modules_form">

                        <div id="speakers_option" class="mec-options-fields active">

                            <h4 class="mec-form-subtitle"><?php esc_html_e('Speakers', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_speakers_status">
                                        <input type="hidden" name="mec[settings][speakers_status]" value="0" />
                                        <input type="checkbox" name="mec[settings][speakers_status]" id="mec_settings_speakers_status" <?php echo ((isset($settings['speakers_status']) and $settings['speakers_status']) ? 'checked="checked"' : ''); ?> value="1" />
                                        <?php esc_html_e('Enable speakers feature', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                        <div class="box">
                                            <h5 class="title"><?php esc_html_e('Speakers', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("Enable this option if your events have speakers. Refresh after enabling it to see the Speakers menu under the MEC dashboard.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Speakers/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                    <p><?php esc_attr_e("After enabling and saving the settings, you should reload the page to see a new menu on the Dashboard > MEC", 'mec'); ?></p>
                                </div>
                            </div>

                        </div>

                        <div id="organizers_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Organizers', 'mec'); ?></h4>

                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_organizers_status">
                                        <input type="hidden" name="mec[settings][organizers_status]" value="0" />
                                        <input onchange="jQuery('#mec_settings_organizers_options').toggleClass('mec-util-hidden');" type="checkbox" name="mec[settings][organizers_status]" id="mec_settings_organizers_status" <?php echo (!isset($settings['organizers_status']) || $settings['organizers_status']) ? 'checked="checked"' : ''; ?> value="1" />
                                        <?php esc_html_e('Enable organizers feature', 'mec'); ?>
                                    </label>
                                </div>
                            </div>

                            <div id="mec_settings_organizers_options" class="<?php echo (!isset($settings['organizers_status']) || $settings['organizers_status']) ? '' : 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_organizer_description"><?php esc_html_e('Organizer Description', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <label id="mec_settings_organizer_description" >
                                            <input type="hidden" name="mec[settings][organizer_description]" value="0" />
                                            <input type="checkbox" name="mec[settings][organizer_description]" id="mec_settings_organizer_description" <?php echo ((isset($settings['organizer_description']) and $settings['organizer_description']) ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable', 'mec'); ?>
                                        </label>
                                        <span class="mec-tooltip">
                                        <div class="box right">
                                            <h5 class="title"><?php esc_html_e('Organizer Description', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("Enabaling this option will add the organizer description textbox to the organizers edit page.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Organizers/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                    </div>
                                </div>
                                <h5 class="mec-form-subtitle"><?php esc_html_e('Additional Organizers', 'mec'); ?></h5>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][additional_organizers]" value="0" />
                                        <input onchange="jQuery('#mec_settings_additional_organizers_description').toggle();" value="1" type="checkbox" name="mec[settings][additional_organizers]" <?php if(!isset($settings['additional_organizers']) or (isset($settings['additional_organizers']) and $settings['additional_organizers'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Show additional organizers', 'mec'); ?>
                                    </label>
                                </div>
                                <div id="mec_settings_additional_organizers_description" class="<?php if((isset($settings['additional_organizers']) and !$settings['additional_organizers']) or !isset($settings['additional_organizers'])) echo 'mec-util-hidden'; ?>">
                                    <div class="mec-form-row">
                                        <label id="mec_settings_additional_organizers_description">
                                            <input type="hidden" name="mec[settings][addintional_organizers_description]" value="0" />
                                            <input type="checkbox" name="mec[settings][addintional_organizers_description]" id="mec_settings_additional_organizers_description" <?php echo ((isset($settings['addintional_organizers_description']) and $settings['addintional_organizers_description']) ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable Description For Additional Organizers', 'mec'); ?>
                                        </label>
                                    </div>
                                </div>

                                <h5 class="mec-form-subtitle"><?php esc_html_e('Social Links', 'mec'); ?></h5>
                                <div class="mec-form-row">
                                    <label id="mec_settings_additional_organizers_social_links">
                                        <input type="hidden" name="mec[settings][addintional_organizers_social_links]" value="0" />
                                        <input type="checkbox" name="mec[settings][addintional_organizers_social_links]" id="mec_settings_additional_organizers_social_links" <?php echo ((isset($settings['addintional_organizers_social_links']) and $settings['addintional_organizers_social_links']) ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable Social Links For Organizers', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div id="locations_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Locations', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label class="mec-col-3" for="mec_settings_location_description"><?php esc_html_e('Location Description', 'mec'); ?></label>
                                <div class="mec-col-9">
                                    <label id="mec_settings_location_description" >
                                        <input type="hidden" name="mec[settings][location_description]" value="0" />
                                        <input type="checkbox" name="mec[settings][location_description]" id="mec_settings_location_description" <?php echo ((isset($settings['location_description']) and $settings['location_description']) ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                        <div class="box left">
                                            <h5 class="title"><?php esc_html_e('Location Description', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("Enabaling this option will add the location description textbox to the locations edit page.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Locations/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </div>
                            </div>
                            <h5 class="mec-form-subtitle"><?php esc_html_e('Other Locations', 'mec'); ?></h5>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][additional_locations]" value="0" />
                                    <input onchange="jQuery('#mec_settings_additional_locations_description').toggle();" value="1" type="checkbox" name="mec[settings][additional_locations]" <?php if(!isset($settings['additional_locations']) or (isset($settings['additional_locations']) and $settings['additional_locations'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Show other locations', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_settings_additional_locations_description" class="<?php if((isset($settings['additional_locations']) and !$settings['additional_locations']) or !isset($settings['additional_locations'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <label id="mec_settings_additional_locations_description">
                                        <input type="hidden" name="mec[settings][addintional_locations_description]" value="0" />
                                        <input type="checkbox" name="mec[settings][addintional_locations_description]" id="mec_settings_additional_locations_description" <?php echo ((isset($settings['addintional_locations_description']) and $settings['addintional_locations_description']) ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Enable Description For Other Locations', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label id="mec_settings_additional_locations_disable_title">
                                        <input type="hidden" name="mec[settings][additional_locations_disable_title]" value="0" />
                                        <input type="checkbox" name="mec[settings][additional_locations_disable_title]" id="mec_settings_additional_locations_disable_title" <?php echo ((isset($settings['additional_locations_disable_title']) and $settings['additional_locations_disable_title']) ? 'checked="checked"' : ''); ?> value="1" /><?php esc_html_e('Disable Title For Other Locations', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <?php if($this->main->getPRO()): ?>
                        <div id="sponsors_option" class="mec-options-fields">

                            <h4 class="mec-form-subtitle"><?php esc_html_e('Sponsors', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_sponsors_status">
                                        <input type="hidden" name="mec[settings][sponsors_status]" value="0" />
                                        <input type="checkbox" name="mec[settings][sponsors_status]" id="mec_settings_sponsors_status" <?php echo ((isset($settings['sponsors_status']) and $settings['sponsors_status']) ? 'checked="checked"' : ''); ?> value="1" />
                                        <?php esc_html_e('Enable sponsors feature', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                        <div class="box">
                                            <h5 class="title"><?php esc_html_e('Sponsors', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("Enable this option in order to add sponsors for your events.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Sponsors/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                    <p><?php esc_attr_e("After enabling and saving the settings, you should reload the page to see a new menu on the Dashboard > MEC", 'mec'); ?></p>
                                </div>
                            </div>

                        </div>
                        <?php endif; ?>

                        <div id="countdown_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Countdown', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][countdown_status]" value="0" />
                                    <input onchange="jQuery('#mec_count_down_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][countdown_status]" <?php if(isset($settings['countdown_status']) and $settings['countdown_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show countdown module on event page', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_count_down_container_toggle" class="<?php if((isset($settings['countdown_status']) and !$settings['countdown_status']) or !isset($settings['countdown_status'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_countdown_list"><?php esc_html_e('Countdown Style', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_countdown_list" name="mec[settings][countdown_list]">
                                            <option value="default" <?php echo ((isset($settings['countdown_list']) and $settings['countdown_list'] == "default") ? 'selected="selected"' : ''); ?> ><?php esc_html_e('Plain Style', 'mec'); ?></option>
                                            <option value="flip" <?php echo ((isset($settings['countdown_list']) and $settings['countdown_list'] == "flip") ? 'selected="selected"' : ''); ?> ><?php esc_html_e('Flip Style', 'mec'); ?></option>
                                        </select>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <div class="mec-col-12">
                                        <label for="mec_settings_countdown_disable_for_ongoing_events">
                                            <input type="hidden" name="mec[settings][countdown_disable_for_ongoing_events]" value="0">
                                            <input type="checkbox" id="mec_settings_countdown_disable_for_ongoing_events" name="mec[settings][countdown_disable_for_ongoing_events]" value="1" <?php echo (isset($settings['countdown_disable_for_ongoing_events']) and $settings['countdown_disable_for_ongoing_events']) ? 'checked="checked"' : ''; ?>>
                                            <?php esc_html_e('Disable for ongoing events', 'mec'); ?>
                                    </label>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][countdown_method_per_event]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][countdown_method_per_event]" <?php if(isset($settings['countdown_method_per_event']) and $settings['countdown_method_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Ability to change countdown method per event', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div id="exceptional_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Exceptional days (Exclude Dates)', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][exceptional_days]" value="0" />
                                    <input onchange="jQuery('#mec_exceptional_days_container_toggle').toggleClass('mec-util-hidden');" value="1" type="checkbox" name="mec[settings][exceptional_days]" <?php if(isset($settings['exceptional_days']) and $settings['exceptional_days']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show exceptional days option on Add/Edit events page', 'mec'); ?>
                                </label>
                                <span class="mec-tooltip">
                                    <div class="box right">
                                        <h5 class="title"><?php esc_html_e('Exceptional days (Exclude Dates)', 'mec'); ?></h5>
                                        <div class="content"><p><?php esc_attr_e("By using this option you can exclude certain days from multi-occurence event dates.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Exceptional_days/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                    </div>
                                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                                </span>
                            </div>
                            <div id="mec_exceptional_days_container_toggle" class="<?php echo (isset($settings['exceptional_days']) && $settings['exceptional_days']) ? '' : 'mec-util-hidden'; ?>">
                                <div id="mec-exceptional-days">
                                    <h5><?php esc_html_e('Global Exceptional Days', 'mec'); ?></h5>
                                    <div id="mec_meta_box_exceptions_form">
                                        <p style="margin-bottom: 10px; padding-left: 5px;"><?php esc_html_e("You may use this option to add your organization's off days.", 'mec'); ?></p>
                                        <div id="mec_exceptions_not_in_days_container">
                                            <?php
                                                $builder = $this->getFormBuilder();
                                                $builder->exceptionalDays([
                                                    'name_prefix' => 'mec[settings][global_exceptional_days]',
                                                    'values' => (isset($settings['global_exceptional_days']) && is_array($settings['global_exceptional_days']) ? $settings['global_exceptional_days'] : [])
                                                ]);
                                            ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div id="related_events" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Related Events', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][related_events]" value="0" />
                                    <input onchange="jQuery('#mec_related_events_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][related_events]" <?php if(isset($settings['related_events']) and $settings['related_events']) echo 'checked="checked"'; ?> /><?php esc_html_e('Display related events based on taxonomy in single event page.', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_related_events_container_toggle" class="<?php if((isset($settings['related_events']) and !$settings['related_events']) or !isset($settings['related_events'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row" style="margin-top:20px;">
                                    <label style="margin-right:7px;"><?php esc_html_e('Select Taxonomies:', 'mec'); ?></label>
                                    <label style="margin-right:7px;margin-bottom: 20px">
                                        <input type="hidden" name="mec[settings][related_events_basedon_category]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][related_events_basedon_category]" <?php if(isset($settings['related_events_basedon_category']) and $settings['related_events_basedon_category']) echo 'checked="checked"'; ?> /><?php esc_html_e('Category', 'mec'); ?>
                                    </label>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][related_events_basedon_organizer]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][related_events_basedon_organizer]" <?php if(isset($settings['related_events_basedon_organizer']) and $settings['related_events_basedon_organizer']) echo 'checked="checked"'; ?> /><?php esc_html_e('Organizer', 'mec'); ?>
                                    </label>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][related_events_basedon_location]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][related_events_basedon_location]" <?php if(isset($settings['related_events_basedon_location']) and $settings['related_events_basedon_location']) echo 'checked="checked"'; ?> /><?php esc_html_e('Location', 'mec'); ?>
                                    </label>
                                    <?php if(isset($settings['speakers_status']) and $settings['speakers_status']): ?>
                                        <label style="margin-right:7px;">
                                            <input type="hidden" name="mec[settings][related_events_basedon_speaker]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][related_events_basedon_speaker]" <?php if(isset($settings['related_events_basedon_speaker']) and $settings['related_events_basedon_speaker']) echo 'checked="checked"'; ?> /><?php esc_html_e('Speaker', 'mec'); ?>
                                        </label>
                                    <?php endif; ?>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][related_events_basedon_label]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][related_events_basedon_label]" <?php if(isset($settings['related_events_basedon_label']) and $settings['related_events_basedon_label']) echo 'checked="checked"'; ?> /><?php esc_html_e('Label', 'mec'); ?>
                                    </label>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][related_events_basedon_tag]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][related_events_basedon_tag]" <?php if(isset($settings['related_events_basedon_tag']) and $settings['related_events_basedon_tag']) echo 'checked="checked"'; ?> /><?php esc_html_e('Tag', 'mec'); ?>
                                    </label>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_related_events_limit"><?php esc_html_e('Max Events', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="number" min="1" step="1" id="mec_settings_related_events_limit" name="mec[settings][related_events_limit]" value="<?php echo ((isset($settings['related_events_limit']) and trim($settings['related_events_limit']) != '') ? $settings['related_events_limit'] : '30'); ?>" />
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][related_events_display_expireds]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][related_events_display_expireds]" <?php if(isset($settings['related_events_display_expireds']) and $settings['related_events_display_expireds']) echo 'checked="checked"'; ?> /><?php esc_html_e('Display Expired Events', 'mec'); ?>
                                    </label>
                                </div>
                                <h5 class="mec-form-subtitle"><?php esc_html_e('Related Events Per Event', 'mec'); ?></h5>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][related_events_per_event]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][related_events_per_event]" <?php if(isset($settings['related_events_per_event']) and $settings['related_events_per_event']) echo 'checked="checked"'; ?> /><?php esc_html_e('Set related events per event.', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div id="next_previous_events" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Next / Previous Events', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][next_previous_events]" value="0" />
                                    <input onchange="jQuery('#mec_next_previous_events_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][next_previous_events]" <?php if(isset($settings['next_previous_events']) and $settings['next_previous_events']) echo 'checked="checked"'; ?> /><?php esc_html_e('Display next / previous events based on taxonomy in single event page.', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_next_previous_events_container_toggle" class="<?php if((isset($settings['next_previous_events']) and !$settings['next_previous_events']) or !isset($settings['next_previous_events'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row" style="margin-top:20px;">
                                    <label style="margin-right:7px;" for="mec_settings_countdown_list"><?php esc_html_e('Select Taxonomies:', 'mec'); ?></label>
                                    <label style="margin-right:7px; margin-bottom: 20px;">
                                        <input type="hidden" name="mec[settings][next_previous_events_category]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][next_previous_events_category]" <?php if(isset($settings['next_previous_events_category']) and $settings['next_previous_events_category']) echo 'checked="checked"'; ?> /><?php esc_html_e('Category', 'mec'); ?>
                                    </label>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][next_previous_events_organizer]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][next_previous_events_organizer]" <?php if(isset($settings['next_previous_events_organizer']) and $settings['next_previous_events_organizer']) echo 'checked="checked"'; ?> /><?php esc_html_e('Organizer', 'mec'); ?>
                                    </label>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][next_previous_events_location]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][next_previous_events_location]" <?php if(isset($settings['next_previous_events_location']) and $settings['next_previous_events_location']) echo 'checked="checked"'; ?> /><?php esc_html_e('Location', 'mec'); ?>
                                    </label>
                                    <?php if(isset($settings['speakers_status']) and $settings['speakers_status']) : ?>
                                        <label style="margin-right:7px;">
                                            <input type="hidden" name="mec[settings][next_previous_events_speaker]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][next_previous_events_speaker]" <?php if(isset($settings['next_previous_events_speaker']) and $settings['next_previous_events_speaker']) echo 'checked="checked"'; ?> /><?php esc_html_e('Speaker', 'mec'); ?>
                                        </label>
                                    <?php endif; ?>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][next_previous_events_label]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][next_previous_events_label]" <?php if(isset($settings['next_previous_events_label']) and $settings['next_previous_events_label']) echo 'checked="checked"'; ?> /><?php esc_html_e('Label', 'mec'); ?>
                                    </label>
                                    <label style="margin-right:7px;">
                                        <input type="hidden" name="mec[settings][next_previous_events_tag]" value="0" />
                                        <input value="1" type="checkbox" name="mec[settings][next_previous_events_tag]" <?php if(isset($settings['next_previous_events_tag']) and $settings['next_previous_events_tag']) echo 'checked="checked"'; ?> /><?php esc_html_e('Tag', 'mec'); ?>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <?php if($this->main->getPRO()): ?>
                        <div id="sms_options" class="mec-options-fields">

                            <h4 class="mec-form-subtitle"><?php esc_html_e('SMS', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_sms_status">
                                        <input type="hidden" name="mec[settings][sms_status]" value="0" />
                                        <input type="checkbox" onchange="jQuery('#mec_sms_module_container_toggle').toggle();" name="mec[settings][sms_status]" id="mec_settings_sms_status" <?php echo ((isset($settings['sms_status']) and $settings['sms_status']) ? 'checked="checked"' : ''); ?> value="1" />
                                        <?php esc_html_e('Enable SMS feature', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                        <div class="box">
                                            <h5 class="title"><?php esc_html_e('SMS', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("Enable this option and add Twilio credentials to send text messages.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#SMS/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </div>
                            </div>
                            <div id="mec_sms_module_container_toggle" class="<?php if((isset($settings['sms_status']) and !$settings['sms_status']) or !isset($settings['sms_status'])) echo 'mec-util-hidden'; ?>">
                                <h5 class="mec-form-subtitle"><?php esc_html_e('Twilio Credentials', 'mec'); ?></h5>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_sms_twilio_account_sid"><?php esc_html_e('Account SID', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="password" id="mec_settings_sms_twilio_account_sid" name="mec[settings][sms_twilio_account_sid]" value="<?php echo ((isset($settings['sms_twilio_account_sid']) and trim($settings['sms_twilio_account_sid']) != '') ? $settings['sms_twilio_account_sid'] : ''); ?>" />
                                        <div class="mec-show-hide-password"><?php esc_html_e('Show / Hide', 'mec'); ?></div>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_sms_twilio_auth_token"><?php esc_html_e('Auth Token', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="password" id="mec_settings_sms_twilio_auth_token" name="mec[settings][sms_twilio_auth_token]" value="<?php echo ((isset($settings['sms_twilio_auth_token']) and trim($settings['sms_twilio_auth_token']) != '') ? $settings['sms_twilio_auth_token'] : ''); ?>" />
                                        <div class="mec-show-hide-password"><?php esc_html_e('Show / Hide', 'mec'); ?></div>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_sms_twilio_sender_number"><?php esc_html_e('Sender (From) Number', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="text" id="mec_settings_sms_twilio_sender_number" name="mec[settings][sms_twilio_sender_number]" value="<?php echo ((isset($settings['sms_twilio_sender_number']) and trim($settings['sms_twilio_sender_number']) != '') ? $settings['sms_twilio_sender_number'] : ''); ?>" placeholder="+17777777777" />
                                    </div>
                                </div>
                                <?php $error = get_option('mec_sms_twilio_error'); ?>
                                <?php if($error): ?>
                                <div class="mec-form-row">
                                    <div class="mec-col-12">
                                        <p class="mec-error"><?php echo $error; ?></p>
                                    </div>
                                </div>
                                <?php endif; ?>
                                <h5 class="mec-form-subtitle"><?php esc_html_e('Notifications', 'mec'); ?></h5>
                                <div class="mec-form-row">
                                    <div class="mec-col-12">
                                        <label for="mec_settings_sms_notif_admin_status">
                                            <input type="hidden" name="mec[settings][sms_notif_admin_status]" value="0" />
                                            <input type="checkbox" onchange="jQuery('#mec_sms_notif_admin_container_toggle').toggle();" name="mec[settings][sms_notif_admin_status]" id="mec_settings_sms_notif_admin_status" <?php echo ((isset($settings['sms_notif_admin_status']) and $settings['sms_notif_admin_status']) ? 'checked="checked"' : ''); ?> value="1" />
                                            <?php esc_html_e('Booking Admin Notification', 'mec'); ?>
                                        </label>
                                    </div>
                                </div>
                                <div id="mec_sms_notif_admin_container_toggle" class="<?php if((isset($settings['sms_notif_admin_status']) and !$settings['sms_notif_admin_status']) or !isset($settings['sms_notif_admin_status'])) echo 'mec-util-hidden'; ?>">
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_sms_notif_admin_recipients"><?php esc_html_e('Recipients', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="text" id="mec_settings_sms_notif_admin_recipients" name="mec[settings][sms_notif_admin_recipients]" value="<?php echo ((isset($settings['sms_notif_admin_recipients']) and trim($settings['sms_notif_admin_recipients']) != '') ? $settings['sms_notif_admin_recipients'] : ''); ?>" placeholder="<?php esc_attr_e('Comma separated numbers ...', 'mec'); ?>" />
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_sms_notif_admin_text"><?php esc_html_e('Text', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <textarea class="widefat" id="mec_settings_sms_notif_admin_text" name="mec[settings][sms_notif_admin_text]" rows="8" placeholder="<?php esc_attr_e('You can write any fixed text or use following placeholders.', 'mec'); ?>"><?php echo ((isset($settings['sms_notif_admin_text']) and trim($settings['sms_notif_admin_text']) != '') ? $settings['sms_notif_admin_text'] : ''); ?></textarea>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <?php MEC_feature_notifications::display_placeholders(); ?>
                                        </div>
                                    </div>
                                </div>
                            </div>

                        </div>
                        <?php endif; ?>

                        <?php if($this->main->getPRO()): ?>
                        <div id="certificate_options" class="mec-options-fields">

                            <h4 class="mec-form-subtitle"><?php esc_html_e('Certificates', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <label for="mec_settings_certificate_status">
                                        <input type="hidden" name="mec[settings][certificate_status]" value="0" />
                                        <input type="checkbox" onchange="jQuery('#mec_certificate_module_container_toggle').toggle();" name="mec[settings][certificate_status]" id="mec_settings_certificate_status" <?php echo ((isset($settings['certificate_status']) and $settings['certificate_status']) ? 'checked="checked"' : ''); ?> value="1" />
                                        <?php esc_html_e('Enable Certificates Module', 'mec'); ?>
                                    </label>
                                    <span class="mec-tooltip">
                                        <div class="box">
                                            <h5 class="title"><?php esc_html_e('Certificates Module', 'mec'); ?></h5>
                                            <div class="content"><p><?php esc_attr_e("Enable this option to build and send certificates to attendees.", 'mec'); ?></p></div>
                                        </div>
                                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                                    </span>
                                </div>
                            </div>
                            <div id="mec_certificate_module_container_toggle" class="<?php if((isset($settings['certificate_status']) and !$settings['certificate_status']) or !isset($settings['certificate_status'])) echo 'mec-util-hidden'; ?>">
                                <h5 class="mec-form-subtitle"><?php esc_html_e('Certificate Shortcodes', 'mec'); ?></h5>
                                <p><?php echo esc_html__("You can use the following shortcodes in certificate builder to display attendee information.", 'mec'); ?></p>
                                <ul>
                                    <li><code>[mec_cert_event_title]</code>: <?php esc_html_e("Event Title", 'mec'); ?></li>
                                    <li><code>[mec_cert_event_date]</code>: <?php esc_html_e("Event Date", 'mec'); ?></li>
                                    <li><code>[mec_cert_attendee_id]</code>: <?php esc_html_e("Attendee ID", 'mec'); ?></li>
                                    <li><code>[mec_cert_attendee_name]</code>: <?php esc_html_e("Attendee Name", 'mec'); ?></li>
                                    <li><code>[mec_cert_ticket_id]</code>: <?php esc_html_e("Ticket ID", 'mec'); ?></li>
                                    <li><code>[mec_cert_ticket_name]</code>: <?php esc_html_e("Ticket Name", 'mec'); ?></li>
                                    <li><code>[mec_cert_transaction_id]</code>: <?php esc_html_e("Transaction ID", 'mec'); ?></li>
                                </ul>
                            </div>
                        </div>
                        <?php endif; ?>

                        <?php if($this->main->getPRO()): ?>

                            <div id="googlemap_option" class="mec-options-fields">
                                <h4 class="mec-form-subtitle"><?php esc_html_e('Map', 'mec'); ?></h4>
                                <?php if(!$this->main->getPRO()): ?>
                                <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                                <?php else: ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][google_maps_status]" value="0" />
                                        <input onchange="jQuery('#mec_google_maps_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][google_maps_status]" <?php if(isset($settings['google_maps_status']) and $settings['google_maps_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show Map on event page', 'mec'); ?>
                                    </label>
                                </div>
                                <div id="mec_google_maps_container_toggle" class="<?php if((isset($settings['google_maps_status']) and !$settings['google_maps_status']) or !isset($settings['google_maps_status'])) echo 'mec-util-hidden'; ?>">
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_google_maps_api_key"><?php esc_html_e('Google Maps API Key', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="text" id="mec_settings_google_maps_api_key" name="mec[settings][google_maps_api_key]" value="<?php echo ((isset($settings['google_maps_api_key']) and trim($settings['google_maps_api_key']) != '') ? $settings['google_maps_api_key'] : ''); ?>" />
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Google Map Options', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("It is necessary to enter the Google Maps API to use it in MEC.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Zoom_level/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3"><?php esc_html_e('Zoom level', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select name="mec[settings][google_maps_zoomlevel]">
                                                <?php for($i = 5; $i <= 21; $i++): ?>
                                                <option value="<?php echo esc_attr($i); ?>" <?php if(isset($settings['google_maps_zoomlevel']) and $settings['google_maps_zoomlevel'] == $i) echo 'selected="selected"'; ?>><?php echo esc_html($i); ?></option>
                                                <?php endfor; ?>
                                            </select>
                                            <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Zoom level', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("This option will work on the Google Maps module on the single event page. Map view shortcode will automatically calculate the zoom level based on the event boundaries.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/google-maps-options/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3"><?php esc_html_e('Google Maps Style', 'mec'); ?></label>
                                        <?php $styles = $this->main->get_googlemap_styles(); ?>
                                        <div class="mec-col-9">
                                            <select name="mec[settings][google_maps_style]">
                                                <option value=""><?php esc_html_e('Default', 'mec'); ?></option>
                                                <?php foreach($styles as $style): ?>
                                                <option value="<?php echo esc_attr($style['key']); ?>" <?php if(isset($settings['google_maps_style']) and $settings['google_maps_style'] == $style['key']) echo 'selected="selected"'; ?>><?php echo esc_html($style['name']); ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3"><?php esc_html_e('Direction on single event', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <select name="mec[settings][google_maps_get_direction_status]">
                                                <option value="0"><?php esc_html_e('Disabled', 'mec'); ?></option>
                                                <option value="1" <?php if(isset($settings['google_maps_get_direction_status']) and $settings['google_maps_get_direction_status'] == 1) echo 'selected="selected"'; ?>><?php esc_html_e('Simple Method', 'mec'); ?></option>
                                                <option value="2" <?php if(isset($settings['google_maps_get_direction_status']) and $settings['google_maps_get_direction_status'] == 2) echo 'selected="selected"'; ?>><?php esc_html_e('Advanced Method', 'mec'); ?></option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_google_maps_date_format1"><?php esc_html_e('Lightbox Date Format', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="text" id="mec_settings_google_maps_date_format1" name="mec[settings][google_maps_date_format1]" value="<?php echo ((isset($settings['google_maps_date_format1']) and trim($settings['google_maps_date_format1']) != '') ? $settings['google_maps_date_format1'] : 'M d Y'); ?>" />
                                            <span class="mec-tooltip">
                                                <div class="box left">
                                                    <h5 class="title"><?php esc_html_e('Lightbox Date Format', 'mec'); ?></h5>
                                                    <div class="content"><p><?php esc_attr_e("Select the event's date format on the map module lightbox.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Lightbox_Date_Format/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3"><?php esc_html_e('Google Maps API Load', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <label>
                                                <input type="hidden" name="mec[settings][google_maps_dont_load_api]" value="0" />
                                                <input value="1" type="checkbox" name="mec[settings][google_maps_dont_load_api]" <?php if(isset($settings['google_maps_dont_load_api']) and $settings['google_maps_dont_load_api']) echo 'checked="checked"'; ?> /><?php esc_html_e("Don't load Google Maps API library", 'mec'); ?>
                                            </label>
                                            <span class="mec-tooltip">
                                            <div class="box top left">
                                                <h5 class="title"><?php esc_html_e('Google Maps API Load', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Enable this option only if another plugin or your site's current theme is also loading the Google Maps API to avoid conflicts.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Google_Maps_API_Load/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3"><?php esc_html_e('Fullscreen Button', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <label>
                                                <input type="hidden" name="mec[settings][google_maps_fullscreen_button]" value="0" />
                                                <input value="1" type="checkbox" name="mec[settings][google_maps_fullscreen_button]" <?php if(isset($settings['google_maps_fullscreen_button']) and $settings['google_maps_fullscreen_button']) echo 'checked="checked"'; ?> /><?php esc_html_e("Enabled", 'mec'); ?>
                                            </label>
                                        </div>
                                    </div>
                                    <?php do_action('mec_map_options_after', $settings); ?>
                                </div>
                                <?php endif; ?>
                            </div>

                        <?php endif; ?>

                        <div id="export_module_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Export', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][export_module_status]" value="0" />
                                    <input onchange="jQuery('#mec_export_module_options_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][export_module_status]" <?php if(isset($settings['export_module_status']) and $settings['export_module_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show export module (iCal export and add to Google calendars) on event page', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_export_module_options_container_toggle" class="<?php if((isset($settings['export_module_status']) and !$settings['export_module_status']) or !isset($settings['export_module_status'])) echo 'mec-util-hidden'; ?>">
                                <ul id="mec_export_module_options">
                                    <?php
                                    $event_options = array('googlecal'=>__('Google Calendar', 'mec'), 'ical'=>__('iCal', 'mec'));
                                    foreach($event_options as $event_key=>$event_option): ?>
                                    <li id="mec_sn_<?php echo esc_attr($event_key); ?>" data-id="<?php echo esc_attr($event_key); ?>" class="mec-form-row mec-switcher <?php echo ((isset($settings['sn'][$event_key]) and $settings['sn'][$event_key]) ? 'mec-enabled' : 'mec-disabled'); ?>">
                                        <label class="mec-col-3"><?php echo esc_html($event_option); ?></label>
                                        <div class="mec-col-9">
                                            <input class="mec-status" type="hidden" name="mec[settings][sn][<?php echo esc_attr($event_key); ?>]" value="<?php echo (isset($settings['sn'][$event_key]) ? esc_attr($settings['sn'][$event_key]) : '1'); ?>" />
                                            <label for="mec[settings][sn][<?php echo esc_attr($event_key); ?>]"></label>
                                        </div>
                                    </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][export_module_hide_expired]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][export_module_hide_expired]" <?php if(isset($settings['export_module_hide_expired']) and $settings['export_module_hide_expired']) echo 'checked="checked"'; ?> /><?php esc_html_e('Hide for Expired Events', 'mec'); ?>
                                </label>
                            </div>
                        </div>

                        <div id="time_module_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Local Time', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][local_time_module_status]" value="0" />
                                    <input onchange="jQuery('#mec_local_time_module_options_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][local_time_module_status]" <?php if(isset($settings['local_time_module_status']) and $settings['local_time_module_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show event time based on local time of visitor on event page', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_local_time_module_options_container_toggle" class="<?php if((isset($settings['local_time_module_status']) and !$settings['local_time_module_status']) or !isset($settings['local_time_module_status'])) echo 'mec-util-hidden'; ?>">
                            </div>
                        </div>

                        <div id="progress_bar_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Progress Bar', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][progress_bar_status]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][progress_bar_status]" <?php if(isset($settings['progress_bar_status']) and $settings['progress_bar_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable progress bar module', 'mec'); ?>
                                </label>
                            </div>
                        </div>

                        <div id="event_gallery_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Event Gallery', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][event_gallery_status]" value="0" />
                                    <input value="1" type="checkbox" name="mec[settings][event_gallery_status]" <?php if(isset($settings['event_gallery_status']) and $settings['event_gallery_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Enable event gallery module', 'mec'); ?>
                                </label>
                            </div>
                        </div>

                        <?php if($this->main->getPRO()): ?>

                            <div id="qrcode_module_option" class="mec-options-fields">
                                <h4 class="mec-form-subtitle"><?php esc_html_e('QR Code', 'mec'); ?></h4>

                                <?php if(!$this->main->getPRO()): ?>
                                <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                                <?php else: ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][qrcode_module_status]" value="0" />
                                        <input onchange="jQuery('#mec_qrcode_module_options_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][qrcode_module_status]" <?php if(!isset($settings['qrcode_module_status']) or (isset($settings['qrcode_module_status']) and $settings['qrcode_module_status'])) echo 'checked="checked"'; ?> /><?php esc_html_e('Show QR code of event in details page and booking invoice', 'mec'); ?>
                                    </label>
                                </div>
                                <div id="mec_qrcode_module_options_container_toggle" class="<?php if((isset($settings['qrcode_module_status']) and !$settings['qrcode_module_status']) or !isset($settings['qrcode_module_status'])) echo 'mec-util-hidden'; ?>">
                                </div>
                                <?php endif; ?>

                            </div>

                            <div id="weather_module_option" class="mec-options-fields">
                                <h4 class="mec-form-subtitle"><?php esc_html_e('Weather', 'mec'); ?></h4>
                                <?php if(!$this->main->getPRO()): ?>
                                <div class="info-msg"><?php echo sprintf(esc_html__("%s is required to use this feature.", 'mec'), '<a href="'.esc_url($this->main->get_pro_link()).'" target="_blank">'.esc_html__('Pro version of Modern Events Calendar', 'mec').'</a>'); ?></div>
                                <?php else: ?>
                                <div class="mec-form-row">
                                    <label>
                                        <input type="hidden" name="mec[settings][weather_module_status]" value="0" />
                                        <input onchange="jQuery('#mec_weather_module_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][weather_module_status]" <?php if(isset($settings['weather_module_status']) and $settings['weather_module_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show weather module on event page', 'mec'); ?>
                                    </label>
                                </div>
                                <div id="mec_weather_module_container_toggle" class="<?php if((isset($settings['weather_module_status']) and !$settings['weather_module_status']) or !isset($settings['weather_module_status'])) echo 'mec-util-hidden'; ?>">
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_weather_module_wa_api_key"><?php esc_html_e('weatherapi.com API Key', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="text" name="mec[settings][weather_module_wa_api_key]" id="mec_settings_weather_module_wa_api_key" value="<?php echo ((isset($settings['weather_module_wa_api_key']) and trim($settings['weather_module_wa_api_key']) != '') ? $settings['weather_module_wa_api_key'] : ''); ?>">
                                            <p><?php echo sprintf(esc_html__('You can get a free one at %s', 'mec'), '<a href="https://www.weatherapi.com/signup.aspx" target="_blank">weatherapi.com</a>'); ?></p>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label class="mec-col-3" for="mec_settings_weather_module_vs_api_key"><?php esc_html_e('Visual Crossing API Key', 'mec'); ?></label>
                                        <div class="mec-col-9">
                                            <input type="text" name="mec[settings][weather_module_vs_api_key]" id="mec_settings_weather_module_vs_api_key" value="<?php echo ((isset($settings['weather_module_vs_api_key']) and trim($settings['weather_module_vs_api_key']) != '') ? $settings['weather_module_vs_api_key'] : ''); ?>">
                                            <p><?php echo sprintf(esc_html__('You can get an API key at %s', 'mec'), '<a href="https://www.visualcrossing.com" target="_blank">visualcrossing.com</a>'); ?></p>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][weather_module_imperial_units]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][weather_module_imperial_units]" <?php if(isset($settings['weather_module_imperial_units']) and $settings['weather_module_imperial_units']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show weather imperial units', 'mec'); ?>
                                        </label>
                                    </div>
                                    <div class="mec-form-row">
                                        <label>
                                            <input type="hidden" name="mec[settings][weather_module_change_units_button]" value="0" />
                                            <input value="1" type="checkbox" name="mec[settings][weather_module_change_units_button]" <?php if(isset($settings['weather_module_change_units_button']) and $settings['weather_module_change_units_button']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show weather change units button', 'mec'); ?>
                                        </label>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>

                        <?php endif; ?>

                        <div id="social_options" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Social Networks', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][social_network_status]" value="0" />
                                    <input onchange="jQuery('#mec_social_network_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][social_network_status]" <?php if(isset($settings['social_network_status']) and $settings['social_network_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show social network module', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_social_network_container_toggle" class="<?php if((isset($settings['social_network_status']) and !$settings['social_network_status']) or !isset($settings['social_network_status'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <ul id="mec_social_networks" class="mec-form-row">
                                        <?php foreach($socials as $social): ?>
                                            <li id="mec_sn_<?php echo esc_attr($social['id']); ?>" data-id="<?php echo esc_attr($social['id']); ?>" class="mec-form-row mec-switcher <?php echo ((isset($settings['sn'][$social['id']]) and $settings['sn'][$social['id']]) ? 'mec-enabled' : 'mec-disabled'); ?>">
                                                <label class="mec-col-3"><?php echo esc_html($social['name']); ?></label>
                                                <div class="mec-col-9">
                                                    <?php if ($social['id'] == 'vk' || $social['id'] == 'tumblr' ||  $social['id'] == 'pinterest' || $social['id'] == 'flipboard' || $social['id'] == 'pocket' || $social['id'] == 'reddit' || $social['id'] == 'whatsapp' || $social['id'] == 'telegram')  : ?>
                                                    <input class="mec-status" type="hidden" name="mec[settings][sn][<?php echo esc_attr($social['id']); ?>]" value="<?php echo (isset($settings['sn'][$social['id']]) ? esc_attr($settings['sn'][$social['id']]) : '0'); ?>" />
                                                    <label for="mec[settings][sn][<?php echo esc_attr($social['id']); ?>]"></label>
                                                    <?php else : ?>
                                                    <input class="mec-status" type="hidden" name="mec[settings][sn][<?php echo esc_attr($social['id']); ?>]" value="<?php echo (isset($settings['sn'][$social['id']]) ? esc_attr($settings['sn'][$social['id']]) : '1'); ?>" />
                                                    <label for="mec[settings][sn][<?php echo esc_attr($social['id']); ?>]"></label>
                                                    <?php endif; ?>
                                                </div>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div id="next_event_option" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Next Event', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="hidden" name="mec[settings][next_event_module_status]" value="0" />
                                    <input onchange="jQuery('#mec_next_previous_event_container_toggle').toggle();" value="1" type="checkbox" name="mec[settings][next_event_module_status]" <?php if(isset($settings['next_event_module_status']) and $settings['next_event_module_status']) echo 'checked="checked"'; ?> /><?php esc_html_e('Show next event module on event page', 'mec'); ?>
                                </label>
                            </div>
                            <div id="mec_next_previous_event_container_toggle" class="<?php if((isset($settings['next_event_module_status']) and !$settings['next_event_module_status']) or !isset($settings['next_event_module_status'])) echo 'mec-util-hidden'; ?>">
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_next_event_module_method"><?php esc_html_e('Method', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_next_event_module_method" name="mec[settings][next_event_module_method]">
                                            <option value="occurrence" <?php echo ((isset($settings['next_event_module_method']) and $settings['next_event_module_method'] == 'occurrence') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Next Occurrence of Current Event', 'mec'); ?></option>
                                            <option value="multiple" <?php echo ((isset($settings['next_event_module_method']) and $settings['next_event_module_method'] == 'multiple') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Multiple Occurrences of Current Event', 'mec'); ?></option>
                                            <option value="event" <?php echo ((isset($settings['next_event_module_method']) and $settings['next_event_module_method'] == 'event') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Next Occurrence of Other Events', 'mec'); ?></option>
                                        </select>
                                    </div>
                                </div>
                                <div class="mec-form-row" id="mec_settings_next_event_module_multiple_count_wrapper" style="<?php echo ((isset($settings['next_event_module_method']) and $settings['next_event_module_method'] == 'multiple') ? '' : 'display: none;'); ?>">
                                    <label class="mec-col-3" for="mec_settings_next_event_module_multiple_count"><?php esc_html_e('Count of Events', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="number" id="mec_settings_next_event_module_multiple_count" name="mec[settings][next_event_module_multiple_count]" value="<?php echo ((isset($settings['next_event_module_multiple_count']) and trim($settings['next_event_module_multiple_count']) != '') ? $settings['next_event_module_multiple_count'] : '10'); ?>" />
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_next_event_module_date_format1"><?php esc_html_e('Date Format', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <input type="text" id="mec_settings_next_event_module_date_format1" name="mec[settings][next_event_module_date_format1]" value="<?php echo ((isset($settings['next_event_module_date_format1']) and trim($settings['next_event_module_date_format1']) != '') ? $settings['next_event_module_date_format1'] : 'M d Y'); ?>" />
                                        <span class="mec-tooltip">
                                            <div class="box left">
                                                <h5 class="title"><?php esc_html_e('Date Format', 'mec'); ?></h5>
                                                <div class="content"><p><?php esc_attr_e("Specify the event's date format on the next event module.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-modules/#Date_Format/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                            </div>
                                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                                        </span>
                                    </div>
                                </div>
                                <div class="mec-form-row">
                                    <label class="mec-col-3" for="mec_settings_next_event_module_active_button"><?php esc_html_e('Display Active Occurrence Button', 'mec'); ?></label>
                                    <div class="mec-col-9">
                                        <select id="mec_settings_next_event_module_active_button" name="mec[settings][next_event_module_active_button]">
                                            <option value="0" <?php echo ((isset($settings['next_event_module_active_button']) and $settings['next_event_module_active_button'] == '0') ? 'selected="selected"' : ''); ?>><?php esc_html_e('No', 'mec'); ?></option>
                                            <option value="1" <?php echo ((isset($settings['next_event_module_active_button']) and $settings['next_event_module_active_button'] == '1') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Yes', 'mec'); ?></option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="mec-options-fields">
                            <?php wp_nonce_field('mec_options_form'); ?>
                            <button style="display: none;" id="mec_modules_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Save Changes', 'mec'); ?></button>
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

<?php
$this->getFactory()->params('footer', function()
{
    ?>
    <script>
    jQuery(document).ready(function()
    {
        jQuery(".dpr-save-btn").on('click', function(event)
        {
            event.preventDefault();
            jQuery("#mec_modules_form_button").trigger('click');
        });

        jQuery('#mec_settings_next_event_module_method').on('change', function()
        {
            var value = jQuery(this).val();
            var $wrapper = jQuery('#mec_settings_next_event_module_multiple_count_wrapper');

            if(value === 'multiple') $wrapper.show();
            else $wrapper.hide();
        });
    });

    jQuery("#mec_modules_form").on('submit', function(event)
    {
        event.preventDefault();

        // Add loading Class to the button
        jQuery(".dpr-save-btn").addClass('loading').text("<?php echo esc_js(esc_attr__('Saved', 'mec')); ?>");
        jQuery('<div class="wns-saved-settings"><?php echo esc_js(esc_attr__('Settings Saved!', 'mec')); ?></div>').insertBefore('#wns-be-content');

        if(jQuery(".mec-purchase-verify").text() != '<?php echo esc_js(esc_attr__('Verified', 'mec')); ?>')
        {
            jQuery(".mec-purchase-verify").text("<?php echo esc_js(esc_attr__('Checking ...', 'mec')); ?>");
        }

        var settings = jQuery("#mec_modules_form").serialize();
        jQuery.ajax(
        {
            type: "POST",
            url: ajaxurl,
            data: "action=mec_save_settings&"+settings,
            beforeSend: function () {
                jQuery('.wns-be-main').append('<div class="mec-loarder-wrap mec-settings-loader"><div class="mec-loarder"><div></div><div></div><div></div></div></div>');
            },
            success: function(data)
            {
                // Remove the loading Class to the button
                setTimeout(function()
                {
                    jQuery(".dpr-save-btn").removeClass('loading').text("<?php echo esc_js(esc_attr__('Save Changes', 'mec')); ?>");
                    jQuery('.wns-saved-settings').remove();
                    jQuery('.mec-loarder-wrap').remove();
                    if(jQuery(".mec-purchase-verify").text() != '<?php echo esc_js(esc_attr__('Verified', 'mec')); ?>')
                    {
                        jQuery(".mec-purchase-verify").text("<?php echo esc_js(esc_attr__('Please Refresh Page', 'mec')); ?>");
                    }
                }, 1000);
            },
            error: function(jqXHR, textStatus, errorThrown)
            {
                // Remove the loading Class to the button
                setTimeout(function()
                {
                    jQuery(".dpr-save-btn").removeClass('loading').text("<?php echo esc_js(esc_attr__('Save Changes', 'mec')); ?>");
                    jQuery('.wns-saved-settings').remove();
                    jQuery('.mec-loarder-wrap').remove();
                }, 1000);
            }
        });
    });
    </script>
    <?php
});