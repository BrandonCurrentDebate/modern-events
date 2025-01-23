<?php
/** no direct access **/
defined('MECEXEC') or die();
    
$ix_options = $this->main->get_ix_options();
?>
<div class="wrap" id="mec-wrap">
    <h1><?php esc_html_e('MEC Import / Export', 'mec'); ?></h1>
    <h2 class="nav-tab-wrapper">
        <a href="<?php echo esc_url($this->main->remove_qs_var('tab')); ?>" class="nav-tab"><?php echo esc_html__('Google Cal. Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-g-calendar-export')); ?>" class="nav-tab"><?php echo esc_html__('Google Cal. Export', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-f-calendar-import')); ?>" class="nav-tab nav-tab-active"><?php echo esc_html__('Facebook Cal. Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-meetup-import')); ?>" class="nav-tab"><?php echo esc_html__('Meetup Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-sync')); ?>" class="nav-tab"><?php echo esc_html__('Synchronization', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-export')); ?>" class="nav-tab"><?php echo esc_html__('Export', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-import')); ?>" class="nav-tab"><?php echo esc_html__('Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-thirdparty')); ?>" class="nav-tab"><?php echo esc_html__('Third Party Plugins', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-test-data')); ?>" class="nav-tab"><?php echo esc_html__('Test Data', 'mec'); ?></a>
    </h2>
    <div class="mec-container">
        <div class="import-content w-clearfix extra">
            <?php if(version_compare(PHP_VERSION, '5.4.0', '<')): ?>
            <p class="mec-error"><?php esc_html_e('The Facebook SDK requires PHP version 5.4 or higher.', 'mec'); ?></p>
            <?php else: ?>
            <div class="mec-facebook-import">
                <form id="mec_facebook_import_form" action="<?php echo esc_url($this->main->get_full_url()); ?>" method="POST">
                    <h3><?php esc_html_e('Import from Facebook Calendar', 'mec'); ?></h3>
                    <p class="description"><?php esc_html_e('Import all of your Facebook events into MEC.', 'mec'); ?> <a href="https://webnus.net/dox/modern-events-calendar/import-facebook-events/" target="_blank"><?php esc_html_e('Documentation', 'mec'); ?></a></p>
                    <div class="mec-form-row">
                        <label class="mec-col-3" for="mec_ix_facebook_app_token"><?php esc_html_e('Facebook Page Access Token', 'mec'); ?></label>
                        <div class="mec-col-4">
                            <input type="text" id="mec_ix_facebook_app_token" name="ix[facebook_app_token]" value="<?php echo (isset($ix_options['facebook_app_token']) ? esc_attr($ix_options['facebook_app_token']) : ''); ?>" />
                        </div>
                    </div>
                    <div class="mec-form-row">
                        <label class="mec-col-3" for="mec_ix_facebook_import_page_link"><?php esc_html_e('Facebook Page Link', 'mec'); ?></label>
                        <div class="mec-col-4">
                            <input type="text" id="mec_ix_facebook_import_page_link" name="ix[facebook_import_page_link]" value="<?php echo (isset($ix_options['facebook_import_page_link']) ? esc_attr($ix_options['facebook_import_page_link']) : ''); ?>" />
                        </div>
                    </div>
                    <div class="mec-options-fields">
                        <input type="hidden" name="mec-ix-action" value="facebook-calendar-import-start" />
                        <button id="mec_ix_facebook_import_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Start', 'mec'); ?></button>
                    </div>
                </form>
            </div>
            <?php if($this->action == 'facebook-calendar-import-start'): ?>
            <div class="mec-ix-facebook-import-started">
                <?php if($this->response['success'] == 0): ?>
                <div class="mec-error"><?php echo MEC_kses::element($this->response['message']); ?></div>
                <?php else: ?>
                <form id="mec_facebook_import_do_form" action="<?php echo esc_url($this->main->get_full_url()); ?>" method="POST">
                    <div class="mec-xi-facebook-import-events mec-options-fields">
                        <h4><?php esc_html_e('Facebook Events', 'mec'); ?></h4>
                        <div class="mec-success"><?php echo sprintf(esc_html__('We found %s events for %s page. Please select your desired events to import.', 'mec'), '<strong>'.esc_html($this->response['data']['count']).'</strong>', '<strong>'.esc_html($this->response['data']['name']).'</strong>'); ?></div>
                        <ul class="mec-select-deselect-actions" data-for="#mec_import_f_calendar_events">
                            <li data-action="select-all"><?php esc_html_e('Select All', 'mec'); ?></li>
                            <li data-action="deselect-all"><?php esc_html_e('Deselect All', 'mec'); ?></li>
                            <li data-action="toggle"><?php esc_html_e('Toggle', 'mec'); ?></li>
                        </ul>
                        <ul id="mec_import_f_calendar_events">
                            <?php foreach($this->response['data']['events'] as $event): if(trim($event['name']) == '') continue; ?>
                            <li>
                                <label>
                                    <input type="checkbox" name="f-events[]" value="<?php echo esc_attr($event['id']); ?>" checked="checked" />
                                    <span><?php echo sprintf(esc_html__('Event Title: %s', 'mec'), '<strong>'.esc_html($event['name']).'</strong>'); ?></span>
                                </label>
                            </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                    <div class="mec-options-fields">
                        <h4><?php esc_html_e('Import Options', 'mec'); ?></h4>
                        <div class="mec-form-row">
                            <label>
                                <input type="checkbox" name="ix[import_locations]" value="1" checked="checked" />
                                <?php esc_html_e('Import Locations', 'mec'); ?>
                            </label>
                        </div>
                        <div class="mec-form-row">
                            <label>
                                <input type="checkbox" name="ix[import_link_event]" value="1" />
                                <?php esc_html_e('Import Facebook Link as Event Link', 'mec'); ?>
                            </label>
                        </div>
                        <div class="mec-form-row">
                            <label>
                                <input type="checkbox" name="ix[import_link_more_info]" value="1" />
                                <?php esc_html_e('Import Facebook Link as More Info Link', 'mec'); ?>
                            </label>
                        </div>
                        <input type="hidden" name="mec-ix-action" value="facebook-calendar-import-do" />
                        <input type="hidden" name="ix[facebook_import_page_link]" value="<?php echo (isset($this->ix['facebook_import_page_link']) ? esc_attr($this->ix['facebook_import_page_link']) : ''); ?>" />
                        <input type="hidden" name="ix[facebook_app_token]" value="<?php echo (isset($this->ix['facebook_app_token']) ? esc_attr($this->ix['facebook_app_token']) : ''); ?>" />
                        <button id="mec_ix_facebook_import_do_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Import', 'mec'); ?></button>
                    </div>
                </form>
                <?php endif; ?>
            </div>
            <?php elseif($this->action == 'facebook-calendar-import-do'): ?>
            <div class="mec-col-6 mec-ix-facebook-import-do">
                <?php if($this->response['success'] == 0): ?>
                <div class="mec-error"><?php echo MEC_kses::element($this->response['message']); ?></div>
                <?php else: ?>
                <div class="mec-success"><?php echo sprintf(esc_html__('%s events successfully imported to your website from Facebook Calendar.', 'mec'), '<strong>'.count($this->response['data']).'</strong>'); ?></div>
                <?php endif; ?>
            </div>
            <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>
</div>