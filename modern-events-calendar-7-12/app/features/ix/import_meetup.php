<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_feature_ix $this */

$ix_options = $this->main->get_ix_options();
?>
<div class="wrap" id="mec-wrap">
    <h1><?php esc_html_e('MEC Import / Export', 'mec'); ?></h1>
    <h2 class="nav-tab-wrapper">
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->remove_qs_var('tab'))); ?>" class="nav-tab"><?php echo esc_html__('Google Cal. Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-g-calendar-export'))); ?>" class="nav-tab"><?php echo esc_html__('Google Cal. Export', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-f-calendar-import'))); ?>" class="nav-tab"><?php echo esc_html__('Facebook Cal. Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-meetup-import'))); ?>" class="nav-tab nav-tab-active"><?php echo esc_html__('Meetup Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-sync'))); ?>" class="nav-tab"><?php echo esc_html__('Synchronization', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-export'))); ?>" class="nav-tab"><?php echo esc_html__('Export', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-import'))); ?>" class="nav-tab"><?php echo esc_html__('Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-thirdparty'))); ?>" class="nav-tab"><?php echo esc_html__('Third Party Plugins', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->add_qs_var('tab', 'MEC-test-data'))); ?>" class="nav-tab"><?php echo esc_html__('Test Data', 'mec'); ?></a>
    </h2>
    <div class="mec-container">
        <div class="import-content w-clearfix extra">
            <div class="mec-meetup-import">
                <?php if($this->action === 'meetup-import-config'): ?>
                <form id="mec_meetup_import_form" action="<?php echo esc_url($this->main->get_full_url()); ?>" method="POST">
                    <h3><?php esc_html_e('Connect your account', 'mec'); ?></h3>
                    <p class="description"><?php echo sprintf(esc_html__('In order to import your events from meetup, first you need an OAuth client in meetup. You can create one using the %s link.', 'mec'), '<a href="https://www.meetup.com/api/oauth/list/" target="_blank">https://www.meetup.com/api/oauth/list/</a>'); ?></p>
                    <p class="description"><?php echo sprintf(esc_html__('For the redirect URL, put the %s URL.', 'mec'), '<a href="'.get_home_url().'" target="_blank">'.get_home_url().'</a>'); ?></p>
                    <div class="mec-form-row" style="margin-top: 30px;">
                        <label class="mec-col-3" for="mec_ix_meetup_public_key"><?php esc_html_e('Meetup Public Key', 'mec'); ?></label>
                        <div class="mec-col-4">
                            <input type="text" id="mec_ix_meetup_public_key" name="ix[meetup_public_key]" value="<?php echo isset($ix_options['meetup_public_key']) ? esc_attr($ix_options['meetup_public_key']) : ''; ?>" required="required" />
                        </div>
                    </div>
                    <div class="mec-form-row">
                        <label class="mec-col-3" for="mec_ix_meetup_secret_key"><?php esc_html_e('Meetup Secret Key', 'mec'); ?></label>
                        <div class="mec-col-4">
                            <input type="text" id="mec_ix_meetup_secret_key" name="ix[meetup_secret_key]" value="<?php echo isset($ix_options['meetup_secret_key']) ? esc_attr($ix_options['meetup_secret_key']) : ''; ?>" required="required" />
                        </div>
                    </div>
                    <div class="mec-form-row" style="padding-bottom: 10px;">
                        <label class="mec-col-3" for="mec_ix_meetup_group_name"><?php esc_html_e('Group URL Name', 'mec'); ?></label>
                        <div class="mec-col-4">
                            <input type="text" id="mec_ix_meetup_group_name" name="ix[meetup_group_name]" value="<?php echo isset($ix_options['meetup_group_name']) ? esc_attr($ix_options['meetup_group_name']) : ''; ?>" required="required" />
                        </div>
                    </div>
                    <p class="description"><?php echo sprintf(esc_html__('If your group URL is https://www.meetup.com/blahblahblah/ then the URL name is %s.', 'mec'), '<strong>blahblahblah</strong>'); ?></p>
                    <div>
                        <input type="hidden" name="mec-ix-action" value="meetup-import-login" />
                        <button id="mec_ix_meetup_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Start', 'mec'); ?></button>
                    </div>
                </form>
                <?php elseif($this->action === 'meetup-import-login'): ?>
                <div class="mec-ix-meetup-login">
                    <h3><?php esc_html_e('Connect your account', 'mec'); ?></h3>
                    <p class="description"><?php echo esc_html__('Please use the following button to login to your meetup account and allow your website to access your meetup account.', 'mec'); ?></p>
                    <a class="button mec-button-primary" href="<?php echo esc_url_raw($this->response['login']); ?>"><?php esc_html_e('Login to Meetup', 'mec'); ?></a>
                </div>
                <?php elseif($this->action === 'meetup-import-start'): ?>
                <div class="mec-ix-meetup-started">
                    <?php if($this->response['success'] == 0): ?>
                    <div class="mec-error"><?php echo MEC_kses::element($this->response['error']); ?></div>
                    <a class="button mec-button-primary" href="<?php echo $this->main->URL('backend').'admin.php?page=MEC-ix&tab=MEC-meetup-import'; ?>"><?php esc_html_e('Start Again', 'mec'); ?></a>
                    <?php else: ?>
                    <form id="mec_meetup_do_form" action="<?php echo esc_url($this->main->remove_qs_var('mec-ix-action', $this->main->get_full_url())); ?>" method="POST">
                        <div class="mec-xi-meetup-events mec-options-fields">
                            <h4><?php esc_html_e('Meetup Events', 'mec'); ?></h4>
                            <div class="mec-success"><?php echo sprintf(esc_html__('We found %s events for %s group. Please select your desired events to import.', 'mec'), '<strong>'.esc_html($this->response['data']['count']).'</strong>', '<strong>'.esc_html($this->response['data']['title']).'</strong>'); ?></div>
                            <ul class="mec-select-deselect-actions" data-for="#mec_import_meetup_events">
                                <li data-action="select-all"><?php esc_html_e('Select All', 'mec'); ?></li>
                                <li data-action="deselect-all"><?php esc_html_e('Deselect All', 'mec'); ?></li>
                                <li data-action="toggle"><?php esc_html_e('Toggle', 'mec'); ?></li>
                            </ul>
                            <ul id="mec_import_meetup_events">
                                <?php foreach($this->response['data']['events'] as $event): ?>
                                <li>
                                    <label>
                                        <input type="checkbox" name="m-events[]" value="<?php echo esc_attr($event['id']); ?>" checked="checked" />
                                        <span><?php echo sprintf(esc_html__('Event Title: %s Event Date: %s - %s', 'mec'), '<strong>'.esc_html($event['title']).'</strong>', '<strong>'.esc_html($event['start']).'</strong>', '<strong>'.esc_html($event['end']).'</strong>'); ?></span>
                                    </label>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                        <div class="mec-options-fields">
                            <h4><?php esc_html_e('Import Options', 'mec'); ?></h4>
                            <div class="mec-form-row">
                                <label>
                                    <input type="checkbox" name="ix[import_organizers]" value="1" checked="checked" />
                                    <?php esc_html_e('Import Organizers', 'mec'); ?>
                                </label>
                            </div>
                            <div class="mec-form-row">
                                <label>
                                    <input type="checkbox" name="ix[import_locations]" value="1" checked="checked" />
                                    <?php esc_html_e('Import Locations', 'mec'); ?>
                                </label>
                            </div>
                            <input type="hidden" name="mec-ix-action" value="meetup-import-do" />
                            <input type="hidden" name="ix[meetup_api_key]" value="<?php echo (isset($this->ix['meetup_api_key']) ? esc_attr($this->ix['meetup_api_key']) : ''); ?>" />
                            <input type="hidden" name="ix[meetup_group_url]" value="<?php echo (isset($this->ix['meetup_group_url']) ? esc_attr($this->ix['meetup_group_url']) : ''); ?>" />
                            <button id="mec_ix_meetup_import_do_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Import', 'mec'); ?></button>
                        </div>
                    </form>
                    <?php endif; ?>
                </div>
                <?php elseif($this->action == 'meetup-import-do'): ?>
                <div class="mec-ix-meetup-import-do">
                    <?php if($this->response['success'] == 0): ?>
                    <div class="mec-error"><?php echo MEC_kses::element($this->response['error']); ?></div>
                    <?php else: ?>
                    <div class="mec-success"><?php echo sprintf(esc_html__('%s events successfully imported to your website from meetup.', 'mec'), '<strong>'.count($this->response['data']).'</strong>'); ?></div>
                    <div class="info-msg"><strong><?php esc_html_e('Attention', 'mec'); ?>:</strong> <?php esc_html_e("Although we tried our best to make the events completely compatible with MEC but some modification might be needed. We suggest you to edit the imported listings one by one on MEC edit event page and make sure thay're correct.", 'mec'); ?></div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>