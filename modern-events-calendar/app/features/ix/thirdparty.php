<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_feature_ix $this */

$third_parties = $this->main->get_integrated_plugins_for_import();
?>
<div class="wrap" id="mec-wrap">
    <h1><?php esc_html_e('MEC Import / Export', 'mec'); ?></h1>
    <h2 class="nav-tab-wrapper">
        <a href="<?php echo esc_url($this->main->remove_qs_var('tab')); ?>" class="nav-tab"><?php echo esc_html__('Google Cal. Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-g-calendar-export')); ?>" class="nav-tab"><?php echo esc_html__('Google Cal. Export', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-f-calendar-import')); ?>" class="nav-tab"><?php echo esc_html__('Facebook Cal. Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-meetup-import')); ?>" class="nav-tab"><?php echo esc_html__('Meetup Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-sync')); ?>" class="nav-tab"><?php echo esc_html__('Synchronization', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-export')); ?>" class="nav-tab"><?php echo esc_html__('Export', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-import')); ?>" class="nav-tab"><?php echo esc_html__('Import', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-thirdparty')); ?>" class="nav-tab nav-tab-active"><?php echo esc_html__('Third Party Plugins', 'mec'); ?></a>
        <a href="<?php echo esc_url($this->main->add_qs_var('tab', 'MEC-test-data')); ?>" class="nav-tab"><?php echo esc_html__('Test Data', 'mec'); ?></a>
    </h2>
    <div class="mec-container">
        <div class="import-content w-clearfix extra">
            <h3><?php esc_html_e('Third Party Plugins', 'mec'); ?></h3>
            <form id="mec_thirdparty_import_form" action="<?php echo esc_url($this->main->get_full_url()); ?>" method="POST">
                <div class="mec-form-row">
                    <p><?php echo sprintf(esc_html__("You can import events from the following integrated plugins to %s.", 'mec'), '<strong>'.esc_html__('Modern Events Calendar', 'mec').'</strong>'); ?></p>
                </div>
                <div class="mec-form-row">
                    <select name="ix[third-party]" id="third_party" title="<?php esc_attr_e('Third Party', 'mec') ?>">
                        <?php foreach($third_parties as $third_party=>$label): ?>
                            <option <?php echo ((isset($this->ix['third-party']) and $this->ix['third-party'] == $third_party) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($third_party); ?>"><?php echo esc_html($label); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <input type="hidden" name="mec-ix-action" value="thirdparty-import-start" />
                    <button class="button button-primary mec-button-primary mec-btn-2"><?php esc_html_e('Start', 'mec'); ?></button>
                </div>
            </form>

            <?php if($this->action == 'thirdparty-import-start'): ?>
                <div class="mec-ix-thirdparty-import-started">
                    <?php if($this->response['success'] == 0): ?>
                        <div class="mec-error"><?php echo MEC_kses::element($this->response['message']); ?></div>
                    <?php elseif(isset($this->response['data']['count']) && !$this->response['data']['count']): ?>
                        <div class="mec-error"><?php echo esc_html__('No events found!', 'mec'); ?></div>
                    <?php else: ?>
                        <form id="mec_thirdparty_import_do_form" action="<?php echo esc_url($this->main->get_full_url()); ?>" method="POST">
                            <div id="mec_ix_thirdparty_import_options_wrapper">
                                <div class="mec-ix-thirdparty-import-events mec-options-fields">
                                    <h4><?php esc_html_e('Found Events', 'mec'); ?></h4>
                                    <div class="mec-success"><?php echo sprintf(esc_html__('We found %s events. Please select your desired events to import.', 'mec'), '<strong>'.esc_html($this->response['data']['count']).'</strong>'); ?></div>
                                    <ul class="mec-select-deselect-actions" data-for="#mec_import_thirdparty_events">
                                        <li data-action="select-all"><?php esc_html_e('Select All', 'mec'); ?></li>
                                        <li data-action="deselect-all"><?php esc_html_e('Deselect All', 'mec'); ?></li>
                                        <li data-action="toggle"><?php esc_html_e('Toggle', 'mec'); ?></li>
                                    </ul>
                                    <ul id="mec_import_thirdparty_events">
                                        <?php foreach($this->response['data']['events'] as $event): if(trim($event->post_title) == '') continue; ?>
                                        <li>
                                            <label>
                                                <input type="checkbox" name="tp-events[]" value="<?php echo esc_attr($event->ID); ?>" checked="checked" />
                                                <span><?php echo sprintf(esc_html__('Event Title: %s', 'mec'), '<strong>'.esc_html($event->post_title).'</strong>'); ?></span>
                                            </label>
                                        </li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                                <div class="mec-options-fields">
                                    <h4><?php esc_html_e('Import Options', 'mec'); ?></h4>

                                    <?php if(!in_array($this->ix['third-party'], array('event-espresso', 'events-manager-single', 'events-manager-recurring'))): ?>
                                    <div class="mec-form-row" style="padding-bottom: 5px;">
                                        <label>
                                            <input type="checkbox" name="ix[import_organizers]" value="1" checked="checked" />
                                            <?php
                                            if($this->ix['third-party'] == 'weekly-class') esc_html_e('Import Instructors', 'mec');
                                            else esc_html_e('Import Organizers', 'mec');
                                            ?>
                                        </label>
                                    </div>
                                    <?php endif; ?>

                                    <?php if(in_array($this->ix['third-party'], array('the-events-calendar'))): ?>
                                    <div class="mec-form-row" style="padding-bottom: 5px;">
                                        <label>
                                            <input type="checkbox" name="ix[import_author]" value="1" checked="checked" />
                                            <?php esc_html_e('Import Author', 'mec'); ?>
                                        </label>
                                    </div>
                                    <?php endif; ?>

                                    <div class="mec-form-row" style="padding-bottom: 5px;">
                                        <label>
                                            <input type="checkbox" name="ix[import_locations]" value="1" checked="checked" />
                                            <?php esc_html_e('Import Locations', 'mec'); ?>
                                        </label>
                                    </div>
                                    <div class="mec-form-row" style="padding-bottom: 5px;">
                                        <label>
                                            <input type="checkbox" name="ix[import_categories]" value="1" checked="checked" />
                                            <?php
                                                if($this->ix['third-party'] == 'weekly-class') esc_html_e('Import Class Types', 'mec');
                                                else esc_html_e('Import Categories', 'mec');
                                            ?>
                                        </label>
                                    </div>
                                    <div class="mec-form-row" style="padding-bottom: 0;">
                                        <label>
                                            <input type="checkbox" name="ix[import_featured_image]" value="1" checked="checked" />
                                            <?php esc_html_e('Import Featured Image', 'mec'); ?>
                                        </label>
                                    </div>
                                    <input type="hidden" name="mec-ix-action" value="thirdparty-import-do" />
                                    <input type="hidden" name="ix[third-party]" value="<?php echo esc_attr($this->ix['third-party']); ?>" />
                                    <?php wp_nonce_field('mec_ix_thirdparty_import'); ?>
                                </div>
                            </div>
                            <button id="mec_ix_thirdparty_import_do_form_button" class="button button-primary mec-button-primary" type="submit"><?php esc_html_e('Import', 'mec'); ?></button>
                        </form>
                        <div id="mec_ix_thirdparty_import_logs"></div>
                    <?php endif; ?>
                </div>
            <?php elseif($this->action == 'thirdparty-import-do'): ?>
                <div class="mec-col-12 mec-ix-thirdparty-import-do">
                    <?php if($this->response['success'] == 0): ?>
                        <div class="mec-error"><?php echo MEC_kses::element($this->response['message']); ?></div>
                    <?php else: ?>
                        <div class="mec-success"><?php echo sprintf(esc_html__('%s events successfully imported to your website.', 'mec'), '<strong>'.esc_html($this->response['data']).'</strong>'); ?></div>
                        <div class="info-msg"><strong><?php esc_html_e('Attention', 'mec'); ?>:</strong> <?php esc_html_e("Although we tried our best to make the events completely compatible with MEC but some modification might be needed. We suggest you to edit the imported listings one by one on MEC edit event page and make sure they are correct.", 'mec'); ?></div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>
<?php $this->factory->params('footer', function()
{
    ?>
    <script>
    jQuery("#mec_thirdparty_import_do_form").on("submit", function(event)
    {
        event.preventDefault();

        mec_ix_thirdparty_start();
        mec_ix_thirdparty_import(1);
    });

    function mec_ix_thirdparty_import(step)
    {
        var data = jQuery("#mec_thirdparty_import_do_form").serialize();
        jQuery.ajax(
        {
            type: "POST",
            url: ajaxurl,
            data: "action=mec_ix_thirdparty_import&step="+step+"&"+data,
            success: function(data)
            {
                mec_ix_thirdparty_log(data.imported + " / " + data.all + " <?php echo esc_js(esc_html__('imported.', 'mec')); ?>");

                if(data.finished)
                {
                    mec_ix_thirdparty_log('<div class="info-msg"><strong><?php esc_html_e('Attention', 'mec'); ?>:</strong> <?php esc_html_e("Although we tried our best to make the events completely compatible with MEC but some modification might be needed. We suggest you to edit the imported listings one by one on MEC edit event page and make sure they are correct.", 'mec'); ?></div>');
                    mec_ix_thirdparty_finish('success');
                }
                else
                {
                    setTimeout(function()
                    {
                        mec_ix_thirdparty_import(data.next_step);
                    }, 500);
                }
            },
            error: function(jqXHR, textStatus, errorThrown)
            {
                mec_ix_thirdparty_log("<?php echo esc_js(esc_html__('An unknown error occurred! Most probably due to an error on the server.', 'mec')); ?>", 'error');
                mec_ix_thirdparty_finish('log');
            }
        });
    }

    function mec_ix_thirdparty_log(message, type)
    {
        let html = '<p>'+message+'</p>';

        if(type === 'error') html = '<div class="mec-error">'+message+'</div>';
        else if(type === 'success') html = '<div class="mec-success">'+message+'</div>';

        const $log_wrapper = jQuery("#mec_ix_thirdparty_import_logs");
        $log_wrapper.prepend(html);
    }

    function mec_ix_thirdparty_start()
    {
        // Elements
        const $button = jQuery("#mec_ix_thirdparty_import_do_form_button");
        const $form_wrapper = jQuery("#mec_ix_thirdparty_import_options_wrapper");

        // Add loading Class to the button
        $button.prop("disabled", "disabled").text("<?php echo esc_js(esc_html__('Importing ... ', 'mec')); ?>");

        // Slide the form up
        $form_wrapper.slideUp(800);

        mec_ix_thirdparty_log("<?php echo esc_js(esc_html__("The import is started ...", 'mec')); ?>");
        mec_ix_thirdparty_log("<?php echo esc_js(esc_html__("Please keep this page open untill you see the finish message.", 'mec')); ?>");
    }

    function mec_ix_thirdparty_finish(type)
    {
        mec_ix_thirdparty_log("<strong><?php echo esc_js(esc_html__("The import is finished.", 'mec')); ?></strong>", type);
        jQuery("#mec_ix_thirdparty_import_do_form_button").remove();
    }
    </script>
    <?php
});