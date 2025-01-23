<?php

namespace MEC\FES;

use MEC\Singleton;
use WP_Post;

class FormBuilder extends Singleton {

    /**
     * Booking demo check
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return bool
     */
    private static function booking_demo_check( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        if ( $is_edit_mode && ( !isset($settings['booking_status']) || !$settings['booking_status'] ) ) {

			echo '<div class="mec-content-notification">
					<p>'
						.'<span>'
							. esc_html__('This widget is displayed if booking module is active. In order for the widget in this page to be displayed correctly, please activate Booking module.', 'mec')
						.'</span>'
						.'<a href="https://webnus.net/dox/modern-events-calendar/booking/" target="_blank">' . esc_html__('How to set booking module', 'mec') . ' </a>'
					.'</p>'
				.'</div>';

            return false;
		}

        return true;
    }

    /**
     * Return title html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function title( $post, $atts = array() ){
        ?>
            <div class="mec-form-row mec-fes-title">
                <label for="mec_fes_title"><?php esc_html_e('Title', 'mec'); ?> <span class="mec-required">*</span></label>
                <input type="text" name="mec[title]" id="mec_fes_title" value="<?php echo (isset($post->post_title) ? esc_attr($post->post_title) : ''); ?>" required="required" />
            </div>
        <?php
    }

    /**
     * Return editor html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function editor( $post, $atts = array() ){
        ?>
            <div class="mec-form-row mec-fes-editor">
                <?php wp_editor(
                    (isset($post->post_content) ? $post->post_content : ''),
                    'mec_fes_content',
                    array(
                        'textarea_name'=>'mec[content]',
                        'textarea_rows' => $atts['textarea_rows'] ?? get_option('default_post_edit_rows', 10),
                    )
                ); ?>
            </div>
        <?php
    }

    /**
     * Return excerpt html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function excerpt( $post, $atts = array() ){

        $required = isset( $atts['required'] ) && $atts['required'] ? true : false;
        $excerpt = isset($post->post_excerpt) ? esc_textarea($post->post_excerpt) : '';

        $placeholder = $required ? __('Event Excerpt', 'mec') : __('Optional Event Excerpt', 'mec');
        ?>
            <div class="mec-meta-box-fields mec-fes-excerpt" id="mec-excerpt">
                <h4><?php esc_html_e('Excerpt', 'mec'); ?> <?php echo ( $required ? '<span class="mec-required">*</span>' : ''); ?></h4>
                <div class="mec-form-row">
                    <div class="mec-col-12">
                        <textarea name="mec[excerpt]" id="mec_fes_excerpt" class="widefat" rows="10" title="<?php echo esc_attr($placeholder); ?>" placeholder="<?php echo esc_attr($placeholder); ?>" <?php echo ( $required ? 'required' : ''); ?>><?php echo $excerpt; ?></textarea>
                    </div>
                </div>
            </div>
        <?php
    }

    /**
     * Return datetime html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function datetime( $post, $atts = array() ){

        $post_id = $post->ID;

        // This date format used for datepicker
        $datepicker_format = $atts['datepicker_format'] ?? 'Y-m-d';
        $time_format = $atts['time_format'] ?? 12;
        $required = (isset($atts['required']) and $atts['required']);

        $allday = get_post_meta($post_id, 'mec_allday', true);
        $one_occurrence = get_post_meta($post_id, 'one_occurrence', true);
        $comment = get_post_meta($post_id, 'mec_comment', true);
        $hide_time = get_post_meta($post_id, 'mec_hide_time', true);

        // MEC Main
        $main = \MEC\Base::get_main();

        // Settings
        $settings = $main->get_settings();

        $hide_end_time_global = isset($settings['hide_event_end_time']) && $settings['hide_event_end_time'];
        $hide_end_time = get_post_meta($post_id, 'mec_hide_end_time', true);

        if($hide_end_time_global) $hide_end_time = 1;

        $start_date = get_post_meta($post_id, 'mec_start_date', true);

        // Advanced Repeating Day
        $advanced_days = get_post_meta( $post->ID, 'mec_advanced_days', true );
        $advanced_days = (is_array($advanced_days)) ? $advanced_days : [];
        $advanced_str = (count($advanced_days)) ? implode('-', $advanced_days) : '';

        $start_time_hour = get_post_meta($post_id, 'mec_start_time_hour', true);
        if(trim($start_time_hour) == '') $start_time_hour = 8;

        $start_time_minutes = get_post_meta($post_id, 'mec_start_time_minutes', true);
        if(trim($start_time_minutes) == '') $start_time_minutes = 0;

        $start_time_ampm = get_post_meta($post_id, 'mec_start_time_ampm', true);
        if(trim($start_time_ampm) == '') $start_time_ampm = 'AM';

        $end_date = get_post_meta($post_id, 'mec_end_date', true);

        $end_time_hour = get_post_meta($post_id, 'mec_end_time_hour', true);
        if(trim($end_time_hour) == '') $end_time_hour = 6;

        $end_time_minutes = get_post_meta($post_id, 'mec_end_time_minutes', true);
        if(trim($end_time_minutes) == '') $end_time_minutes = 0;

        $end_time_ampm = get_post_meta($post_id, 'mec_end_time_ampm', true);
        if(trim($end_time_ampm) == '') $end_time_ampm = 'PM';

        $repeat_status = get_post_meta($post_id, 'mec_repeat_status', true);
        $repeat_type = get_post_meta($post_id, 'mec_repeat_type', true);
        if(trim($repeat_type) == '') $repeat_type = 'daily';

        $repeat_interval = get_post_meta($post_id, 'mec_repeat_interval', true);
        if(trim($repeat_interval) == '' and in_array($repeat_type, array('daily', 'weekly'))) $repeat_interval = 1;

        $certain_weekdays = get_post_meta($post_id, 'mec_certain_weekdays', true);
        if($repeat_type != 'certain_weekdays') $certain_weekdays = [];

        $in_days_str = get_post_meta($post_id, 'mec_in_days', true);
        $in_days = trim($in_days_str) ? explode(',', $in_days_str) : [];

        $mec_repeat_end = get_post_meta($post_id, 'mec_repeat_end', true);
        if(trim($mec_repeat_end) == '') $mec_repeat_end = 'never';

        $repeat_end_at_occurrences = get_post_meta($post_id, 'mec_repeat_end_at_occurrences', true);
        if(trim($repeat_end_at_occurrences) == '') $repeat_end_at_occurrences = 9;

        $repeat_end_at_date = get_post_meta($post_id, 'mec_repeat_end_at_date', true);
        ?>
            <div class="mec-meta-box-fields mec-fes-datetime" id="mec-date-time">
                <h4><?php esc_html_e('Date and Time', 'mec'); ?></h4>
                <div id="mec_meta_box_date_form">
                    <div class="mec-title">
                        <span class="mec-dashicons dashicons dashicons-calendar-alt"></span>
                        <label for="mec_start_date"><?php esc_html_e('Start Date', 'mec'); ?> <?php echo ($required ? '<span class="mec-required">*</span>' : ''); ?></label>
                    </div>
                    <div class="mec-form-row">
                        <div class="mec-col-4">
                            <input type="text" name="mec[date][start][date]" id="mec_start_date" value="<?php echo esc_attr(\MEC\Base::get_main()->standardize_format($start_date, $datepicker_format)); ?>" placeholder="<?php esc_html_e('Start Date', 'mec'); ?>" autocomplete="off" />
                        </div>
                        <div class="mec-col-6 mec-time-picker <?php echo ($allday == 1) ? 'mec-util-hidden' : ''; ?>">
                            <?php \MEC\Base::get_main()->timepicker(array(
                                'method' => $time_format,
                                'time_hour' => $start_time_hour,
                                'time_minutes' => $start_time_minutes,
                                'time_ampm' => $start_time_ampm,
                                'name' => 'mec[date][start]',
                                'id_key' => 'start_',
                                'include_h0' => true,
                            )); ?>
                        </div>
                    </div>
                    <div class="mec-title">
                        <span class="mec-dashicons dashicons dashicons-calendar-alt"></span>
                        <label for="mec_end_date"><?php esc_html_e('End Date', 'mec'); ?> <?php echo ($required ? '<span class="mec-required">*</span>' : ''); ?></label>
                    </div>
                    <div class="mec-form-row">
                        <div class="mec-col-4">
                            <input type="text" name="mec[date][end][date]" id="mec_end_date" value="<?php echo esc_attr(\MEC\Base::get_main()->standardize_format($end_date, $datepicker_format)); ?>" placeholder="<?php esc_html_e('End Date', 'mec'); ?>" autocomplete="off" />
                        </div>
                        <div class="mec-col-6 mec-time-picker <?php echo ($allday == 1) ? 'mec-util-hidden' : ''; ?>">
                            <?php \MEC\Base::get_main()->timepicker(array(
                                'method' => $time_format,
                                'time_hour' => $end_time_hour,
                                'time_minutes' => $end_time_minutes,
                                'time_ampm' => $end_time_ampm,
                                'name' => 'mec[date][end]',
                                'id_key' => 'end_',
                            )); ?>
                        </div>
                    </div>
                    <div class="mec-form-row">
                        <input <?php if($allday == '1') echo 'checked="checked"'; ?> type="checkbox" name="mec[date][allday]" id="mec_allday" value="1" onchange="jQuery('.mec-time-picker').toggle();" /><label for="mec_allday"><?php esc_html_e('All-day Event', 'mec'); ?></label>
                    </div>
                    <div class="mec-form-row">
                        <input <?php if($hide_time == '1') echo 'checked="checked"'; ?> type="checkbox" name="mec[date][hide_time]" id="mec_hide_time" value="1" /><label for="mec_hide_time"><?php esc_html_e('Hide Event Time', 'mec'); ?></label>
                    </div>
                    <div class="mec-form-row <?php echo $hide_end_time_global ? 'mec-util-hidden' : ''; ?>">
                        <input <?php if($hide_end_time == '1') echo 'checked="checked"'; ?> type="checkbox" name="mec[date][hide_end_time]" id="mec_hide_end_time" value="1" /><label for="mec_hide_end_time"><?php esc_html_e('Hide Event End Time', 'mec'); ?></label>
                    </div>
                    <div class="mec-form-row">
                        <div class="mec-col-4">
                            <input type="text" class="" name="mec[date][comment]" id="mec_comment" placeholder="<?php esc_html_e('Notes on the time', 'mec'); ?>" value="<?php echo esc_attr($comment); ?>" />
                            <p class="description"><?php esc_html_e('It appears next to the event time on the Single Event Page. You can enter notes such as the timezone name in this field.', 'mec'); ?></p>
                        </div>
                    </div>
                </div>
                <div id="mec_meta_box_repeat_form">
                    <h4><?php esc_html_e('Repeating', 'mec'); ?></h4>
                    <div class="mec-form-row">
                        <input <?php if($repeat_status == '1') echo 'checked="checked"'; ?> type="checkbox" name="mec[date][repeat][status]" id="mec_repeat" value="1" /><label for="mec_repeat"><?php esc_html_e('Event Repeating', 'mec'); ?></label>
                    </div>
                    <div class="mec-form-repeating-event-row">
                        <div class="mec-form-row">
                            <label class="mec-col-3" for="mec_repeat_type"><?php esc_html_e('Repeats', 'mec'); ?></label>
                            <select class="mec-col-2" name="mec[date][repeat][type]" id="mec_repeat_type">
                                <option <?php if($repeat_type == 'daily') echo 'selected="selected"'; ?> value="daily"><?php esc_html_e('Daily', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'weekday') echo 'selected="selected"'; ?> value="weekday"><?php esc_html_e('Every Weekday', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'weekend') echo 'selected="selected"'; ?> value="weekend"><?php esc_html_e('Every Weekend', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'certain_weekdays') echo 'selected="selected"'; ?> value="certain_weekdays"><?php esc_html_e('Certain Weekdays', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'weekly') echo 'selected="selected"'; ?> value="weekly"><?php esc_html_e('Weekly', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'monthly') echo 'selected="selected"'; ?> value="monthly"><?php esc_html_e('Monthly', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'yearly') echo 'selected="selected"'; ?> value="yearly"><?php esc_html_e('Yearly', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'custom_days') echo 'selected="selected"'; ?> value="custom_days"><?php esc_html_e('Custom Days', 'mec'); ?></option>
                                <option <?php if($repeat_type == 'advanced') echo 'selected="selected"'; ?> value="advanced"><?php esc_html_e('Advanced', 'mec'); ?></option>
                            </select>
                        </div>
                        <div class="mec-form-row" id="mec_repeat_interval_container">
                            <label class="mec-col-3" for="mec_repeat_interval"><?php esc_html_e('Repeat Interval', 'mec'); ?></label>
                            <input class="mec-col-2" type="text" name="mec[date][repeat][interval]" id="mec_repeat_interval" placeholder="<?php esc_html_e('Repeat interval', 'mec'); ?>" value="<?php echo ($repeat_type == 'weekly' ? ($repeat_interval/7) : $repeat_interval); ?>" />
                        </div>
                        <div class="mec-form-row" id="mec_repeat_certain_weekdays_container">
                            <label class="mec-col-3"><?php esc_html_e('Week Days', 'mec'); ?></label>
                            <label class="label-checkbox"><input type="checkbox" name="mec[date][repeat][certain_weekdays][]" value="1" <?php echo (in_array(1, $certain_weekdays) ? 'checked="checked"' : ''); ?> /><?php esc_html_e('Monday', 'mec'); ?></label>
                            <label class="label-checkbox">&nbsp;<input type="checkbox" name="mec[date][repeat][certain_weekdays][]" value="2" <?php echo (in_array(2, $certain_weekdays) ? 'checked="checked"' : ''); ?> /><?php esc_html_e('Tuesday', 'mec'); ?></label>
                            <label class="label-checkbox">&nbsp;<input type="checkbox" name="mec[date][repeat][certain_weekdays][]" value="3" <?php echo (in_array(3, $certain_weekdays) ? 'checked="checked"' : ''); ?> /><?php esc_html_e('Wednesday', 'mec'); ?></label>
                            <label class="label-checkbox">&nbsp;<input type="checkbox" name="mec[date][repeat][certain_weekdays][]" value="4" <?php echo (in_array(4, $certain_weekdays) ? 'checked="checked"' : ''); ?> /><?php esc_html_e('Thursday', 'mec'); ?></label>
                            <label class="label-checkbox">&nbsp;<input type="checkbox" name="mec[date][repeat][certain_weekdays][]" value="5" <?php echo (in_array(5, $certain_weekdays) ? 'checked="checked"' : ''); ?> /><?php esc_html_e('Friday', 'mec'); ?></label>
                            <label class="label-checkbox">&nbsp;<input type="checkbox" name="mec[date][repeat][certain_weekdays][]" value="6" <?php echo (in_array(6, $certain_weekdays) ? 'checked="checked"' : ''); ?> /><?php esc_html_e('Saturday', 'mec'); ?></label>
                            <label class="label-checkbox">&nbsp;<input type="checkbox" name="mec[date][repeat][certain_weekdays][]" value="7" <?php echo (in_array(7, $certain_weekdays) ? 'checked="checked"' : ''); ?> /><?php esc_html_e('Sunday', 'mec'); ?></label>
                        </div>
                        <div class="mec-form-row" id="mec_exceptions_in_days_container">
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <div class="mec-form-row">
                                        <div class="mec-col-4">
                                            <input type="text" id="mec_exceptions_in_days_start_date" value="" placeholder="<?php esc_html_e('Start', 'mec'); ?>" title="<?php esc_html_e('Start', 'mec'); ?>" class="mec_date_picker_dynamic_format widefat" autocomplete="off"/>
                                        </div>
                                        <div class="mec-col-8">
                                            <?php \MEC\Base::get_main()->timepicker(array(
                                                'method' => $time_format,
                                                'time_hour' => $start_time_hour,
                                                'time_minutes' => $start_time_minutes,
                                                'time_ampm' => $start_time_ampm,
                                                'name' => 'mec[exceptionsdays][start]',
                                                'id_key' => 'exceptions_in_days_start_',
                                                'include_h0' => true,
                                            )); ?>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-4">
                                            <input type="text" id="mec_exceptions_in_days_end_date" value="" placeholder="<?php esc_html_e('End', 'mec'); ?>" title="<?php esc_html_e('End', 'mec'); ?>" class="mec_date_picker_dynamic_format" autocomplete="off"/>
                                        </div>
                                        <div class="mec-col-8">
                                            <?php \MEC\Base::get_main()->timepicker(array(
                                                'method' => $time_format,
                                                'time_hour' => $end_time_hour,
                                                'time_minutes' => $end_time_minutes,
                                                'time_ampm' => $end_time_ampm,
                                                'name' => 'mec[exceptionsdays][end]',
                                                'id_key' => 'exceptions_in_days_end_',
                                            )); ?>
                                        </div>
                                    </div>
                                    <div class="mec-form-row">
                                        <div class="mec-col-12">
                                            <button class="button" type="button" id="mec_add_in_days"><?php esc_html_e('Add', 'mec'); ?></button>
                                            <span class="mec-tooltip">
                                                <div class="box top">
                                                    <h5 class="title"><?php esc_html_e('Custom Days Repeating', 'mec'); ?></h5>
                                                    <div class="content">
                                                        <p>
                                                            <?php esc_attr_e('Add certain days to event occurrences. If you have a single day event, start and end dates should be the same, If you have a multiple day event, the start and end dates must match the initial date.', 'mec'); ?>
                                                            <a href="https://webnus.net/dox/modern-events-calendar/date-and-time/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a>
                                                        </p>
                                                    </div>
                                                </div>
                                                <i title="" class="dashicons-before dashicons-editor-help"></i>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-form-row" id="mec_in_days">
                                <?php $i = 1; foreach($in_days as $in_day): ?>
                                    <?php
                                    $in_day = explode(':', $in_day);
                                    $first_date = \MEC\Base::get_main()->standardize_format($in_day[0], $datepicker_format);
                                    $second_date = \MEC\Base::get_main()->standardize_format($in_day[1], $datepicker_format);

                                    $in_day_start_time = '';
                                    $in_day_start_time_label = '';
                                    $in_day_end_time = '';
                                    $in_day_end_time_label = '';

                                    if(isset($in_day[2]) and isset($in_day[3]))
                                    {
                                        $in_day_start_time = $in_day[2];
                                        $in_day_end_time = $in_day[3];

                                        // If 24 hours format is enabled then convert it back to 12 hours
                                        if( $time_format == 24 )
                                        {
                                            $in_day_ex_start = explode('-', $in_day_start_time);
                                            $in_day_ex_end = explode('-', $in_day_end_time);

                                            $in_day_start_time_label = \MEC\Base::get_main()->to_24hours($in_day_ex_start[0], $in_day_ex_start[2]).':'.$in_day_ex_start[1];
                                            $in_day_end_time_label = \MEC\Base::get_main()->to_24hours($in_day_ex_end[0], $in_day_ex_end[2]).':'.$in_day_ex_end[1];
                                        }
                                        else
                                        {
                                            $pos = strpos($in_day_start_time, '-');
                                            if($pos !== false) $in_day_start_time_label = substr_replace($in_day_start_time, ':', $pos, 1);

                                            $pos = strpos($in_day_end_time, '-');
                                            if($pos !== false) $in_day_end_time_label = substr_replace($in_day_end_time, ':', $pos, 1);

                                            $in_day_start_time_label = str_replace('-', ' ', $in_day_start_time_label);
                                            $in_day_end_time_label = str_replace('-', ' ', $in_day_end_time_label);
                                        }
                                    }

                                    $in_day = $first_date . ':' . $second_date.(trim($in_day_start_time) ? ':'.$in_day_start_time : '').(trim($in_day_end_time) ? ':'.$in_day_end_time : '');
                                    $in_day_label = $first_date. (trim($in_day_start_time_label) ? ' '.$in_day_start_time_label : '') . ' - ' . $second_date. (trim($in_day_end_time_label) ? ' '.$in_day_end_time_label : '');
                                    ?>
                                    <div class="mec-form-row" id="mec_in_days_row<?php echo esc_attr($i); ?>">
                                        <input type="hidden" name="mec[in_days][<?php echo esc_attr($i); ?>]" value="<?php echo esc_attr($in_day); ?>"/>
                                        <span class="mec-not-in-days-day"><?php echo \MEC_kses::element($in_day_label); ?></span>
                                        <span class="mec-not-in-days-remove" onclick="mec_in_days_remove(<?php echo esc_attr($i); ?>);">x</span>
                                    </div>
                                <?php $i++; endforeach; ?>
                            </div>
                            <input type="hidden" id="mec_new_in_days_key" value="<?php echo ($i+1); ?>" />
                            <div class="mec-util-hidden" id="mec_new_in_days_raw">
                                <div class="mec-form-row" id="mec_in_days_row:i:">
                                    <input type="hidden" name="mec[in_days][:i:]" value=":val:" />
                                    <span class="mec-not-in-days-day">:label:</span>
                                    <span class="mec-not-in-days-remove" onclick="mec_in_days_remove(:i:);">x</span>
                                </div>
                            </div>
                        </div>
                        <div id="mec-advanced-wraper">
                            <div class="mec-form-row">
                                <ul>
                                    <li>
                                        <?php esc_html_e('First', 'mec'); ?>
                                    </li>
                                    <ul>
                                        <?php $day_1th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 1); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_1th}.1"); ?>">
                                            <?php esc_html_e($day_1th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_1th); ?>.1-</span>
                                        </li>
                                        <?php $day_2th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 2); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_2th}.1"); ?>">
                                            <?php esc_html_e($day_2th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_2th); ?>.1-</span>
                                        </li>
                                        <?php $day_3th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 3); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_3th}.1"); ?>">
                                            <?php esc_html_e($day_3th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_3th); ?>.1-</span>
                                        </li>
                                        <?php $day_4th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 4); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_4th}.1"); ?>">
                                            <?php esc_html_e($day_4th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_4th); ?>.1-</span>
                                        </li>
                                        <?php $day_5th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 5); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_5th}.1"); ?>">
                                            <?php esc_html_e($day_5th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_5th); ?>.1-</span>
                                        </li>
                                        <?php $day_6th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 6); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_6th}.1"); ?>">
                                            <?php esc_html_e($day_6th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_6th); ?>.1-</span>
                                        </li>
                                        <?php $day_7th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 7); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_7th}.1"); ?>">
                                            <?php esc_html_e($day_7th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_7th); ?>.1-</span>
                                        </li>
                                    </ul>
                                </ul>
                                <ul>
                                    <li>
                                        <?php esc_html_e('Second', 'mec'); ?>
                                    </li>
                                    <ul>
                                        <?php $day_1th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 1); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_1th}.2"); ?>">
                                            <?php esc_html_e($day_1th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_1th); ?>.2-</span>
                                        </li>
                                        <?php $day_2th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 2); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_2th}.2"); ?>">
                                            <?php esc_html_e($day_2th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_2th); ?>.2-</span>
                                        </li>
                                        <?php $day_3th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 3); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_3th}.2"); ?>">
                                            <?php esc_html_e($day_3th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_3th); ?>.2-</span>
                                        </li>
                                        <?php $day_4th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 4); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_4th}.2"); ?>">
                                            <?php esc_html_e($day_4th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_4th); ?>.2-</span>
                                        </li>
                                        <?php $day_5th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 5); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_5th}.2"); ?>">
                                            <?php esc_html_e($day_5th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_5th); ?>.2-</span>
                                        </li>
                                        <?php $day_6th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 6); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_6th}.2"); ?>">
                                            <?php esc_html_e($day_6th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_6th); ?>.2-</span>
                                        </li>
                                        <?php $day_7th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 7); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_7th}.2"); ?>">
                                            <?php esc_html_e($day_7th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_7th); ?>.2-</span>
                                        </li>
                                    </ul>
                                </ul>
                                <ul>
                                    <li>
                                        <?php esc_html_e('Third', 'mec'); ?>
                                    </li>
                                    <ul>
                                        <?php $day_1th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 1); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_1th}.3"); ?>">
                                            <?php esc_html_e($day_1th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_1th); ?>.3-</span>
                                        </li>
                                        <?php $day_2th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 2); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_2th}.3"); ?>">
                                            <?php esc_html_e($day_2th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_2th); ?>.3-</span>
                                        </li>
                                        <?php $day_3th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 3); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_3th}.3"); ?>">
                                            <?php esc_html_e($day_3th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_3th); ?>.3-</span>
                                        </li>
                                        <?php $day_4th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 4); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_4th}.3"); ?>">
                                            <?php esc_html_e($day_4th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_4th); ?>.3-</span>
                                        </li>
                                        <?php $day_5th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 5); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_5th}.3"); ?>">
                                            <?php esc_html_e($day_5th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_5th); ?>.3-</span>
                                        </li>
                                        <?php $day_6th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 6); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_6th}.3"); ?>">
                                            <?php esc_html_e($day_6th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_6th); ?>.3-</span>
                                        </li>
                                        <?php $day_7th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 7); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_7th}.3"); ?>">
                                            <?php esc_html_e($day_7th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_7th); ?>.3-</span>
                                        </li>
                                    </ul>
                                </ul>
                                <ul>
                                    <li>
                                        <?php esc_html_e('Fourth', 'mec'); ?>
                                    </li>
                                    <ul>
                                        <?php $day_1th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 1); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_1th}.4"); ?>">
                                            <?php esc_html_e($day_1th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_1th); ?>.4-</span>
                                        </li>
                                        <?php $day_2th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 2); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_2th}.4"); ?>">
                                            <?php esc_html_e($day_2th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_2th); ?>.4-</span>
                                        </li>
                                        <?php $day_3th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 3); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_3th}.4"); ?>">
                                            <?php esc_html_e($day_3th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_3th); ?>.4-</span>
                                        </li>
                                        <?php $day_4th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 4); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_4th}.4"); ?>">
                                            <?php esc_html_e($day_4th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_4th); ?>.4-</span>
                                        </li>
                                        <?php $day_5th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 5); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_5th}.4"); ?>">
                                            <?php esc_html_e($day_5th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_5th); ?>.4-</span>
                                        </li>
                                        <?php $day_6th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 6); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_6th}.4"); ?>">
                                            <?php esc_html_e($day_6th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_6th); ?>.4-</span>
                                        </li>
                                        <?php $day_7th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 7); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_7th}.4"); ?>">
                                            <?php esc_html_e($day_7th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_7th); ?>.4-</span>
                                        </li>
                                    </ul>
                                </ul>
                                <ul>
                                    <li>
                                        <?php esc_html_e('Last', 'mec'); ?>
                                    </li>
                                    <ul>
                                        <?php $day_1th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 1); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_1th}.l"); ?>">
                                            <?php esc_html_e($day_1th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_1th); ?>.l-</span>
                                        </li>
                                        <?php $day_2th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 2); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_2th}.l"); ?>">
                                            <?php esc_html_e($day_2th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_2th); ?>.l-</span>
                                        </li>
                                        <?php $day_3th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 3); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_3th}.l"); ?>">
                                            <?php esc_html_e($day_3th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_3th); ?>.l-</span>
                                        </li>
                                        <?php $day_4th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 4); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_4th}.l"); ?>">
                                            <?php esc_html_e($day_4th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_4th); ?>.l-</span>
                                        </li>
                                        <?php $day_5th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 5); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_5th}.l"); ?>">
                                            <?php esc_html_e($day_5th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_5th); ?>.l-</span>
                                        </li>
                                        <?php $day_6th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 6); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_6th}.l"); ?>">
                                            <?php esc_html_e($day_6th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_6th); ?>.l-</span>
                                        </li>
                                        <?php $day_7th = \MEC\Base::get_main()->advanced_repeating_sort_day(\MEC\Base::get_main()->get_first_day_of_week(), 7); ?>
                                        <li class="<?php \MEC\Base::get_main()->mec_active($advanced_days, "{$day_7th}.l"); ?>">
                                            <?php esc_html_e($day_7th, 'mec'); ?>
                                            <span class="key"><?php echo esc_attr($day_7th); ?>.l-</span>
                                        </li>
                                    </ul>
                                </ul>
                                <input class="mec-col-2" type="hidden" name="mec[date][repeat][advanced]"
                                 id="mec_date_repeat_advanced"  value="<?php echo esc_attr($advanced_str); ?>" />
                            </div>
                        </div>
                        <div id="mec_end_wrapper">
                            <div class="mec-form-row">
                                <label for="mec_repeat_ends_never"><h5 class="mec-title"><?php esc_html_e('End Repeat', 'mec'); ?></h5></label>
                            </div>
                            <div class="mec-form-row">
                                <input <?php if($mec_repeat_end == 'never') echo 'checked="checked"'; ?> type="radio" value="never" name="mec[date][repeat][end]" id="mec_repeat_ends_never" />
                                <label for="mec_repeat_ends_never"><?php esc_html_e('Never', 'mec'); ?></label>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-3">
                                    <input <?php if($mec_repeat_end == 'date') echo 'checked="checked"'; ?> type="radio" value="date" name="mec[date][repeat][end]" id="mec_repeat_ends_date" />
                                    <label for="mec_repeat_ends_date"><?php esc_html_e('On', 'mec'); ?></label>
                                </div>
                                <input class="mec-col-2" type="text" name="mec[date][repeat][end_at_date]" id="mec_date_repeat_end_at_date" autocomplete="off" value="<?php echo esc_attr( \MEC\Base::get_main()->standardize_format( $repeat_end_at_date, $datepicker_format ) ); ?>" />
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-3">
                                    <input <?php if($mec_repeat_end == 'occurrences') echo 'checked="checked"'; ?> type="radio" value="occurrences" name="mec[date][repeat][end]" id="mec_repeat_ends_occurrences" />
                                    <label for="mec_repeat_ends_occurrences"><?php esc_html_e('After', 'mec'); ?></label>
                                </div>
                                <input class="mec-col-2" type="text" name="mec[date][repeat][end_at_occurrences]" id="mec_date_repeat_end_at_occurrences" autocomplete="off" placeholder="<?php esc_html_e('Occurrences times', 'mec'); ?>"  value="<?php echo esc_attr(($repeat_end_at_occurrences+1)); ?>" />
                                <span class="mec-tooltip">
                                    <div class="box">
                                        <h5 class="title"><?php esc_html_e('Occurrences times', 'mec'); ?></h5>
                                        <div class="content"><p><?php esc_attr_e('The event will finish after certain repeats. For example if you set it to 10, the event will finish after 10 repeats.', 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/event-detailssingle-event-page/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                                    </div>
                                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                                </span>
                            </div>
                            <div class="mec-form-row">
                                <input
                                    <?php
                                    if ($one_occurrence == '1') {
                                        echo 'checked="checked"';
                                    }
                                    ?>
                                        type="checkbox" name="mec[date][one_occurrence]" id="mec-one-occurrence" value="1"/><label
                                        for="mec-one-occurrence"><?php esc_html_e('Show only one occurrence of this event', 'mec'); ?></label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        <?php
    }

    /**
     * Return countdown status html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function countdown_status( $post, $atts = array() ){

        $countdown_method = get_post_meta($post->ID, 'mec_countdown_method', true);
        if(trim($countdown_method) == '') {

            $countdown_method = 'global';
        }

        ?>
            <div id="mec-fes-countdown-status" class="mec-meta-box-fields">
                <h4><?php esc_html_e('Countdown Method', 'mec'); ?></h4>
                <div class="mec-form-row">
                    <div class="mec-col-4">
                        <select name="mec[countdown_method]" id="mec_countdown_method" title="<?php esc_attr_e('Countdown Method', 'mec'); ?>">
                            <option value="global" <?php if('global' == $countdown_method) echo 'selected="selected"'; ?>><?php esc_html_e('Inherit from global options', 'mec'); ?></option>
                            <option value="start" <?php if('start' == $countdown_method) echo 'selected="selected"'; ?>><?php esc_html_e('Count to Event Start', 'mec'); ?></option>
                            <option value="end" <?php if('end' == $countdown_method) echo 'selected="selected"'; ?>><?php esc_html_e('Count to Event End', 'mec'); ?></option>
                        </select>
                    </div>
                </div>
            </div>
        <?php
    }

    /**
     * Return style per event html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function style_per_event( $post, $atts = array() ){

        $style_per_event = get_post_meta($post->ID, 'mec_style_per_event', true);
        if(trim($style_per_event) == '') {

            $style_per_event = 'global';
        }

        ?>
        <div id="mec-fes-style-per-event" class="mec-meta-box-fields">
            <h4><?php esc_html_e('Details Page Style', 'mec'); ?></h4>
            <div class="mec-form-row">
                <div class="mec-col-4">
                    <select name="mec[style_per_event]" id="mec_style_per_event" title="<?php esc_attr_e('Event Style', 'mec'); ?>">
                        <option value="global"><?php esc_html_e('Inherit from global options', 'mec'); ?></option>
                        <option value="default" <?php echo $style_per_event === 'default' ? 'selected="selected"' : ''; ?>><?php esc_html_e('Default Style', 'mec'); ?></option>
                        <option value="modern" <?php echo $style_per_event === 'modern' ? 'selected="selected"' : ''; ?>><?php esc_html_e('Modern Style', 'mec'); ?></option>
                        <?php do_action('mec_single_style', array('style_per_event' => $style_per_event), 'style_per_event'); ?>
                        <?php if(is_plugin_active( 'mec-single-builder/mec-single-builder.php')): ?>
                            <option value="builder" <?php echo $style_per_event === 'builder' ? 'selected="selected"' : ''; ?>><?php esc_html_e('Elementor Single Builder', 'mec'); ?></option>
                        <?php endif; ?>
                    </select>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Return trailer URL html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function trailer_url($post, $atts = array()){
        $trailer_url = get_post_meta($post->ID, 'mec_trailer_url', true);
        $trailer_title = get_post_meta($post->ID, 'mec_trailer_title', true);
        ?>
        <div id="mec-fes-trailer-url" class="mec-meta-box-fields">
            <h4><?php esc_html_e('Trailer URL', 'mec'); ?></h4>
            <div class="mec-form-row">
                <div class="mec-col-6">
                    <input name="mec[trailer_url]" id="mec_trailer_url" title="<?php esc_attr_e('Trailer URL', 'mec'); ?>" type="url" value="<?php echo trim($trailer_url) ? esc_url($trailer_url) : ''; ?>" class="widefat" placeholder="http://">
                </div>
                <div class="mec-col-6">
                    <input name="mec[trailer_title]" id="mec_trailer_title" title="<?php esc_attr_e('Trailer Title', 'mec'); ?>" type="text" value="<?php echo esc_attr($trailer_title); ?>" class="widefat" placeholder="<?php esc_attr_e('Trailer Title', 'mec'); ?>">
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Return visibility html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function visibility( $post, $atts = array() ){

        // Public Event
        $public = get_post_meta($post->ID, 'mec_public', true);
        if(trim($public) === '') {

            $public = 1;
        }
        ?>
            <div id="mec-fes-visibility" class="mec-meta-box-fields">
                <h4><?php esc_html_e('Visibility', 'mec'); ?></h4>
                <div class="mec-form-row">
                    <div class="mec-col-4">
                        <select name="mec[public]" id="mec_public" title="<?php esc_attr_e('Event Visibility', 'mec'); ?>">
                            <option value="1" <?php if('1' == $public) echo 'selected="selected"'; ?>><?php esc_html_e('Show on Shortcodes', 'mec'); ?></option>
                            <option value="0" <?php if('0' == $public) echo 'selected="selected"'; ?>><?php esc_html_e('Hide on Shortcodes', 'mec'); ?></option>
                        </select>
                    </div>
                </div>
            </div>
        <?php
    }

    /**
     * Return timezone html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function timezone( $post, $atts = array() ){

        $event_timezone = get_post_meta($post->ID, 'mec_timezone', true);
        if(trim($event_timezone) == '') {

            $event_timezone = 'global';
        }
        ?>
        <div id="mec-fes-timezone" class="mec-meta-box-fields">
            <h4><?php esc_html_e('Timezone', 'mec'); ?></h4>
            <div class="mec-form-row mec-timezone-event">
                <div class="mec-col-4">
                    <select name="mec[timezone]" id="mec_event_timezone">
                        <option value="global"><?php esc_html_e('Inherit from global options'); ?></option>
                        <?php echo \MEC_kses::form(\MEC\Base::get_main()->timezones($event_timezone)); ?>
                    </select>
                </div>

            </div>
        </div>
        <?php
    }

    /**
     * Return note html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function note( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        if( !\MEC\Base::get_main()->is_note_visible(get_post_status($post->ID)) ){

            if( $is_edit_mode ){

                echo '<div class="mec-content-notification">
					<p>'
						.'<span>'
							. esc_html__('The output cannot be displayed.', 'mec')
						.'</span>'
						.'<a href="#" target="_blank">' . esc_html__('How to set', 'mec') . ' </a>'
					.'</p>'
				.'</div>';
            }

            return;
        }

        $note = get_post_meta($post->ID, 'mec_note', true);
        ?>
            <div class="mec-meta-box-fields mec-fes-note" id="mec-event-note">
                <h4><?php esc_html_e('Note to reviewer', 'mec'); ?></h4>
                <div class="mec-form-row" id="mec_meta_box_event_note">
                    <textarea name="mec[note]"><?php echo esc_textarea($note); ?></textarea>
                </div>
            </div>

        <?php
    }

    /**
     * Return guest html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function guest( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        if( is_user_logged_in() && !$is_edit_mode ){

            return;
        }

        $required = isset( $atts['required'] ) && $atts['required'] ? true : false;

        $guest_email = get_post_meta($post->ID, 'fes_guest_email', true);
        $guest_name = get_post_meta($post->ID, 'fes_guest_name', true);
        ?>
            <!-- Guest Email and Name -->
            <div class="mec-meta-box-fields mec-fes-user-data" id="mec-guest-email-link">
                <h4><?php esc_html_e('User Data', 'mec'); ?></h4>
                <div class="mec-form-row">
                    <label class="mec-col-2" for="mec_guest_email"><?php esc_html_e('Email', 'mec'); ?><span>*</span></label>
                    <input class="mec-col-7" type="email" required="required" name="mec[fes_guest_email]" id="mec_guest_email" value="<?php echo esc_attr($guest_email); ?>" placeholder="<?php esc_html_e('eg. yourname@gmail.com', 'mec'); ?>" />
                </div>
                <div class="mec-form-row">
                    <label class="mec-col-2" for="mec_guest_name"><?php esc_html_e('Name', 'mec'); ?><span>*</span></label>
                    <input class="mec-col-7" type="text" required="required" name="mec[fes_guest_name]" id="mec_guest_name" value="<?php echo esc_attr($guest_name); ?>" placeholder="<?php esc_html_e('eg. John Smith', 'mec'); ?>" />
                </div>
            </div>
        <?php
    }

    /**
     * Return event links html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function event_links( $post, $atts = array() ){

        $event_link_required = isset( $atts['event_link_required'] ) && $atts['event_link_required'];
        $more_info_required = isset( $atts['more_info_required'] ) && $atts['more_info_required'];

        $read_more = get_post_meta($post->ID, 'mec_read_more', true);
        $more_info = get_post_meta($post->ID, 'mec_more_info', true);
        $more_info_title = get_post_meta($post->ID, 'mec_more_info_title', true);
        ?>
        <!-- Event Links Section -->
        <div class="mec-meta-box-fields mec-fes-event-links" id="mec-event-links">
            <h4><?php esc_html_e('Event Links', 'mec'); ?></h4>
            <div class="mec-form-row">
                <label class="mec-col-2" for="mec_read_more_link"><?php echo esc_html(\MEC\Base::get_main()->m('read_more_link', esc_html__('Event Link', 'mec'))); ?> <?php echo ($event_link_required ? '<span class="mec-required">*</span>' : ''); ?></label>
                <input class="mec-col-9" type="text" name="mec[read_more]" id="mec_read_more_link" value="<?php echo esc_attr($read_more); ?>" placeholder="<?php esc_html_e('eg. http://yoursite.com/your-event', 'mec'); ?>" <?php echo ($event_link_required ? 'required' : ''); ?> />
                <p class="description"><?php esc_html_e('If you fill it, it will replace the default event page link. Insert full link including http(s)://', 'mec'); ?></p>
            </div>
            <div class="mec-form-row">
                <label class="mec-col-2" for="mec_more_info_link"><?php echo esc_html(\MEC\Base::get_main()->m('more_info_link', esc_html__('More Info', 'mec'))); ?> <?php echo $more_info_required ? '<span class="mec-required">*</span>' : ''; ?></label>
                <input class="mec-col-5" type="text" name="mec[more_info]" id="mec_more_info_link" value="<?php echo esc_attr($more_info); ?>" placeholder="<?php esc_html_e('eg. http://yoursite.com/your-event', 'mec'); ?>" <?php echo ( $more_info_required ? 'required' : ''); ?> />
                <input class="mec-col-2" type="text" name="mec[more_info_title]" id="mec_more_info_title" value="<?php echo esc_attr($more_info_title); ?>" placeholder="<?php esc_html_e('More Information', 'mec'); ?>" />
                <p class="description"><?php esc_html_e('This link will appear on the single event page. Insert full link including http(s)://', 'mec'); ?></p>
            </div>
        </div>

        <?php
    }

    /**
     * Return cost html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function cost( $post, $atts = array() ){

        $required = isset( $atts['required'] ) && $atts['required'] ? true : false;

        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        $cost = get_post_meta($post->ID, 'mec_cost', true);
        $cost_type = ((isset($settings['single_cost_type']) and trim($settings['single_cost_type'])) ? $settings['single_cost_type'] : 'numeric');

        $cost_auto_calculate = get_post_meta($post->ID, 'mec_cost_auto_calculate', true);

        $currency = get_post_meta($post->ID, 'mec_currency', true);
        if(!is_array($currency)) $currency = [];

        $currency_per_event = ((isset($settings['currency_per_event']) and trim($settings['currency_per_event'])) ? $settings['currency_per_event'] : 0);

        $currencies = \MEC\Base::get_main()->get_currencies();
        $current_currency = (isset($currency['currency']) ? $currency['currency'] : (isset($settings['currency']) ? $settings['currency'] : NULL));
        ?>
            <!-- Event Cost Section -->
            <div class="mec-meta-box-fields mec-fes-cost" id="mec-event-cost">
                <h4><?php echo esc_html(\MEC\Base::get_main()->m('event_cost', esc_html__('Event Cost', 'mec'))); ?> <?php echo $required ? '<span class="mec-required">*</span>' : ''; ?></h4>
                <div id="mec_meta_box_cost_form" class="<?php echo ($cost_auto_calculate ? 'mec-util-hidden' : ''); ?>">
                    <div class="mec-form-row">
                        <input type="<?php echo ($cost_type === 'alphabetic' ? 'text' : 'number'); ?>" <?php echo ($cost_type === 'numeric' ? 'min="0" step="any"' : ''); ?> class="mec-col-3" name="mec[cost]" id="mec_cost" value="<?php echo esc_attr($cost); ?>" placeholder="<?php esc_html_e('Cost', 'mec'); ?>" <?php echo ($required ? 'required' : ''); ?> />
                    </div>
                </div>

                <div class="mec-form-row">
                    <div class="mec-col-12">
                        <label for="mec_cost_auto_calculate" class="label-checkbox">
                            <input type="hidden" name="mec[cost_auto_calculate]" value="0" />
                            <input type="checkbox" name="mec[cost_auto_calculate]" id="mec_cost_auto_calculate" <?php echo ($cost_auto_calculate == 1) ? 'checked="checked"' : ''; ?> value="1" onchange="jQuery('#mec_meta_box_cost_form').toggleClass('mec-util-hidden');">
                            <?php esc_html_e('Show the minimum price based on tickets', 'mec'); ?>
                        </label>
                    </div>
                </div>

                <?php if($currency_per_event): ?>
                <h4 class="mec-form-subtitle"><?php echo esc_html__('Currency Options', 'mec'); ?></h4>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_currency_currency"><?php esc_html_e('Currency', 'mec'); ?></label>
                    <div class="mec-col-4">
                        <select name="mec[currency][currency]" id="mec_currency_currency">
                            <?php foreach($currencies as $c=>$currency_name): ?>
                                <option value="<?php echo esc_attr($c); ?>" <?php echo (($current_currency == $c) ? 'selected="selected"' : ''); ?>><?php echo esc_html($currency_name); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_currency_currency_symptom"><?php esc_html_e('Currency Sign', 'mec'); ?></label>
                    <div class="mec-col-4">
                        <input type="text" name="mec[currency][currency_symptom]" id="mec_currency_currency_symptom" value="<?php echo (isset($currency['currency_symptom']) ? esc_attr($currency['currency_symptom']) : ''); ?>" />
                        <span class="mec-tooltip">
                            <div class="box left">
                                <h5 class="title"><?php esc_html_e('Currency Sign', 'mec'); ?></h5>
                                <div class="content"><p><?php esc_attr_e("Default value will be \"currency\" if you leave it empty.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/currency-options/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                            </div>
                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                        </span>
                    </div>
                </div>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_currency_currency_sign"><?php esc_html_e('Currency Position', 'mec'); ?></label>
                    <div class="mec-col-4">
                        <select name="mec[currency][currency_sign]" id="mec_currency_currency_sign">
                            <option value="before" <?php echo ((isset($currency['currency_sign']) and $currency['currency_sign'] == 'before') ? 'selected="selected"' : ''); ?>><?php esc_html_e('$10 (Before)', 'mec'); ?></option>
                            <option value="before_space" <?php echo ((isset($currency['currency_sign']) and $currency['currency_sign'] == 'before_space') ? 'selected="selected"' : ''); ?>><?php esc_html_e('$ 10 (Before with Space)', 'mec'); ?></option>
                            <option value="after" <?php echo ((isset($currency['currency_sign']) and $currency['currency_sign'] == 'after') ? 'selected="selected"' : ''); ?>><?php esc_html_e('10$ (After)', 'mec'); ?></option>
                            <option value="after_space" <?php echo ((isset($currency['currency_sign']) and $currency['currency_sign'] == 'after_space') ? 'selected="selected"' : ''); ?>><?php esc_html_e('10 $ (After with Space)', 'mec'); ?></option>
                        </select>
                    </div>
                </div>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_currency_thousand_separator"><?php esc_html_e('Thousand Separator', 'mec'); ?></label>
                    <div class="mec-col-4">
                        <input type="text" name="mec[currency][thousand_separator]" id="mec_currency_thousand_separator" value="<?php echo (isset($currency['thousand_separator']) ? esc_attr($currency['thousand_separator']) : ','); ?>" />
                    </div>
                </div>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_currency_decimal_separator"><?php esc_html_e('Decimal Separator', 'mec'); ?></label>
                    <div class="mec-col-4">
                        <input type="text" name="mec[currency][decimal_separator]" id="mec_currency_decimal_separator" value="<?php echo (isset($currency['decimal_separator']) ? esc_attr($currency['decimal_separator']) : '.'); ?>" />
                    </div>
                </div>
                <div class="mec-form-row">
                    <div class="mec-col-12">
                        <label for="mec_currency_decimal_separator_status" class="label-checkbox">
                            <input type="hidden" name="mec[currency][decimal_separator_status]" value="1" />
                            <input type="checkbox" name="mec[currency][decimal_separator_status]" id="mec_currency_decimal_separator_status" <?php echo ((isset($currency['decimal_separator_status']) and $currency['decimal_separator_status'] == '0') ? 'checked="checked"' : ''); ?> value="0" />
                            <?php esc_html_e('No decimal', 'mec'); ?>
                        </label>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        <?php
    }

    /**
     * Return thumbnail html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function thumbnail( $post, $atts = array() ){

        $required = isset( $atts['required'] ) && $atts['required'];

        $attachment_id = get_post_thumbnail_id($post->ID);
        $featured_image = wp_get_attachment_image_src($attachment_id, 'large');
        if(isset($featured_image[0])) {

            $featured_image = $featured_image[0];
        }

        $featured_image_caption = $atts['featured_image_caption'] ?? false;
        $media_access = current_user_can('upload_files');
        ?>
        <!-- Event Featured Image Section -->
        <div class="mec-meta-box-fields mec-fes-featured-image" id="mec-featured-image">
            <h4><?php esc_html_e('Featured Image', 'mec'); ?> <?php echo ( $required ? '<span class="mec-required">*</span>' : ''); ?></h4>

            <?php if($media_access): ?>
            <div class="mec-form-row">
                <div id="mec_thumbnail_img">
                    <?php echo (trim($featured_image) ? '<img src="'.esc_attr($featured_image).'" />' : ''); ?>
                </div>
                <input type="hidden" id="mec_thumbnail" name="mec[featured_image]" value="<?php if(isset($attachment_id) and intval($attachment_id)) the_guid($attachment_id); ?>" />
                <button type="button" class="mec_upload_image_button button" data-post-id="<?php echo esc_attr($post->ID); ?>" id="mec_thumbnail_button"><?php echo esc_html__('Choose image', 'mec'); ?></button>
                <button type="button" class="mec_remove_image_button button <?php echo (trim($featured_image) ? '' : 'mec-util-hidden'); ?>"><?php echo esc_html__('Remove image', 'mec'); ?></button>
            </div>
            <?php else: ?>
            <div class="mec-form-row">
                <span id="mec_fes_thumbnail_img"><?php echo (trim($featured_image) ? '<img src="'.esc_attr($featured_image).'" />' : ''); ?></span>
                <input type="hidden" id="mec_fes_thumbnail" name="mec[featured_image]" value="<?php if(isset($attachment_id) and intval($attachment_id)) the_guid($attachment_id); ?>" />
                <input type="file" id="mec_featured_image_file" onchange="mec_fes_upload_featured_image();" />
                <span id="mec_fes_remove_image_button" class="<?php echo (trim($featured_image) ? '' : 'mec-util-hidden'); ?>"><?php esc_html_e('Remove Image', 'mec'); ?></span>

                <div class="mec-error mec-util-hidden" id="mec_fes_thumbnail_error"></div>
            </div>
            <?php endif; ?>

            <?php if( $featured_image_caption ): ?>
            <div class="mec-form-row">
                <input type="text" id="mec_fes_thumbnail_caption" name="mec[featured_image_caption]" value="<?php if(isset($attachment_id) and intval($attachment_id)) echo wp_get_attachment_caption($attachment_id); ?>" placeholder="<?php esc_attr_e('Image Caption', 'mec'); ?>" />
            </div>
            <?php endif; ?>
        </div>

        <?php
    }

    /**
     * Return categories html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function categories( $post, $atts = array() ){

        $required = isset( $atts['required'] ) && $atts['required'] ? true : false;

        ?>
        <div class="mec-meta-box-fields mec-fes-category" id="mec-categories">
            <h4><?php echo esc_html(\MEC\Base::get_main()->m('taxonomy_categories', esc_html__('Categories', 'mec'))); ?> <?php echo ( $required ? '<span class="mec-required">*</span>' : ''); ?></h4>
            <div class="mec-form-row">
                <?php
                    wp_list_categories(array(
                        'taxonomy' => 'mec_category',
                        'hide_empty' => false,
                        'title_li' => '',
                        'walker' => new \FES_Custom_Walker($post->ID),
                    ));
                ?>
            </div>
        </div>

        <?php
    }

    /**
     * Return labels html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function labels( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;

        $required = isset( $atts['required'] ) && $atts['required'] ? true : false;

        $post_labels = get_the_terms($post->ID, 'mec_label');

        $labels = [];
        if($post_labels) {

            foreach($post_labels as $post_label){

                $labels[] = $post_label->term_id;
            }
        }

        $label_terms = get_terms(
            array(
                'taxonomy'=>'mec_label',
                'hide_empty'=>false,
            )
        );

        if( $is_edit_mode && empty( $label_terms ) ){

            echo '<div class="mec-content-notification"><p>'
					.'<span>'. esc_html__('This widget is displayed if label is set. In order for the widget in this page to be displayed correctly, please set label for your last event.', 'mec').'</span>'
					. '<a href="https://webnus.net/dox/modern-events-calendar/label/" target="_blank">' . esc_html__('How to set label', 'mec') . ' </a>'
				.'</p></div>';
        }

        ?>
            <!-- Event Label Section -->
            <?php if(count($label_terms)): ?>
                <div class="mec-meta-box-fields mec-fes-labels" id="mec-labels">
                    <h4><?php echo esc_html(\MEC\Base::get_main()->m('taxonomy_labels', esc_html__('Labels', 'mec'))); ?> <?php echo ($required ? '<span class="mec-required">*</span>' : ''); ?></h4>
                    <div class="mec-form-row">
                        <?php foreach($label_terms as $label_term): ?>
                        <label for="mec_fes_labels<?php echo esc_attr($label_term->term_id); ?>">
                            <input type="checkbox" name="mec[labels][<?php echo esc_attr($label_term->term_id); ?>]" id="mec_fes_labels<?php echo esc_attr($label_term->term_id); ?>" value="1" <?php echo (in_array($label_term->term_id, $labels) ? 'checked="checked"' : ''); ?> />
                            <?php do_action('mec_label_to_checkbox_frontend', $label_term, $labels) ?>
                            <?php echo esc_html($label_term->name); ?>
                        </label>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>

        <?php
    }

    /**
     * Return color html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function color( $post, $atts = array() ){

        $color = get_post_meta($post->ID, 'mec_color', true);
        $available_colors = \MEC\Base::get_main()->get_available_colors();

        if(!trim($color)) {

            $color = $available_colors[0];
        }
        ?>

        <!-- Event Color Section -->
        <?php if(count($available_colors)): ?>
            <div class="mec-meta-box-fields mec-fes-color" id="mec-event-color">
                <h4><?php esc_html_e('Event Color', 'mec'); ?></h4>
                <div class="mec-form-row">
                    <div class="mec-form-row mec-available-color-row">
                        <input type="hidden" id="mec_event_color" name="mec[color]" value="#<?php echo esc_attr($color); ?>" />
                        <?php foreach($available_colors as $available_color): ?>
                        <span class="mec-color <?php echo ($available_color == $color ? 'color-selected' : ''); ?>" onclick="mec_set_event_color('<?php echo esc_attr($available_color); ?>');" style="background-color: #<?php echo esc_attr($available_color); ?>"></span>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php
    }

    /**
     * Return tags html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function tags( $post, $atts = array() ){

        $post_tags = wp_get_post_terms($post->ID, apply_filters('mec_taxonomy_tag', ''));

        $tags = '';
        foreach($post_tags as $post_tag) {

            $tags .= $post_tag->name.',';
        }
        ?>
            <!-- Event Tags Section -->
            <div class="mec-meta-box-fields mec-fes-tags" id="mec-tags">
                <h4><?php esc_html_e('Tags', 'mec'); ?></h4>
                <div class="mec-form-row">
                    <textarea name="mec[tags]" id="mec_fes_tags" placeholder="<?php esc_attr_e('Insert your desired tags, comma separated.', 'mec'); ?>"><?php echo (trim($tags) ? trim($tags, ', ') : ''); ?></textarea>
                </div>
            </div>

        <?php
    }

    /**
     * Return speakers html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function speakers( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;

        $speaker_terms = get_terms(array(
            'taxonomy'=>'mec_speaker',
            'hide_empty'=>false
        ));

        if( is_wp_error( $speaker_terms ) ){

            if( $is_edit_mode ){

                echo '<div class="mec-content-notification"><p>'
					.'<span>'. esc_html__('This widget is displayed if speaker is set. In order for the widget in this page to be displayed correctly, please set speaker for your last event.', 'mec').'</span>'
					. '<a href="https://webnus.net/dox/modern-events-calendar/speaker/" target="_blank">' . esc_html__('How to set speaker', 'mec') . ' </a>'
				.'</p></div>';
            }

            error_log( print_r($speaker_terms, true) );
            return;
        }

        $post_speakers = get_the_terms($post->ID, 'mec_speaker');
        $speakers = [];
        if($post_speakers) {
            foreach($post_speakers as $post_speaker){

                if(!isset($post_speaker->term_id)) continue;
                $speakers[] = $post_speaker->term_id;
            }
        }

        ?>
        <!-- Event Speakers Section -->
        <div class="mec-meta-box-fields mec-fes-speakers" id="mec-speakers">
            <h4><?php echo esc_html(\MEC\Base::get_main()->m('taxonomy_speakers', esc_html__('Speakers', 'mec'))); ?></h4>
            <div class="mec-form-row">
                <input type="text" name="mec[speakers][datas][names]" id="mec_speaker_input_names" placeholder="<?php echo sprintf(esc_html__('%s Name', 'mec'), \MEC\Base::get_main()->m('taxonomy_speaker', esc_html__('Speaker', 'mec'))); ?>" class="" />
                <p><?php echo sprintf(esc_html__('Insert name of one %s: Chris Taylor', 'mec'), strtolower(\MEC\Base::get_main()->m('taxonomy_speaker', esc_html__('speaker', 'mec')))); ?></p>
                <button class="button" type="button" id="mec_add_speaker_button"><?php esc_html_e('Add', 'mec'); ?></button>
            </div>
            <div class="mec-form-row" id="mec-fes-speakers-list">
            <?php if(count($speaker_terms)): ?>
                <?php foreach($speaker_terms as $speaker_term): ?>
                    <label for="mec_fes_speakers<?php echo esc_attr($speaker_term->term_id); ?>">
                        <input type="checkbox" name="mec[speakers][<?php echo esc_attr($speaker_term->term_id); ?>]" id="mec_fes_speakers<?php echo esc_attr($speaker_term->term_id); ?>" value="1" <?php echo (in_array($speaker_term->term_id, $speakers) ? 'checked="checked"' : ''); ?> />
                        <?php echo esc_html($speaker_term->name); ?>
                    </label>
                <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <?php
    }

    /**
     * Return sponsors html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function sponsors( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        $post_sponsors = get_the_terms($post->ID, 'mec_sponsor');
        if( is_wp_error( $post_sponsors ) ){

            if( $is_edit_mode ){

                echo '<div class="mec-content-notification">
					<p>'
						.'<span>'
							. esc_html__('The output cannot be displayed.', 'mec')
						.'</span>'
						.'<a href="#" target="_blank">' . esc_html__('How to set', 'mec') . ' </a>'
					.'</p>'
				.'</div>';
            }

            error_log( print_r($post_sponsors, true) );
            return;
        }

        $sponsors = [];
        if( is_array( $post_sponsors ) ) {
            foreach($post_sponsors as $post_sponsor){

                if(!isset($post_sponsor->term_id)) continue;

                $sponsors[] = $post_sponsor->term_id;
            }
        }

        $sponsor_terms = get_terms(array(
            'taxonomy'=>'mec_sponsor',
            'hide_empty'=>false
        ));

        ?>
        <!-- Event Sponsors Section -->
        <div class="mec-meta-box-fields mec-fes-sponsors" id="mec-sponsors">
            <h4><?php echo esc_html(\MEC\Base::get_main()->m('taxonomy_sponsors', esc_html__('Sponsors', 'mec'))); ?></h4>
            <?php if(isset($atts['add_sponsors']) && $atts['add_sponsors']): ?>
            <div class="mec-form-row">
                <input type="text" name="mec[sponsors][datas][names]" id="mec_sponsor_input_names" placeholder="<?php echo sprintf(esc_html__('%s Name', 'mec'), \MEC\Base::get_main()->m('taxonomy_sponsor', esc_html__('Sponsor', 'mec'))); ?>" />
                <p><?php echo sprintf(esc_html__('Insert name of one %s: Company A', 'mec'), strtolower(\MEC\Base::get_main()->m('taxonomy_sponsor', esc_html__('sponsor', 'mec')))); ?></p>
                <button class="button" type="button" id="mec_add_sponsor_button"><?php esc_html_e('Add', 'mec'); ?></button>
            </div>
            <?php endif; ?>
            <div class="mec-form-row" id="mec-fes-sponsors-list">
                <?php if(count($sponsor_terms)): ?>
                    <?php foreach($sponsor_terms as $sponsor_term): ?>
                        <label for="mec_fes_sponsors<?php echo esc_attr($sponsor_term->term_id); ?>">
                            <input type="checkbox" name="mec[sponsors][<?php echo esc_attr($sponsor_term->term_id); ?>]" id="mec_fes_sponsors<?php echo esc_attr($sponsor_term->term_id); ?>" value="1" <?php echo (in_array($sponsor_term->term_id, $sponsors) ? 'checked="checked"' : ''); ?> />
                            <?php echo esc_html($sponsor_term->name); ?>
                        </label>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <?php
    }

    /**
     * Return agreement html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function agreement( $post, $atts = array() ){

        $agreement_page = $atts['agreement_page'] ?? 0;
        $checked = $atts['checked'] ?? false;

        ?>
        <div id="mec-fes-agreement">
            <div class="mec-form-row">
                <!-- Agreement Section -->
                <label>
                    <input type="hidden" name="mec[agreement]" value="0">
                    <input type="checkbox" name="mec[agreement]" required value="1" <?php echo $checked ? 'checked="checked"' : ''; ?>>

                    <?php if( $agreement_page ): ?>
                    <span><?php echo sprintf(esc_html__('I accept the %s in order to submit an event.', 'mec'), '<a href="'.get_permalink( $agreement_page ).'" target="_blank">'.esc_html__('Privacy Policy', 'mec').'</a>'); ?> <span class="mec-required">*</span></span>
                    <?php else: ?>
                    <span><?php esc_html_e('I accept the Privacy Policy in order to submit an event.', 'mec'); ?> <span class="mec-required">*</span></span>
                    <?php endif; ?>
                </label>
            </div>
        </div>
        <?php
    }

    /**
     * Return event data html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function event_data( $post, $atts = array() ){

        $fields = \MEC\Base::get_main()->getEventFields();
        $fields->form(array(
            'id' => 'mec-event-data',
            'class' => 'mec-meta-box-fields mec-event-tab-content mec-fes-event-fields',
            'post' => $post,
            'data' => get_post_meta($post->ID, 'mec_fields', true),
            'name_prefix' => 'mec',
            'id_prefix' => 'mec_event_fields_',
            'mandatory_status' => true,
        ));
    }

    /**
     * Return hourly schedules html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function hourly_schedule( $post, $atts = array() ){

        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        $meta_hourly_schedules = get_post_meta($post->ID, 'mec_hourly_schedules', true);
        if(is_array($meta_hourly_schedules) and count($meta_hourly_schedules))
        {
            $first_key = key($meta_hourly_schedules);

            $hourly_schedules = [];
            if(!isset($meta_hourly_schedules[$first_key]['schedules']))
            {
                $hourly_schedules[] = array(
                    'title' => esc_html__('Day 1', 'mec'),
                    'schedules' => $meta_hourly_schedules,
                );
            }
            else $hourly_schedules = $meta_hourly_schedules;
        }
        else $hourly_schedules = [];

        // Status of Speakers Feature
        $speakers_status = isset($settings['speakers_status']) && $settings['speakers_status'];
        $speakers = get_terms('mec_speaker', array(
            'orderby' => 'name',
            'order' => 'ASC',
            'hide_empty' => '0',
        ));

        $builder = \MEC\Base::get_main()->getFormBuilder();
        $builder->hourlySchedule([
            'hourly_schedules' => $hourly_schedules,
            'speakers_status' => $speakers_status,
            'speakers' => $speakers,
        ]);
    }

    /**
     * Return Event Gallery html form
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function event_gallery($post, $atts = array())
    {
        // Disable For Guest
        if(!get_current_user_id()) return;

        $required = isset($atts['required']) && $atts['required'];
        $gallery = get_post_meta($post->ID, 'mec_event_gallery', true);
        if(!is_array($gallery)) $gallery = [];
        ?>
        <script>
        jQuery(document).ready(function()
        {
            <?php if(current_user_can('upload_files')): ?>
            jQuery('#mec_event_gallery_image_uploader').on('click', function(event)
            {
                var real_ajax_url = wp.ajax.settings.url;
                wp.ajax.settings.url = real_ajax_url + '?mec_fes=1';

                var post_id = jQuery(this).data('post-id');
                if(post_id && post_id !== -1) wp.media.model.settings.post.id = post_id;
                if(post_id === -1) wp.media.model.settings.post.id = null;

                event.preventDefault();

                var frame;
                if(frame)
                {
                    frame.open();
                    return;
                }

                frame = wp.media({
                    multiple: true
                });

                frame.on('select', function()
                {
                    frame.state().get('selection').map(function(attachment)
                    {
                        var image = attachment.toJSON();
                        var image_id = image.id;

                        jQuery('#mec_meta_box_event_gallery').append(`<li class="mec-event-gallery-wrapper-${image_id}" data-id="${image_id}">
                            <input type="hidden" name="mec[event_gallery][]" value="${image_id}" />
                            <img style="width: 200px;" src="${image.url}" alt="${image.url}" />
                            <span class="mec-event-gallery-delete" data-id="${image_id}">x</span>
                        </li>`);
                    });

                    frame.close();
                    mec_event_gallery_delete_listeners();
                });

                frame.open();
            });
            <?php else: ?>
            jQuery("#mec_event_gallery_image_uploader").on('change', function()
            {
                var fd = new FormData();
                fd.append("action", "mec_event_gallery_image_upload");
                fd.append("_wpnonce", "<?php echo wp_create_nonce('mec_event_gallery_image_upload'); ?>");

                // Append Images
                jQuery.each(jQuery("#mec_event_gallery_image_uploader")[0].files, function(i, file)
                {
                    fd.append('images[]', file);
                });

                jQuery("#mec_event_gallery_error").html("").addClass("mec-util-hidden");
                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: fd,
                    dataType: "json",
                    processData: false,
                    contentType: false
                })
                .done(function(response)
                {
                    if(response.success)
                    {
                        var images = response.data;
                        for (var i = 0; i < response.data.length; i++)
                        {
                            var image = images[i];
                            var image_id = image.id;

                            jQuery('#mec_meta_box_event_gallery').append(`<li class="mec-event-gallery-wrapper-${image_id}" data-id="${image_id}">
                                <input type="hidden" name="mec[event_gallery][]" value="${image_id}" />
                                <img style="width: 200px;" src="${image.url}" alt="${image.url}" />
                                <span class="mec-event-gallery-delete" data-id="${image_id}">x</span>
                            </li>`);
                        }

                        mec_event_gallery_delete_listeners();
                    }
                    else
                    {
                        jQuery("#mec_event_gallery_error").html(response.message).removeClass("mec-util-hidden");
                    }

                    // Reset File Input
                    jQuery("#mec_event_gallery_image_uploader").val('');
                });

                return false;
            });
            <?php endif; ?>
            function mec_event_gallery_delete_listeners()
            {
                jQuery('.mec-event-gallery-delete').off('click').on('click', function()
                {
                    var id = jQuery(this).data('id');
                    jQuery('.mec-event-gallery-wrapper-'+id).remove();
                });
            }
            mec_event_gallery_delete_listeners();
        });
        </script>
        <div id="mec-event-gallery" class="mec-meta-box-fields mec-fes-gallery">
            <h4><?php esc_html_e('Gallery', 'mec'); ?> <?php echo ( $required ? '<span class="mec-required">*</span>' : ''); ?></h4>
            <div id="mec_meta_box_event_gallery_options" class="mec-form-row">
                <?php if(current_user_can('upload_files')): ?>
                <button type="button" id="mec_event_gallery_image_uploader" class="button" data-post-id="<?php echo esc_attr($post->ID); ?>"><?php esc_html_e('Add event gallery images', 'mec'); ?></button>
                <?php else: ?>
                <input type="file" id="mec_event_gallery_image_uploader" multiple><?php esc_html_e('Add event gallery images', 'mec'); ?>
                <?php endif; ?>
                <p class="description"><?php esc_html_e('png, jpg, gif, and webp files are allowed.', 'mec'); ?></p>
                <div class="mec-error mec-util-hidden" id="mec_event_gallery_error"></div>
            </div>
            <ul id="mec_meta_box_event_gallery">
                <?php foreach($gallery as $image_id): $image_url = wp_get_attachment_url($image_id); ?>
                <li class="mec-event-gallery-wrapper-<?php echo esc_attr($image_id); ?>" data-id="<?php echo esc_attr($image_id); ?>">
                    <input type="hidden" name="mec[event_gallery][]" value="<?php echo esc_attr($image_id); ?>" />
                    <img style="width: 200px;" src="<?php echo esc_url($image_url); ?>"  alt="<?php echo esc_url($image_url); ?>" />
                    <span class="mec-event-gallery-delete" data-id="<?php echo esc_attr($image_id); ?>">x</span>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php
    }

    public static function related_events($post)
    {
        $related_events = get_post_meta($post->ID, 'mec_related_events', true);
        if(!is_array($related_events)) $related_events = [];

        // Main
        $main = \MEC\Base::get_main();

        // All Upcoming Events
        $all_events = $main->get_upcoming_event_ids();
        if(!is_array($all_events)) $all_events = [];

        // Unshift Current Events
        if(count($related_events))
        {
            foreach(array_reverse($related_events) as $related_event)
            {
                array_unshift($all_events, $related_event);
            }
        }

        $all_events = array_unique($all_events);
        ?>
        <div class="mec-meta-box-fields mec-event-tab-content mec-fes-related-events" id="mec-event-related-events">
            <h4><?php esc_html_e('Related Events', 'mec'); ?></h4>
            <div id="mec_meta_box_related_events_options">
                <select id="mec_related_events" class="mec-related_events-dropdown-select2" name="mec[related_events][]" multiple="multiple">
                <?php foreach($all_events as $all_event_id): if($all_event_id == $post->ID) continue; $title = get_post($all_event_id)->post_title; ?>
                    <option value="<?php echo esc_attr($all_event_id); ?>" <?php echo in_array($all_event_id, $related_events) ? 'selected="selected"' : ''; ?>><?php echo esc_html($title); ?></option>
                <?php endforeach; ?>
                </select>
            </div>
        </div>
        <?php
    }

    public static function banner($post)
    {
        $banner_options = get_post_meta($post->ID, 'mec_banner', true);
        if(!is_array($banner_options)) $banner_options = [];

        $mec_banner_status = isset($banner_options['status']) && $banner_options['status'];
        $mec_banner_color = $banner_options['color'] ?? '';
        $mec_banner_image = $banner_options['image'] ?? '';
        $mec_banner_featured_image = $banner_options['use_featured_image'] ?? 0;
        ?>
        <div class="mec-meta-box-fields mec-event-tab-content mec-fes-event-banner" id="mec-event-banner">
            <h4><?php esc_html_e('Event Banner', 'mec'); ?></h4>
            <div class="mec-form-row">
                <label>
                    <input type="hidden" name="mec[banner][display]" value="0" />
                    <input value="1" onchange="jQuery('#mec_meta_box_event_banner_options').toggleClass('mec-util-hidden');" type="checkbox" name="mec[banner][status]" <?php echo $mec_banner_status ? 'checked="checked"' : ''; ?> /><?php esc_html_e('Display Banner', 'mec'); ?>
                </label>
            </div>
            <div id="mec_meta_box_event_banner_options" class="<?php if(!$mec_banner_status) echo 'mec-util-hidden'; ?>">
                <div class="mec-form-row">
                    <label for="mec_banner_color"><?php esc_html_e("Background Color", 'mec'); ?></label>
                    <input type="<?php echo is_admin() ? 'text' : 'color'; ?>" name="mec[banner][color]" class="mec-color-picker" value="<?php echo esc_attr($mec_banner_color); ?>" id="mec_banner_color" />
                </div>
                <div class="mec-form-row">
                    <input type="hidden" name="mec[banner][use_featured_image]" value="0">
                    <label>
                        <input type="checkbox" name="mec[banner][use_featured_image]" value="1" onchange="jQuery('#mec_event_banner_thumbnail_options').toggleClass('w-hidden');" <?php echo $mec_banner_featured_image ? 'checked' : ''; ?>>
                        <?php esc_html_e('Use featured image as banner image', 'mec'); ?>
                    </label>
                </div>
                <div class="mec-form-row mec-thumbnail-row <?php echo $mec_banner_featured_image ? 'w-hidden' : ''; ?>" id="mec_event_banner_thumbnail_options">
                    <div id="mec_banner_thumbnail_img">
                        <?php echo (trim($mec_banner_image) ? '<img src="'.esc_attr($mec_banner_image).'" style="max-width: 100%;" />' : ''); ?>
                    </div>
                    <input type="hidden" id="mec_banner_thumbnail" name="mec[banner][image]" value="<?php if(trim($mec_banner_image)) echo $mec_banner_image; ?>" />
                    <button type="button" class="mec_upload_image_button button" id="mec_banner_thumbnail_button" data-preview-id="mec_banner_thumbnail_img" data-input-id="mec_banner_thumbnail"><?php echo esc_html__('Choose image', 'mec'); ?></button>
                    <button type="button" class="mec_remove_image_button button mec-dash-remove-btn <?php echo (trim($mec_banner_image) ? '' : 'mec-util-hidden'); ?>" data-preview-id="mec_banner_thumbnail_img" data-input-id="mec_banner_thumbnail"><?php echo esc_html__('Remove image', 'mec'); ?></button>
				</div>
            </div>
        </div>
        <?php
    }

    /**
     * Return locations html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function locations( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        $is_fes_form = !is_admin() || $is_edit_mode;

        \MEC\Base::get_main()->load_map_assets();

        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        $locations = get_terms('mec_location', array('orderby'=>'name', 'hide_empty'=>'0'));
        $dont_show_map = get_post_meta($post->ID, 'mec_dont_show_map', true);

        $location_id = get_post_meta($post->ID, 'mec_location_id', true);
        $location_id = apply_filters('wpml_object_id', $location_id, 'mec_location', true);

        $location_ids = get_post_meta($post->ID, 'mec_additional_location_ids', true);
        if(!is_array($location_ids)) $location_ids = [];

        $additional_locations_status = (!isset($settings['additional_locations']) or (isset($settings['additional_locations']) and $settings['additional_locations'])) ? true : false;
        if($is_fes_form and isset($settings['fes_section_other_locations']) and !$settings['fes_section_other_locations']) $additional_locations_status = false;

        // Map Options
        $status = isset($settings['google_maps_status']) ? $settings['google_maps_status'] : 1;
        $api_key = isset($settings['google_maps_api_key']) ? $settings['google_maps_api_key'] : '';

        // FES Options
        $add_new_location = ($is_fes_form and isset($settings['fes_add_location'])) ? $settings['fes_add_location'] : 1;
        $required = ($is_fes_form and isset($settings['fes_required_location']) and $settings['fes_required_location']);
        $optional = !$required;
        ?>

        <div class="mec-meta-box-fields mec-event-tab-content" id="mec-location">
            <h4><?php echo sprintf(esc_html__('Event Main %s', 'mec'), \MEC\Base::get_main()->m('taxonomy_location', esc_html__('Location', 'mec'))); ?> <?php echo ($required ? '<span class="mec-required">*</span>' : ''); ?></h4>
			<div class="mec-form-row">
				<select name="mec[location_id]" id="mec_location_id" title="<?php echo esc_attr__(\MEC\Base::get_main()->m('taxonomy_location', esc_html__('Location', 'mec')), 'mec'); ?>">
                    <?php if($optional): ?>
                    <option value="1"><?php esc_html_e('Hide location', 'mec'); ?></option>
                    <?php endif; ?>
                    <?php if($add_new_location): ?>
                    <option value="0"><?php esc_html_e('Insert a new location', 'mec'); ?></option>
                    <?php endif; ?>
					<?php foreach($locations as $location): ?>
					<option <?php if($location_id == $location->term_id) echo 'selected="selected"'; ?> value="<?php echo esc_attr($location->term_id); ?>"><?php echo esc_html($location->name); ?></option>
					<?php endforeach; ?>
				</select>
                <span class="mec-tooltip">
                    <div class="box top">
                        <h5 class="title"><?php esc_html_e('Location', 'mec'); ?></h5>
                        <div class="content"><p><?php esc_attr_e('Choose one of saved locations or insert a new one.', 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/location/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                    </div>
                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                </span>
			</div>
			<div id="mec_location_new_container">
				<div class="mec-form-row">
					<input type="text" name="mec[location][name]" id="mec_location_name" value="" placeholder="<?php esc_html_e('Location Name', 'mec'); ?>" />
					<p class="description"><?php esc_html_e('eg. City Hall', 'mec'); ?></p>
				</div>
				<div class="mec-form-row">
					<input type="text" name="mec[location][address]" id="mec_location_address" value="" placeholder="<?php esc_html_e('Address', 'mec'); ?>" />
					<p class="description"><?php esc_html_e('eg. City hall, Manhattan, New York', 'mec'); ?></p>

                    <?php if($status and trim($api_key)): ?>
                    <script>
                    jQuery(document).ready(function()
                    {
                        if(typeof google !== 'undefined')
                        {
                            var location_autocomplete = new google.maps.places.Autocomplete(document.getElementById('mec_location_address'));
                            google.maps.event.addListener(location_autocomplete, 'place_changed', function()
                            {
                                var place = location_autocomplete.getPlace();
                                jQuery('#mec_location_latitude').val(place.geometry.location.lat());
                                jQuery('#mec_location_longitude').val(place.geometry.location.lng());
                            });
                        }
                    });
                    </script>
                    <?php endif; ?>
				</div>
                <div class="mec-form-row">
                    <input type="text" name="mec[location][opening_hour]" id="mec_opening_hour" value="" placeholder="<?php esc_html_e('Opening hour in text format like 09:15 or 18:30', 'mec'); ?>" title="<?php esc_attr_e('Opening Hour', 'mec'); ?>" />
                </div>
				<div class="mec-form-row mec-lat-lng-row">
					<input class="mec-has-tip" type="text" name="mec[location][latitude]" id="mec_location_latitude" value="" placeholder="<?php esc_html_e('Latitude', 'mec'); ?>" title="<?php esc_attr_e('Latitude', 'mec'); ?>" />
					<input class="mec-has-tip" type="text" name="mec[location][longitude]" id="mec_location_longitude" value="" placeholder="<?php esc_html_e('Longitude', 'mec'); ?>" title="<?php esc_attr_e('Longitude', 'mec'); ?>" />
                    <span class="mec-tooltip">
                        <div class="box top">
                            <h5 class="title"><?php esc_html_e('Latitude/Longitude', 'mec'); ?></h5>
                            <div class="content"><p><?php esc_attr_e('Latitude and Longitude are parameters that represent the coordinates in the geographic coordinate system. You can find your venue\'s Latitude and Longitude measurments via the link below. ', 'mec'); ?><a href="https://latlong.net" target="_blank"><?php esc_html_e('Get Latitude and Longitude', 'mec'); ?></a></p></div>
                        </div>
                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                    </span>
                </div>
                <div class="mec-form-row">
                    <input type="text" name="mec[location][url]" id="mec_location_url" value="" placeholder="<?php esc_html_e('Location Website', 'mec'); ?>" title="<?php esc_html_e('Location Website', 'mec'); ?>" />
                </div>
                <div class="mec-form-row">
                    <input type="text" name="mec[location][tel]" id="mec_location_tel" value="" placeholder="<?php esc_html_e('Location Phone', 'mec'); ?>" title="<?php esc_html_e('Location Phone', 'mec'); ?>" />
                </div>
                <?php do_action('mec_location_after_new_form'); ?>
                <?php /* Don't show this section in FES */ if( !$is_fes_form ): ?>
				<div class="mec-form-row mec-thumbnail-row">
					<div id="mec_location_thumbnail_img"></div>
					<input type="hidden" name="mec[location][thumbnail]" id="mec_location_thumbnail" value="" />
					<button type="button" class="mec_location_upload_image_button button" id="mec_location_thumbnail_button"><?php echo esc_html__('Choose image', 'mec'); ?></button>
					<button type="button" class="mec_location_remove_image_button button mec-dash-remove-btn mec-util-hidden"><?php echo esc_html__('Remove image', 'mec'); ?></button>
				</div>
                <?php else: ?>
                <div class="mec-form-row mec-thumbnail-row">
                    <span id="mec_fes_location_thumbnail_img"></span>
					<input type="hidden" name="mec[location][thumbnail]" id="mec_fes_location_thumbnail" value="" />
					<input type="file" id="mec_fes_location_thumbnail_file" onchange="mec_fes_upload_location_thumbnail();" />
                    <span class="mec_fes_location_remove_image_button button mec-util-hidden" id="mec_fes_location_remove_image_button"><?php echo esc_html__('Remove image', 'mec'); ?></span>
				</div>
                <?php endif; ?>
			</div>
            <?php if(\MEC\Base::get_main()->getPRO()): ?>
            <div class="mec-form-row mec-show-map-status">
                <input type="hidden" name="mec[dont_show_map]" value="0" />
                <label for="mec_location_dont_show_map"><input type="checkbox" id="mec_location_dont_show_map" name="mec[dont_show_map]" value="1" <?php echo ($dont_show_map ? 'checked="checked"' : ''); ?> /><?php echo esc_html__("Don't show map in single event page", 'mec'); ?></label>
            </div>
            <?php endif; ?>
            <?php if($additional_locations_status and count($locations)): ?>
            <h4><?php echo esc_html(\MEC\Base::get_main()->m('other_locations', esc_html__('Other Locations', 'mec'))); ?></h4>
            <div class="mec-form-row">
                <p class="description"><?php esc_html_e('You can select extra locations in addition to main location if you like.', 'mec'); ?></p>
                <div class="mec-additional-locations">
                    <select class="mec-select2-dropdown" name="mec[additional_location_ids][]" multiple="multiple">
                        <?php foreach($locations as $location): ?>
                            <option <?php if(in_array($location->term_id, $location_ids)) echo 'selected="selected"'; ?> value="<?php echo esc_attr($location->term_id); ?>">
                                <?php echo esc_html($location->name); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <?php endif; ?>
		</div>
        <?php
    }

    /**
     * Return Organizers html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function organizers( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        $is_fes_form = !is_admin() || $is_edit_mode;

        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        $organizers = get_terms('mec_organizer', array('orderby'=>'name', 'hide_empty'=>'0'));

        $organizer_id = get_post_meta($post->ID, 'mec_organizer_id', true);
        $organizer_id = apply_filters('wpml_object_id', $organizer_id, 'mec_organizer', true);

        // Detect it by current user
        if($is_fes_form && trim($organizer_id) === '' && is_user_logged_in())
        {
            // MEC Main
            $main = \MEC\Base::get_main();

            $current_user = wp_get_current_user();
            $organizer_id = apply_filters(
                'mec_get_organizer_id_by_email',
                $main->get_organizer_id_by_email($current_user->user_email),
                $current_user,
                $current_user->user_email
            );
        }

        $organizer_ids = get_post_meta($post->ID, 'mec_additional_organizer_ids', true);
        if(!is_array($organizer_ids)) $organizer_ids = [];
        $organizer_ids = array_unique($organizer_ids);

        $additional_organizers_status = !isset($settings['additional_organizers']) || $settings['additional_organizers'];

        // FES Options
        $use_all_organizers = (($is_fes_form and isset($settings['fes_use_all_organizers']) and !$settings['fes_use_all_organizers']) ? false : true);
        if(!$use_all_organizers)
        {
            $additional_organizers_status = false;
            $organizers = [];

            // Display Saved Organizer for Current Event in FES
            if($post->ID and $organizer_id and $organizer_id != 1) $organizers[] = get_term($organizer_id);
        }

        $add_new_organizer = ($is_fes_form and isset($settings['fes_add_organizer'])) ? $settings['fes_add_organizer'] : 1;
        ?>
        <div class="mec-meta-box-fields mec-event-tab-content" id="mec-organizer">
            <h4><?php echo sprintf(esc_html__('Event Main %s', 'mec'), \MEC\Base::get_main()->m('taxonomy_organizer', esc_html__('Organizer', 'mec'))); ?></h4>
			<div class="mec-form-row">
				<select name="mec[organizer_id]" id="mec_organizer_id" title="<?php echo esc_attr__(\MEC\Base::get_main()->m('taxonomy_organizer', esc_html__('Organizer', 'mec')), 'mec'); ?>">
                    <option value="1"><?php esc_html_e('Hide organizer', 'mec'); ?></option>
                    <?php if($add_new_organizer): ?>
					<option value="0"><?php esc_html_e('Insert a new organizer', 'mec'); ?></option>
                    <?php endif; ?>
					<?php foreach($organizers as $organizer): ?>
					<option <?php if($organizer_id == $organizer->term_id) echo ($selected = 'selected="selected"'); ?> value="<?php echo esc_attr($organizer->term_id); ?>"><?php echo esc_html($organizer->name); ?></option>
					<?php endforeach; ?>
				</select>
                <span class="mec-tooltip">
                    <div class="box top">
                        <h5 class="title"><?php esc_html_e('Organizer', 'mec'); ?></h5>
                        <div class="content"><p><?php esc_attr_e('Choose one of the saved organizers or insert a new one.', 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/organizer-and-other-organizer/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                    </div>
                    <i title="" class="dashicons-before dashicons-editor-help"></i>
                </span>
			</div>
			<div id="mec_organizer_new_container">
				<div class="mec-form-row">
					<input type="text" name="mec[organizer][name]" id="mec_organizer_name" value="" placeholder="<?php esc_html_e('Name', 'mec'); ?>" />
					<p class="description"><?php esc_html_e('eg. John Smith', 'mec'); ?></p>
				</div>
                <div class="mec-form-row">
                    <input type="text" name="mec[organizer][tel]" id="mec_organizer_tel" value="" placeholder="<?php esc_attr_e('Phone number.', 'mec'); ?>" />
                    <p class="description"><?php esc_html_e('eg. +1 (234) 5678', 'mec'); ?></p>
                </div>
                <div class="mec-form-row">
                    <input type="text" name="mec[organizer][email]" id="mec_organizer_email" value="" placeholder="<?php esc_attr_e('Email address.', 'mec'); ?>" />
                    <p class="description"><?php esc_html_e('eg. john@smith.com', 'mec'); ?></p>
                </div>
                <div class="mec-form-row">
                    <input type="url" name="mec[organizer][url]" id="mec_organizer_url" value="" placeholder="<?php esc_html_e('Page URL', 'mec'); ?>" />
                    <p class="description"><?php esc_html_e('eg. https://webnus.net', 'mec'); ?></p>
                </div>
                <div class="mec-form-row">
                    <input type="text" name="mec[organizer][page_label]" id="mec_organizer_page_label" value="" placeholder="<?php esc_html_e('Page Label', 'mec'); ?>" />
                    <p class="description"><?php esc_html_e('eg. Website name or any text', 'mec'); ?></p>
                </div>
                <?php /* Don't show this section in FES */ if( !$is_fes_form ): ?>
				<div class="mec-form-row mec-thumbnail-row">
					<div id="mec_organizer_thumbnail_img"></div>
					<input type="hidden" name="mec[organizer][thumbnail]" id="mec_organizer_thumbnail" value="" />
                    <button type="button" class="mec_organizer_upload_image_button button" id="mec_organizer_thumbnail_button"><?php echo esc_html__('Choose image', 'mec'); ?></button>
					<button type="button" class="mec_organizer_remove_image_button button mec-util-hidden mec-dash-remove-btn"><?php echo esc_html__('Remove image', 'mec'); ?></button>
				</div>
                <?php else: ?>
                <div class="mec-form-row mec-thumbnail-row">
                    <span id="mec_fes_organizer_thumbnail_img"></span>
					<input type="hidden" name="mec[organizer][thumbnail]" id="mec_fes_organizer_thumbnail" value="" />
					<input type="file" id="mec_fes_organizer_thumbnail_file" onchange="mec_fes_upload_organizer_thumbnail();" />
                    <span class="mec_fes_organizer_remove_image_button button mec-util-hidden" id="mec_fes_organizer_remove_image_button"><?php echo esc_html__('Remove image', 'mec'); ?></span>
				</div>
                <?php endif; ?>
			</div>
            <?php if($additional_organizers_status and count($organizers)): ?>
            <div id="mec-additional-organizer-wrap" class="<?php echo !isset($selected) ? 'mec-util-hidden' : ''; ?>">
                <h4><?php echo esc_html(\MEC\Base::get_main()->m('other_organizers', esc_html__('Other Organizers', 'mec'))); ?></h4>
                <div class="mec-form-row">
                    <p><?php esc_html_e('You can select extra organizers in addition to main organizer if you like.', 'mec'); ?></p>
                    <div class="mec-additional-organizers">
                        <select class="mec-select2-dropdown">
                            <?php foreach($organizers as $organizer): ?>
                            <option <?php if(in_array($organizer->term_id, $organizer_ids)) echo 'selected="selected"'; ?> value="<?php echo esc_attr($organizer->term_id); ?>">
                                <?php echo esc_html($organizer->name); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                        <button class="button" id="mec_additional_organizers_add" type="button" data-sort-label="<?php esc_attr_e('Sort', 'mec'); ?>" data-remove-label="<?php esc_attr_e('Remove', 'mec'); ?>"><?php esc_html_e('Add', 'mec'); ?></button>
                    </div>
                </div>
                <div class="mec-form-row">
                    <ul id="mec_orgz_form_row" class="mec-additional-organizers-list">
                        <?php foreach($organizer_ids as $organizer_id): $organizer = get_term($organizer_id); ?>
                        <li>
                            <input type="hidden" name="mec[additional_organizer_ids][]" value="<?php echo esc_attr($organizer_id); ?>">
                            <span class="mec-additional-organizer-sort"><?php echo esc_html__('Sort', 'mec'); ?></span>
                            <span onclick="mec_additional_organizers_remove(this);" class="mec-additional-organizer-remove"><?php echo esc_html__('Remove', 'mec'); ?></span>
                            <span class="mec_orgz_item_name"><?php echo esc_html($organizer->name); ?></span>
                        </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
            <?php endif; ?>
		</div>
        <?php
    }

    /**
     * Return booking options
     *
     * @param int $post_id
     *
     * @since 1.0.0
     *
     * @return array
     */
    public static function get_booking_options( $post_id ){

        $booking_options = get_post_meta($post_id, 'mec_booking', true);
        if(!is_array($booking_options)) {

            $booking_options = [];
        }

        return $booking_options;
    }

    /**
     * Return total booking limit html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function total_booking_limit( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_limit = isset($booking_options['bookings_limit']) ? $booking_options['bookings_limit'] : '';
        $bookings_limit_unlimited = isset($booking_options['bookings_limit_unlimited']) && $booking_options['bookings_limit_unlimited'] == 1 ? true : false;
        ?>
        <div class="mec-meta-box-fields" id="mec-total-booking-limit">
            <h4 class="mec-title"><label for="mec_bookings_limit"><?php esc_html_e('Total booking limit', 'mec'); ?></label></h4>
            <div class="mec-form-row">
                <label class="mec-col-4" for="mec_bookings_limit_unlimited" id="mec_bookings_limit_unlimited_label">
                    <input type="hidden" name="mec[booking][bookings_limit_unlimited]" value="0"/>
                    <input id="mec_bookings_limit_unlimited" <?php checked( $bookings_limit_unlimited ) ?> type="checkbox" value="1" name="mec[booking][bookings_limit_unlimited]"/>
                    <?php esc_html_e('Unlimited', 'mec'); ?>
                    <span class="mec-tooltip">
                        <div class="box">
                            <h5 class="title"><?php esc_html_e('Total booking limit', 'mec'); ?></h5>
                            <div class="content">
                                <p>
                                    <?php esc_attr_e('If you want to set a limit to all the tickets, uncheck this checkbox and put a limitation number for it.', 'mec'); ?>
                                    <a href="https://webnus.net/dox/modern-events-calendar/total-booking-limits/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a>
                                    <a href="https://webnus.net/dox/modern-events-calendar/add-a-booking-system/" target="_blank"><?php esc_html_e('Read About A Booking System', 'mec'); ?></a>
                                </p>
                            </div>
                        </div>
                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                    </span>
                </label>
                <input class="mec-col-4 <?php echo $bookings_limit_unlimited ? 'mec-util-hidden' : ''; ?>" type="number" name="mec[booking][bookings_limit]" id="mec_bookings_limit"
                        value="<?php echo esc_attr($bookings_limit); ?>" placeholder="<?php esc_html_e('100', 'mec'); ?>"/>
            </div>
        </div>
        <?php
    }

    /**
     * Return date selection method html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function booking_date_selection( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );
        $bookings_date_selection = isset($booking_options['bookings_date_selection']) ? $booking_options['bookings_date_selection'] : 'global';
        ?>
        <div class="mec-meta-box-fields" id="mec-booking-date-selection">
            <h4 class="mec-title"><?php esc_html_e('Date Selection', 'mec'); ?></h4>
            <div class="mec-form-row">
            <label class="mec-col-4" for="mec_bookings_date_selection"><?php esc_html_e('Date Selection', 'mec'); ?></label>
                <div class="mec-col-4">
                    <select name="mec[booking][bookings_date_selection]" id="mec_bookings_date_selection">
                        <option value="global" <?php echo $bookings_date_selection === 'global' ? 'selected="selected"' : ''; ?>><?php esc_html_e('Inherit from global options', 'mec'); ?></option>
                        <option value="dropdown" <?php echo $bookings_date_selection === 'dropdown' ? 'selected' : ''; ?>><?php esc_html_e('Dropdown', 'mec'); ?></option>
                        <option value="calendar" <?php echo $bookings_date_selection === 'calendar' ? 'selected' : ''; ?>><?php esc_html_e('Calendar', 'mec'); ?></option>
                        <option value="checkboxes" <?php echo $bookings_date_selection === 'checkboxes' ? 'selected' : ''; ?>><?php esc_html_e('Checkboxes', 'mec'); ?></option>
                        <option value="express-calendar" <?php echo $bookings_date_selection === 'express-calendar' ? 'selected' : ''; ?>><?php esc_html_e('Express Calendar', 'mec'); ?></option>
                    </select>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Return bookings minimum per booking html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function minimum_ticket_per_booking( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_minimum_per_booking = (isset($booking_options['bookings_minimum_per_booking']) and trim($booking_options['bookings_minimum_per_booking'])) ? (int) $booking_options['bookings_minimum_per_booking'] : 1;
        ?>
        <div class="mec-meta-box-fields" id="mec-minimum-ticket-per-booking">
            <h4 class="mec-title"><label for="mec_bookings_mtpb"><?php esc_html_e('Minimum ticket per booking', 'mec'); ?></label></h4>
            <div class="mec-form-row">
                <input class="mec-col-4" type="number" name="mec[booking][bookings_minimum_per_booking]" id="mec_bookings_mtpb"
                    value="<?php echo esc_attr($bookings_minimum_per_booking); ?>" placeholder="<?php esc_html_e('1', 'mec'); ?>" min="1" step="1">
            </div>
        </div>
        <?php
    }

    /**
     * Return discount per user roles html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function discount_per_user_roles( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        global $wp_roles;
        $roles = $wp_roles->get_names();

        $loggedin_discount = isset($booking_options['loggedin_discount']) ? $booking_options['loggedin_discount'] : '';

        ?>
        <div class="mec-meta-box-fields" id="mec-discount-per-user-roles">
            <h4 class="mec-title"><?php esc_html_e('Discount per user roles', 'mec'); ?></h4>
            <?php
            foreach($roles as $role_key => $role_name):
                $role_discount = isset($booking_options['roles_discount_'.$role_key]) ? $booking_options['roles_discount_'.$role_key] : $loggedin_discount;
                ?>
                <div class="mec-form-row">
                    <div class="mec-col-2">
                        <label for="mec_bookings_roles_discount_<?php echo esc_attr($role_key); ?>"><?php echo esc_html($role_name); ?></label>
                    </div>
                    <input class="mec-col-4" type="text" name="mec[booking][roles_discount_<?php echo esc_attr($role_key); ?>]" id="mec_bookings_roles_discount_<?php echo esc_attr($role_key); ?>" value="<?php echo esc_attr($role_discount); ?>" placeholder="<?php esc_html_e('e.g 5', 'mec'); ?>">
                </div>
            <?php endforeach; ?>
        </div>
        <?php
    }


    /**
     * Return discount per user roles html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function book_all_occurrences( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_all_occurrences = isset($booking_options['bookings_all_occurrences']) ? $booking_options['bookings_all_occurrences'] : 0;
        $bookings_all_occurrences_multiple = isset($booking_options['bookings_all_occurrences_multiple']) ? $booking_options['bookings_all_occurrences_multiple'] : 0;

        ?>
        <div class="mec-meta-box-fields" id="mec-book-all-occurrences">
            <h4 class="mec-title"><?php esc_html_e('Book All Occurrences', 'mec'); ?></h4>
            <div class="mec-form-row">
                <label class="mec-col-12" for="mec_bookings_all_occurrences">
                    <input type="hidden" name="mec[booking][bookings_all_occurrences]" value="0"/>
                    <input id="mec_bookings_all_occurrences"
                        <?php
                        if ($bookings_all_occurrences == 1) {
                            echo 'checked="checked"';
                        }
                        ?>
                            type="checkbox" value="1" name="mec[booking][bookings_all_occurrences]" onchange="jQuery('#mec_bookings_all_occurrences_options').toggle();"/>
                    <?php esc_html_e('Sell all occurrences by one booking', 'mec'); ?>
                    <span class="mec-tooltip">
                        <div class="box">
                            <h5 class="title"><?php esc_html_e('Book All Occurrences', 'mec'); ?></h5>
                            <div class="content">
                                <p>
                                    <?php esc_attr_e("If you have a series of events and you want to sell all of them at once, this option is for you! For example a weekly yoga course or something similar.", 'mec'); ?>
                                </p>
                            </div>
                        </div>
                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                    </span>
                </label>
            </div>
            <div class="mec-form-row <?php echo (!$bookings_all_occurrences ? 'mec-util-hidden' : ''); ?>" id="mec_bookings_all_occurrences_options">
                <label class="mec-col-8" for="mec_bookings_all_occurrences_multiple">
                    <input type="hidden" name="mec[booking][bookings_all_occurrences_multiple]" value="0"/>
                    <input id="mec_bookings_all_occurrences_multiple"
                        <?php
                        if ($bookings_all_occurrences_multiple == 1) {
                            echo 'checked="checked"';
                        }
                        ?>
                            type="checkbox" value="1" name="mec[booking][bookings_all_occurrences_multiple]"/>
                    <?php esc_html_e('Allow multiple bookings by same email on different dates', 'mec'); ?>
                </label>
            </div>
        </div>
        <?php
    }

    /**
     * Return interval options html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function interval_options( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_stop_selling_after_first_occurrence = isset($booking_options['stop_selling_after_first_occurrence']) ? $booking_options['stop_selling_after_first_occurrence'] : 0;
        ?>
        <div class="mec-meta-box-fields" id="mec-interval-options">
            <h4 class="mec-title"><?php esc_html_e('Interval Options', 'mec'); ?></h4>
            <div class="mec-form-row">
                <label class="mec-col-4 mec_booking_show_booking_form_interval_label" for="mec_booking_show_booking_form_interval"><?php esc_html_e('Show Booking Form Interval', 'mec'); ?></label>
                <div class="mec-col-4">
                    <input type="number" id="mec_booking_show_booking_form_interval" name="mec[booking][show_booking_form_interval]" value="<?php echo ((isset($booking_options['show_booking_form_interval']) and trim($booking_options['show_booking_form_interval']) != '') ? $booking_options['show_booking_form_interval'] : ''); ?>" placeholder="<?php esc_attr_e('Minutes (e.g 5)', 'mec'); ?>" />
                    <span class="mec-tooltip">
                        <div class="box">
                            <h5 class="title"><?php esc_html_e('Show Booking Form Interval', 'mec'); ?></h5>
                            <div class="content"><p><?php esc_attr_e("You can show the booking form only at certain times before the event starts. If you set this option to 30 then the booking form will open only 30 minutes before starting the event! One day is 1440 minutes.", 'mec'); ?></p></div>
                        </div>
                        <i title="" class="dashicons-before dashicons-editor-help"></i>
                    </span>
                </div>
            </div>
            <div class="mec-form-row">
                <label class="mec-col-8 mec_booking_stop_selling_after_first_occurrence_label" for="mec_booking_stop_selling_after_first_occurrence">
                    <input type="hidden" name="mec[booking][stop_selling_after_first_occurrence]" value="0"/>
                    <input id="mec_booking_stop_selling_after_first_occurrence"
                        <?php
                        if ($bookings_stop_selling_after_first_occurrence == 1) {
                            echo 'checked="checked"';
                        }
                        ?>
                            type="checkbox" value="1" name="mec[booking][stop_selling_after_first_occurrence]"/>
                    <?php esc_html_e('Stop selling tickets after first occurrence.', 'mec'); ?>
                </label>
            </div>
        </div>
        <?php
    }

    /**
     * Return automatic approval html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function automatic_approval( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        ?>
        <div class="mec-meta-box-fields" id="mec-automatic-approval">
            <h4><?php esc_html_e('Automatic Approval', 'mec'); ?></h4>
            <div class="mec-form-row">
                <label class="mec-col-4" for="mec_booking_auto_verify"><?php esc_html_e('Email Verification', 'mec'); ?></label>
                <div class="mec-col-4">
                    <select name="mec[booking][auto_verify]" id="mec_booking_auto_verify">
                        <option value="global" <?php if(isset($booking_options['auto_verify']) and 'global' == $booking_options['auto_verify']) echo 'selected="selected"'; ?>><?php esc_html_e('Inherit from global options', 'mec'); ?></option>
                        <option value="0" <?php if(isset($booking_options['auto_verify']) and '0' == $booking_options['auto_verify']) echo 'selected="selected"'; ?>><?php esc_html_e('Disabled', 'mec'); ?></option>
                        <option value="1" <?php if(isset($booking_options['auto_verify']) and '1' == $booking_options['auto_verify']) echo 'selected="selected"'; ?>><?php esc_html_e('Enabled', 'mec'); ?></option>
                    </select>
                </div>
            </div>
            <div class="mec-form-row">
                <label class="mec-col-4" for="mec_booking_auto_confirm"><?php esc_html_e('Booking Confirmation', 'mec'); ?></label>
                <div class="mec-col-4">
                    <select name="mec[booking][auto_confirm]" id="mec_booking_auto_confirm">
                        <option value="global" <?php if(isset($booking_options['auto_confirm']) and 'global' == $booking_options['auto_confirm']) echo 'selected="selected"'; ?>><?php esc_html_e('Inherit from global options', 'mec'); ?></option>
                        <option value="0" <?php if(isset($booking_options['auto_confirm']) and '0' == $booking_options['auto_confirm']) echo 'selected="selected"'; ?>><?php esc_html_e('Disabled', 'mec'); ?></option>
                        <option value="1" <?php if(isset($booking_options['auto_confirm']) and '1' == $booking_options['auto_confirm']) echo 'selected="selected"'; ?>><?php esc_html_e('Enabled', 'mec'); ?></option>
                    </select>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Return last few tickets percentage html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function last_few_tickets_percentage( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_last_few_tickets_percentage_inherite = $booking_options['last_few_tickets_percentage_inherit'] ?? 1;
        $bookings_last_few_tickets_percentage = ((isset($booking_options['last_few_tickets_percentage']) and trim($booking_options['last_few_tickets_percentage']) != '') ? max(1, $booking_options['last_few_tickets_percentage']) : (isset($settings['booking_last_few_tickets_percentage']) ? max(1, $settings['booking_last_few_tickets_percentage']) : 15));

        ?>
        <div class="mec-meta-box-fields" id="mec-last-few-tickets-percentage">
            <div class="mec-form-row">
                <h4 class="mec-title"><?php esc_html_e('Last Few Tickets Percentage', 'mec'); ?></h4>
                <div class="mec-form-row">
                    <label class="mec-col-4" for="mec_bookings_last_few_tickets_percentage_inherit">
                        <input type="hidden" name="mec[booking][last_few_tickets_percentage_inherit]" value="0"/>
                        <input id="mec_bookings_last_few_tickets_percentage_inherit"
                            <?php
                            if ($bookings_last_few_tickets_percentage_inherite == 1) {
                                echo 'checked="checked"';
                            }
                            ?>
                                type="checkbox" value="1" name="mec[booking][last_few_tickets_percentage_inherit]" onchange="jQuery(this).parent().parent().find('input[type=number]').toggle();"/>
                        <?php esc_html_e('Inherit from global options', 'mec'); ?>
                    </label>
                    <input class="mec-col-4" <?php echo ($bookings_last_few_tickets_percentage_inherite == 1) ? 'style="display: none;"' : ''; ?> type="number" min="1" max="100" step="1" name="mec[booking][last_few_tickets_percentage]" value="<?php echo esc_attr($bookings_last_few_tickets_percentage); ?>" placeholder="<?php esc_html_e('15', 'mec'); ?>"/>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Return thankyou page html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function thankyou_page( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_thankyou_page_inherit = isset($booking_options['thankyou_page_inherit']) ? $booking_options['thankyou_page_inherit'] : 1;

        $pages = get_pages();
        ?>

        <div class="mec-meta-box-fields" id="mec-thankyou-page">
            <h4 class="mec-title"><?php esc_html_e('Thank You Page', 'mec'); ?></h4>
            <div class="mec-form-row">
                <label class="mec-col-4 mec_bookings_thankyou_page_inherit" for="mec_bookings_thankyou_page_inherit">
                    <input type="hidden" name="mec[booking][thankyou_page_inherit]" value="0"/>
                    <input id="mec_bookings_thankyou_page_inherit"
                        <?php
                        if ($bookings_thankyou_page_inherit == 1) {
                            echo 'checked="checked"';
                        }
                        ?>
                            type="checkbox" value="1" name="mec[booking][thankyou_page_inherit]" onchange="jQuery('#mec_booking_thankyou_page_options').toggle();"/>
                    <?php esc_html_e('Inherit from global options', 'mec'); ?>
                </label>
            </div>
            <div id="mec_booking_thankyou_page_options" <?php echo ($bookings_thankyou_page_inherit == 1) ? 'style="display: none;"' : ''; ?>>
                <br>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_bookings_booking_thankyou_page"><?php esc_html_e('Thank You Page', 'mec'); ?></label>
                    <div class="mec-col-9">
                        <select id="mec_bookings_booking_thankyou_page" name="mec[booking][booking_thankyou_page]">
                            <option value="">----</option>
                            <?php foreach($pages as $page): ?>
                                <option <?php echo ((isset($booking_options['booking_thankyou_page']) and $booking_options['booking_thankyou_page'] == $page->ID) ? 'selected="selected"' : ''); ?> value="<?php echo esc_attr($page->ID); ?>"><?php echo esc_html($page->post_title); ?></option>
                            <?php endforeach; ?>
                        </select>
                        <span class="mec-tooltip">
                            <div class="box left">
                                <h5 class="title"><?php esc_html_e('Thank You Page', 'mec'); ?></h5>
                                <div class="content"><p><?php esc_attr_e("User redirects to this page after booking. Leave it empty if you want to disable it.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                            </div>
                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                        </span>
                    </div>
                </div>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_bookings_booking_thankyou_page_time"><?php esc_html_e('Thank You Page Time Interval', 'mec'); ?></label>
                    <div class="mec-col-9">
                        <input type="number" id="mec_bookings_booking_thankyou_page_time" name="mec[booking][booking_thankyou_page_time]" value="<?php echo ((isset($booking_options['booking_thankyou_page_time']) and trim($booking_options['booking_thankyou_page_time']) != '0') ? $booking_options['booking_thankyou_page_time'] : '2000'); ?>" placeholder="<?php esc_attr_e('2000 mean 2 seconds', 'mec'); ?>" />
                        <span class="mec-tooltip">
                            <div class="box left">
                                <h5 class="title"><?php esc_html_e('Thank You Page Time Interval', 'mec'); ?></h5>
                                <div class="content"><p><?php esc_attr_e("Waiting time before redirecting to thank you page. It's in miliseconds so 2000 means 2 seconds.", 'mec'); ?><a href="https://webnus.net/dox/modern-events-calendar/booking/" target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
                            </div>
                            <i title="" class="dashicons-before dashicons-editor-help"></i>
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <?php
    }

    /**
     * Return booking button label html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function booking_button_label( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_booking_button_label = ((isset($booking_options['bookings_booking_button_label']) and trim($booking_options['bookings_booking_button_label']) != '') ? $booking_options['bookings_booking_button_label'] : '');

        ?>
        <div class="mec-meta-box-fields" id="mec-booking-button-label">
            <h4 class="mec-title"><label for="mec_bookings_bbl"><?php esc_html_e('Booking Button Label', 'mec'); ?></label></h4>
            <div class="mec-form-row">
                <input class="mec-col-4" type="text" name="mec[booking][bookings_booking_button_label]" id="mec_bookings_bbl"
                    value="<?php echo esc_attr($bookings_booking_button_label); ?>" placeholder="<?php esc_html_e('Book Now', 'mec'); ?>">
            </div>
        </div>
        <?php
    }

    /**
     * Return booking partial payment html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function booking_partial_payment($post, $atts = array())
    {
        if(!static::booking_demo_check($post, $atts))
        {
            return;
        }

        // Partial Payment
        $partial_payment = \MEC\Base::get_main()->getPartialPayment();

        // Partial Payment per event is not enabled
        if(!$partial_payment->is_payable_per_event_enabled()) return;

        $booking_options = static::get_booking_options( $post->ID );

        $payable_inherit = !isset($booking_options['bookings_payable_inherit']) || $booking_options['bookings_payable_inherit'];
        $payable = $booking_options['bookings_payable'] ?? 100;
        $payable_type = $booking_options['bookings_payable_type'] ?? 'percent';

        // Validate
        list($payable, $payable_type) = $partial_payment->validate_payable_options($payable, $payable_type);
        ?>
        <div class="mec-meta-box-fields" id="mec-booking-partial-payment">
            <h4 class="mec-title"><?php esc_html_e('Partial Payment', 'mec'); ?></h4>
            <div class="mec-form-row">
                <label class="mec-col-4 mec-bookings-payable-inherit" for="mec_bookings_payable_inherit">
                    <input type="hidden" name="mec[booking][bookings_payable_inherit]" value="0"/>
                    <input id="mec_bookings_payable_inherit"
                        <?php
                        if ($payable_inherit == 1) {
                            echo 'checked="checked"';
                        }
                        ?>
                            type="checkbox" value="1" name="mec[booking][bookings_payable_inherit]" onchange="jQuery('#mec_booking_payable_options').toggle();"/>
                    <?php esc_html_e('Inherit from global options', 'mec'); ?>
                </label>
            </div>
            <div id="mec_booking_payable_options" <?php echo ($payable_inherit == 1) ? 'style="display: none;"' : ''; ?>>
                <br>
                <div class="mec-form-row">
                    <label class="mec-col-3" for="mec_bookings_payable"><?php esc_html_e('Payable', 'mec'); ?></label>
                    <div class="mec-col-9">
                        <input type="number" min="1" id="mec_bookings_payable" name="mec[booking][bookings_payable]" value="<?php echo esc_attr($payable); ?>" />
                        <select id="mec_bookings_payable_type" name="mec[booking][bookings_payable_type]" title="<?php esc_attr_e('Payable Type', 'mec'); ?>">
                            <option value="percent" <?php echo ($payable_type === 'percent') ? 'selected' : ''; ?>><?php esc_attr_e('Percent (%)', 'mec'); ?></option>
                            <option value="amount" <?php echo ($payable_type === 'amount') ? 'selected' : ''; ?>><?php esc_attr_e('Amount ($)', 'mec'); ?></option>
                        </select>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Return booking button label html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function total_user_booking_limits( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        $bookings_user_limit = $booking_options['bookings_user_limit'] ?? '';
        $bookings_user_limit_unlimited = $booking_options['bookings_user_limit_unlimited'] ?? true;

        ?>
        <div class="mec-meta-box-fields" id="mec_bookings_user_limit">
            <h4 class="mec-title"><label for="mec_bookings_user_limit"><?php esc_html_e('Total User Booking Limits', 'mec'); ?></label></h4>
            <div class="mec-form-row">
                <label class="mec-col-4" for="mec_bookings_user_limit_unlimited" id="mec_bookings_user_limit_unlimited_label">
                    <input type="hidden" name="mec[booking][bookings_user_limit_unlimited]" value="0"/>
                    <input id="mec_bookings_user_limit_unlimited"
                        <?php
                        if ($bookings_user_limit_unlimited == 1) {
                            echo 'checked="checked"';
                        }
                        ?>
                            type="checkbox" value="1" name="mec[booking][bookings_user_limit_unlimited]" onchange="jQuery(this).parent().parent().find('input[type=text]').toggle().val('');"/>
                    <?php esc_html_e('Inherit from global options', 'mec'); ?>
                </label>
                <input class="mec-col-4" <?php echo ($bookings_user_limit_unlimited == 1) ? 'style="display: none;"' : ''; ?> type="text" name="mec[booking][bookings_user_limit]" id="mec_bookings_user_limit"
                        value="<?php echo esc_attr($bookings_user_limit); ?>" placeholder="<?php esc_html_e('12', 'mec'); ?>"/>
            </div>
        </div>
        <?php
    }

    /**
     * Return booking button label html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function gateways( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        $gateway_settings = \MEC\Base::get_main()->get_gateways_options();

        if( !( isset($gateway_settings['gateways_per_event']) and $gateway_settings['gateways_per_event'] ) ){

            if( $is_edit_mode ){

                echo '<div class="mec-content-notification">
					<p>'
						.'<span>'
							. esc_html__('Payment gateways per event is disabled.', 'mec')
						.'</span>'
						.'<a href="#" target="_blank">' . esc_html__('How to set', 'mec') . ' </a>'
					.'</p>'
				.'</div>';
            }

            return;
        }

        $gateways = \MEC\Base::get_main()->get_gateways();
        $enableds_gateways = [];
        foreach($gateways as $gateway){

            if(!$gateway->enabled()) continue;
            $enableds_gateways[] = $gateway;
        }

        if( $is_edit_mode && empty( $enableds_gateways ) ){

            echo '<div class="mec-content-notification">
                <p>'
                    .'<span>'
                        . esc_html__('There is no payment gateway to show.', 'mec')
                    .'</span>'
                    .'<a href="#" target="_blank">' . esc_html__('How to set', 'mec') . ' </a>'
                .'</p>'
            .'</div>';

            return;
        }

        $booking_options = static::get_booking_options( $post->ID );

        ?>
        <div class="mec-meta-box-fields mec-booking-tab-content" id="mec_meta_box_booking_options_form_gateways_per_event">
            <h4 class="mec-title"><?php esc_html_e('Disabled Gateways', 'mec'); ?></h4>
            <p class="description"><?php esc_html_e("You can disable some of the following payment gateways by checking them otherwise they will be enabled.", 'mec'); ?></p>

            <?php foreach($enableds_gateways as $g): ?>
            <div class="mec-form-row" style="margin-bottom: 0;">
                <label class="mec-col-4">
                    <input type="hidden" name="mec[booking][gateways_<?php echo esc_attr($g->id()); ?>_disabled]" value="0"/>
                    <input type="checkbox" value="1" name="mec[booking][gateways_<?php echo esc_attr($g->id()); ?>_disabled]" <?php echo (isset($booking_options['gateways_'.$g->id().'_disabled']) and $booking_options['gateways_'.$g->id().'_disabled']) ? 'checked="checked"' : ''; ?> />
                    <?php echo esc_html($g->title()); ?>
                </label>
            </div>
            <?php endforeach; ?>
        </div>
        <?php
    }

    /**
     * Return fees html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function fees( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        $booking_options = static::get_booking_options( $post->ID );

        $global_inheritance = get_post_meta($post->ID, 'mec_fees_global_inheritance', true);
        if (trim($global_inheritance) == '') {
            $global_inheritance = 1;
        }

        $fees = get_post_meta($post->ID, 'mec_fees', true);

        $global_fees = isset($settings['fees']) ? $settings['fees'] : [];
        if (!is_array($fees) and trim($fees) == '') {
            $fees = $global_fees;
        }

        if (!is_array($fees)) {
            $fees = [];
        }
        ?>
        <div class="mec-meta-box-fields mec-booking-tab-content mec-fes-fees" id="mec-fees">
            <h4 class="mec-meta-box-header"><?php esc_html_e('Fees', 'mec'); ?></h4>
            <div id="mec_meta_box_fees_form">
                <div class="mec-form-row">
                    <label class="fees_global_inheritance_label">
                        <input type="hidden" name="mec[fees_global_inheritance]" value="0"/>
                        <input onchange="jQuery('#mec_taxes_fees_container_toggle').toggle();" value="1" type="checkbox"
                               name="mec[fees_global_inheritance]"
                            <?php
                            if ($global_inheritance) {
                                echo 'checked="checked"';
                            }
                            ?>
                        /><?php esc_html_e('Inherit from global options', 'mec'); ?>
                    </label>
                </div>
                <div id="mec_taxes_fees_container_toggle" class="
				<?php
                if ($global_inheritance) {
                    echo 'mec-util-hidden';
                }
                ?>
				">
                    <div class="mec-form-row">
                        <button class="button" type="button" id="mec_add_fee_button"><?php esc_html_e('Add', 'mec'); ?></button>
                    </div>
                    <div id="mec_fees_list">
                        <?php
                        $i = 0;
                        foreach ($fees as $key => $fee) :
                            if (!is_numeric($key)) {
                                continue;
                            }
                            $i = max($i, $key);
                            ?>
                            <div class="mec-box" id="mec_fee_row<?php echo esc_attr($i); ?>">
                                <div class="mec-form-row">
                                    <input class="mec-col-12" type="text" name="mec[fees][<?php echo esc_attr($i); ?>][title]"
                                           placeholder="<?php esc_attr_e('Fee Title', 'mec'); ?>"
                                           value="<?php echo(isset($fee['title']) ? esc_attr($fee['title']) : ''); ?>"/>
                                </div>
                                <div class="mec-form-row">
								<span class="mec-col-4">
									<input type="text" name="mec[fees][<?php echo esc_attr($i); ?>][amount]"
                                           placeholder="<?php esc_attr_e('Amount', 'mec'); ?>"
                                           value="<?php echo(isset($fee['amount']) ? esc_attr($fee['amount']) : 0); ?>"/>
									<span class="mec-tooltip">
										<div class="box top">
											<h5 class="title"><?php esc_html_e('Amount', 'mec'); ?></h5>
											<div class="content"><p><?php esc_attr_e('Fee amount, considered as fixed amount if you set the type to amount otherwise considered as percentage', 'mec'); ?>
                                                    <a href="https://webnus.net/dox/modern-events-calendar/tickets-and-taxes-fees/"
                                                       target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
										</div>
										<i title="" class="dashicons-before dashicons-editor-help"></i>
									</span>
								</span>
                                    <span class="mec-col-4">
									<select name="mec[fees][<?php echo esc_attr($i); ?>][type]">
										<option value="percent" <?php echo((isset($fee['type']) and $fee['type'] == 'percent') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Percent', 'mec'); ?></option>
										<option value="amount" <?php echo((isset($fee['type']) and $fee['type'] == 'amount') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Amount (Per Ticket)', 'mec'); ?></option>
                                        <option value="amount_per_date" <?php echo ((isset($fee['type']) and $fee['type'] == 'amount_per_date') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Amount (Per Date)', 'mec'); ?></option>
										<option value="amount_per_booking" <?php echo((isset($fee['type']) and $fee['type'] == 'amount_per_booking') ? 'selected="selected"' : ''); ?>><?php esc_html_e('Amount (Per Booking)', 'mec'); ?></option>
									</select>
								</span>
                                    <button class="button mec-dash-remove-btn" type="button" id="mec_remove_fee_button<?php echo esc_attr($i); ?>"
                                            onclick="mec_remove_fee(<?php echo esc_attr($i); ?>);"><?php esc_html_e('Remove', 'mec'); ?></button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            <input type="hidden" id="mec_new_fee_key" value="<?php echo ($i + 1); ?>"/>
            <div class="mec-util-hidden" id="mec_new_fee_raw">
                <div class="mec-box" id="mec_fee_row:i:">
                    <div class="mec-form-row">
                        <input class="mec-col-12" type="text" name="mec[fees][:i:][title]"
                               placeholder="<?php esc_attr_e('Fee Title', 'mec'); ?>"/>
                    </div>
                    <div class="mec-form-row">
						<span class="mec-col-4">
							<input type="text" name="mec[fees][:i:][amount]"
                                   placeholder="<?php esc_attr_e('Amount', 'mec'); ?>" value="0" />
							<span class="mec-tooltip">
								<div class="box top">
									<h5 class="title"><?php esc_html_e('Amount', 'mec'); ?></h5>
									<div class="content"><p><?php esc_attr_e('Fee amount, considered as fixed amount if you set the type to amount otherwise considered as percentage', 'mec'); ?>
                                            <a href="https://webnus.net/dox/modern-events-calendar/tickets-and-taxes-fees/"
                                               target="_blank"><?php esc_html_e('Read More', 'mec'); ?></a></p></div>
								</div>
								<i title="" class="dashicons-before dashicons-editor-help"></i>
							</span>
						</span>
                        <span class="mec-col-4">
							<select name="mec[fees][:i:][type]">
								<option value="percent"><?php esc_html_e('Percent', 'mec'); ?></option>
								<option value="amount"><?php esc_html_e('Amount (Per Ticket)', 'mec'); ?></option>
								<option value="amount_per_date"><?php esc_html_e('Amount (Per Date)', 'mec'); ?></option>
								<option value="amount_per_booking"><?php esc_html_e('Amount (Per Booking)', 'mec'); ?></option>
							</select>
						</span>
                        <button class="button mec_remove_fee_button mec-dash-remove-btn" type="button" id="mec_remove_fee_button:i:"
                                onclick="mec_remove_fee(:i:);"><?php esc_html_e('Remove', 'mec'); ?></button>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Return booking form html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function booking_form( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        do_action('mec_events_meta_box_regform_start', $post);

        $global_inheritance = get_post_meta($post->ID, 'mec_reg_fields_global_inheritance', true);
        if(trim($global_inheritance) == '') $global_inheritance = 1;

        $reg_fields = get_post_meta($post->ID, 'mec_reg_fields', true);
        $global_reg_fields = \MEC\Base::get_main()->get_reg_fields();

        if((is_array($reg_fields) and !count($reg_fields)) or (!is_array($reg_fields) and trim($reg_fields) == '')) $reg_fields = $global_reg_fields;
        if(!is_array($reg_fields)) $reg_fields = [];

        $bfixed_fields = get_post_meta($post->ID, 'mec_bfixed_fields', true);
        $global_bfixed_fields = \MEC\Base::get_main()->get_bfixed_fields();

        if((is_array($bfixed_fields) and !count($bfixed_fields)) or (!is_array($bfixed_fields) and trim($bfixed_fields) == '')) $bfixed_fields = $global_bfixed_fields;
        if(!is_array($bfixed_fields)) $bfixed_fields = [];

        $mec_name = false;
        $mec_email = false;

        foreach($reg_fields as $field)
        {
            if(isset($field['type']))
            {
                if($field['type'] == 'mec_email') $mec_email = true;
                if($field['type'] == 'name') $mec_name = true;
            }
            else break;
        }

        if(!$mec_name)
        {
            array_unshift($reg_fields, array(
                'mandatory' => '0',
                'type' => 'name',
                'label' => esc_html__('Name', 'mec'),
            ));
        }

        if(!$mec_email)
        {
            array_unshift($reg_fields, array(
                'mandatory' => '0',
                'type' => 'mec_email',
                'label' => esc_html__('Email', 'mec'),
            ));
        }
        ?>
        <div class="mec-meta-box-fields mec-booking-tab-content mec-fes-reg-form" id="mec-reg-fields">
            <h4 class="mec-meta-box-header"><?php esc_html_e('Booking Form', 'mec'); ?></h4>

            <?php if($post->ID != \MEC\Base::get_main()->get_original_event($post->ID)) : ?>
            <p class="warning-msg"><?php esc_html_e("You're translating an event so MEC will use the original event for booking form. You can only translate the field name and options. Please define exact fields that you defined in the original event here.", 'mec'); ?></p>
            <?php endif; ?>

            <div id="mec_meta_box_reg_fields_form">
                <div class="mec-form-row">
                    <label class="label-checkbox reg_fields_global_inheritance_label">
                        <input type="hidden" name="mec[reg_fields_global_inheritance]" value="0"/>
                        <input onchange="jQuery('#mec_regform_container_toggle').toggle();" value="1" type="checkbox"
                               name="mec[reg_fields_global_inheritance]"
                            <?php
                            if ($global_inheritance) {
                                echo 'checked="checked"';
                            }
                            ?>
                        /><?php esc_html_e('Inherit from global options', 'mec'); ?>
                    </label>
                </div>
                <?php do_action('mec_meta_box_reg_fields_form', $post->ID); ?>
                <div id="mec_regform_container_toggle" class="
				<?php
                if ($global_inheritance) {
                    echo 'mec-util-hidden';
                }
                ?>">

                    <div class="mec-booking-per-attendee-fields">
                        <h5 class="mec-form-subtitle"><?php esc_html_e('Per Attendee Fields', 'mec'); ?></h5>
                        <?php /** Don't remove this hidden field **/ ?>
                        <input type="hidden" name="mec[reg_fields]" value=""/>

                        <ul id="mec_reg_form_fields">
                            <?php
                            $i = 0;
                            foreach($reg_fields as $key => $reg_field)
                            {
                                if(!is_numeric($key)) continue;

                                $i = max($i, $key);

                                if($reg_field['type'] == 'text') echo \MEC_kses::form(\MEC\Base::get_main()->field_text($key, $reg_field));
                                elseif($reg_field['type'] == 'mec_email') echo \MEC_kses::form(\MEC\Base::get_main()->field_mec_email($key, $reg_field));
                                elseif($reg_field['type'] == 'name') echo \MEC_kses::form(\MEC\Base::get_main()->field_name($key, $reg_field));
                                elseif($reg_field['type'] == 'email') echo \MEC_kses::form(\MEC\Base::get_main()->field_email($key, $reg_field));
                                elseif($reg_field['type'] == 'date') echo \MEC_kses::form(\MEC\Base::get_main()->field_date($key, $reg_field));
                                elseif($reg_field['type'] == 'file') echo \MEC_kses::form(\MEC\Base::get_main()->field_file($key, $reg_field));
                                elseif($reg_field['type'] == 'tel') echo \MEC_kses::form(\MEC\Base::get_main()->field_tel($key, $reg_field));
                                elseif($reg_field['type'] == 'textarea') echo \MEC_kses::form(\MEC\Base::get_main()->field_textarea($key, $reg_field));
                                elseif($reg_field['type'] == 'p') echo \MEC_kses::form(\MEC\Base::get_main()->field_p($key, $reg_field));
                                elseif($reg_field['type'] == 'checkbox') echo \MEC_kses::form(\MEC\Base::get_main()->field_checkbox($key, $reg_field));
                                elseif($reg_field['type'] == 'radio') echo \MEC_kses::form(\MEC\Base::get_main()->field_radio($key, $reg_field));
                                elseif($reg_field['type'] == 'select') echo \MEC_kses::form(\MEC\Base::get_main()->field_select($key, $reg_field));
                                elseif($reg_field['type'] == 'agreement') echo \MEC_kses::form(\MEC\Base::get_main()->field_agreement($key, $reg_field));
                            }
                            ?>
                        </ul>
                        <div id="mec_reg_form_field_types">
                            <button type="button" class="button red" data-type="name"><?php esc_html_e('MEC Name', 'mec'); ?></button>
                            <button type="button" class="button red" data-type="mec_email"><?php esc_html_e('MEC Email', 'mec'); ?></button>
                            <button type="button" class="button" data-type="text"><?php esc_html_e('Text', 'mec'); ?></button>
                            <button type="button" class="button" data-type="email"><?php esc_html_e('Email', 'mec'); ?></button>
                            <button type="button" class="button" data-type="date"><?php esc_html_e('Date', 'mec'); ?></button>
                            <button type="button" class="button" data-type="tel"><?php esc_html_e('Tel', 'mec'); ?></button>
                            <button type="button" class="button" data-type="file"><?php esc_html_e('File', 'mec'); ?></button>
                            <button type="button" class="button" data-type="textarea"><?php esc_html_e('Textarea', 'mec'); ?></button>
                            <button type="button" class="button" data-type="checkbox"><?php esc_html_e('Checkboxes', 'mec'); ?></button>
                            <button type="button" class="button" data-type="radio"><?php esc_html_e('Radio Buttons', 'mec'); ?></button>
                            <button type="button" class="button" data-type="select"><?php esc_html_e('Dropdown', 'mec'); ?></button>
                            <button type="button" class="button" data-type="agreement"><?php esc_html_e('Agreement', 'mec'); ?></button>
                            <button type="button" class="button" data-type="p"><?php esc_html_e('Paragraph', 'mec'); ?></button>
                        </div>
                        <input type="hidden" id="mec_new_reg_field_key" value="<?php echo ($i + 1); ?>"/>
                        <div class="mec-util-hidden">
                            <div id="mec_reg_field_text">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_text(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_email">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_email(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_mec_email">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_mec_email(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_name">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_name(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_tel">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_tel(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_date">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_date(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_file">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_file(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_textarea">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_textarea(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_checkbox">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_checkbox(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_radio">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_radio(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_select">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_select(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_agreement">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_agreement(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_p">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_p(':i:')); ?>
                            </div>
                            <div id="mec_reg_field_option">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_option(':fi:', ':i:')); ?>
                            </div>
                        </div>
                    </div>
                    <div class="mec-booking-fixed-fields">
                        <h5 class="mec-form-subtitle"><?php esc_html_e('Fixed Fields', 'mec'); ?></h5>
                        <div class="mec-form-row" id="mec_bfixed_form_container">
                            <?php /** Don't remove this hidden field **/ ?>
                            <input type="hidden" name="mec[bfixed_fields]" value="" />

                            <ul id="mec_bfixed_form_fields">
                                <?php
                                $b = 0;
                                foreach($bfixed_fields as $key => $bfixed_field)
                                {
                                    if(!is_numeric($key)) continue;
                                    if(!is_array($bfixed_field)) continue;
                                    $b = max($b, $key);

                                    if($bfixed_field['type'] == 'text') echo \MEC_kses::form(\MEC\Base::get_main()->field_text($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'name') echo \MEC_kses::form(\MEC\Base::get_main()->field_name($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'mec_email') echo \MEC_kses::form(\MEC\Base::get_main()->field_mec_email($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'email') echo \MEC_kses::form(\MEC\Base::get_main()->field_email($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'date') echo \MEC_kses::form(\MEC\Base::get_main()->field_date($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'file') echo \MEC_kses::form(\MEC\Base::get_main()->field_file($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'tel') echo \MEC_kses::form(\MEC\Base::get_main()->field_tel($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'textarea') echo \MEC_kses::form(\MEC\Base::get_main()->field_textarea($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'p') echo \MEC_kses::form(\MEC\Base::get_main()->field_p($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'checkbox') echo \MEC_kses::form(\MEC\Base::get_main()->field_checkbox($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'radio') echo \MEC_kses::form(\MEC\Base::get_main()->field_radio($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'select') echo \MEC_kses::form(\MEC\Base::get_main()->field_select($key, $bfixed_field, 'bfixed'));
                                    elseif($bfixed_field['type'] == 'agreement') echo \MEC_kses::form(\MEC\Base::get_main()->field_agreement($key, $bfixed_field, 'bfixed'));
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
                        </div>
                        <input type="hidden" id="mec_new_bfixed_field_key" value="<?php echo ($b + 1); ?>" />
                        <div class="mec-util-hidden">
                            <div id="mec_bfixed_field_text">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_text(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_email">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_email(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_tel">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_tel(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_date">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_date(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_textarea">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_textarea(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_checkbox">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_checkbox(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_radio">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_radio(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_select">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_select(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_agreement">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_agreement(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_p">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_p(':i:', array(), 'bfixed')); ?>
                            </div>
                            <div id="mec_bfixed_field_option">
                                <?php echo \MEC_kses::form(\MEC\Base::get_main()->field_option(':fi:', ':i:', array(), 'bfixed')); ?>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
        <?php
        do_action('mec_events_meta_box_regform_end', $post->ID);
    }

    /**
     * Return ticket variations html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function ticket_variations( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $settings = \MEC\Settings\Settings::getInstance()->get_settings();

        $global_inheritance = get_post_meta($post->ID, 'mec_ticket_variations_global_inheritance', true);
        if(trim($global_inheritance) == '') $global_inheritance = 1;

        $ticket_variations = get_post_meta($post->ID, 'mec_ticket_variations', true);
        $global_variations = $settings['ticket_variations'] ?? [];

        if(!is_array($ticket_variations) and trim($ticket_variations) == '') $ticket_variations = $global_variations;
        if(!is_array($ticket_variations)) $ticket_variations = [];

        // Ticket Variations Object
        $TicketVariations = \MEC\Base::get_main()->getTicketVariations();
        ?>
        <div class="mec-meta-box-fields mec-booking-tab-content mec-fes-ticket-variations" id="mec-ticket-variations">
            <h4 class="mec-meta-box-header"><?php esc_html_e('Ticket Variations / Options', 'mec'); ?></h4>
            <div id="mec_meta_box_ticket_variations_form">
                <div class="mec-form-row">
                    <label class="ticket_variations_global_inheritance_label">
                        <input type="hidden" name="mec[ticket_variations_global_inheritance]" value="0"/>
                        <input onchange="jQuery('#mec_taxes_ticket_variations_container_toggle').toggle();" value="1" type="checkbox" name="mec[ticket_variations_global_inheritance]" <?php echo ($global_inheritance ? 'checked="checked"' : ''); ?>> <?php esc_html_e('Inherit from global options', 'mec'); ?>
                    </label>
                </div>
                <div id="mec_taxes_ticket_variations_container_toggle" class="<?php echo ($global_inheritance ? 'mec-util-hidden' : ''); ?>">
                    <div class="mec-form-row">
                        <button class="button" type="button" id="mec_add_ticket_variation_button"><?php esc_html_e('Add', 'mec'); ?></button>
                    </div>
                    <div id="mec_ticket_variations_list">
                        <?php
                        $i = 0;
                        foreach($ticket_variations as $key => $ticket_variation)
                        {
                            if(!is_numeric($key)) continue;

                            $i = max($i, $key);
                            $TicketVariations->item([
                                'i' => $i,
                                'value' => $ticket_variation,
                            ]);
                        }
                        ?>
                    </div>
                </div>
            </div>
            <input type="hidden" id="mec_new_ticket_variation_key" value="<?php echo ($i + 1); ?>"/>
            <div class="mec-util-hidden" id="mec_new_ticket_variation_raw">
                <?php
                    $TicketVariations->item([
                        'i' => ':i:',
                        'value' => [],
                    ]);
                ?>
            </div>
        </div>
        <?php
    }

    /**
     * Return attendees html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function attendees( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $draft = !(isset($post->post_status) and $post->post_status != 'auto-draft');
        if($draft) return;

        $limit = 100;
        $now = current_time('timestamp');
        $_6months_ago = strtotime('-6 Months', $now);

        $occ = new \MEC_feature_occurrences();
        $occurrences = $occ->get_dates($post->ID, $now, $limit);

        $date_format = get_option('date_format');
        $time_format = get_option('time_format');
        $datetime_format = $date_format.' '.$time_format;

        $db = \MEC\Base::get_main()->getDB();
        $booking_dates = $db->select("SELECT `date` FROM `#__mec_bookings` WHERE `event_id`='".esc_sql($post->ID)."' GROUP BY `date` ORDER BY `date`", 'loadColumn');
        $booking_dates_for_manage = $db->select("SELECT `date` FROM `#__mec_bookings` WHERE `event_id`='".esc_sql($post->ID)."' AND `verified`=1 GROUP BY `date` ORDER BY `date`", 'loadColumn');

        do_action('mec_events_meta_box_attendees_start', $post);
        ?>
        <div class="mec-meta-box-fields mec-booking-tab-content mec-fes-attendees" id="mec_meta_box_booking_options_form_attendees">
            <h4 class="mec-meta-box-header"><?php esc_html_e('Attendees', 'mec'); ?></h4>
            <div class="mec-attendees-wrapper mec-booking-attendees-wrapper">
                <div>
                    <select id="mec_att_occurrences_dropdown" title="<?php esc_attr_e('Occurrence', 'mec'); ?>">
                        <option class="mec-load-occurrences" value="<?php echo esc_attr($_6months_ago.':'.$_6months_ago); ?>"><?php esc_html_e('Previous Occurrences', 'mec'); ?></option>
                        <?php $i = 1; foreach($occurrences as $occurrence): ?>
                        <option value="<?php echo esc_attr($occurrence->tstart.':'.$occurrence->tend); ?>" <?php echo ($i === 1 ? 'selected="selected"' : ''); ?>><?php echo esc_html(date_i18n($datetime_format, $occurrence->tstart)); ?></option>
                        <?php $i++; endforeach; ?>
                        <?php if(count($occurrences) >= $limit and isset($occurrence)): ?>
                        <option class="mec-load-occurrences" value="<?php echo esc_attr($occurrence->tstart.':'.$occurrence->tend); ?>"><?php esc_html_e('Next Occurrences', 'mec'); ?></option>
                        <?php endif; ?>
                    </select>
                </div>
                <div class="mec-attendees-list">
                </div>
            </div>

            <?php if(count($booking_dates)): ?>
                <?php
                    $from_options = '';
                    foreach($booking_dates as $booking_date) $from_options .= '<option value="'.esc_attr(strtotime($booking_date)).'">'.esc_html(date_i18n($datetime_format, strtotime($booking_date))).'</option>';

                    $from = '<select id="mec_move_bookings_booking_dates_dropdown" title="'.esc_attr__('Occurrence', 'mec').'">
                        '.$from_options.'
                    </select>';

                    $to_options = '';
                    foreach($occurrences as $occurrence) $to_options .= '<option value="'.esc_attr($occurrence->tstart).'">'.esc_html(date_i18n($datetime_format, $occurrence->tstart)).'</option>';

                    $to = '<select id="mec_move_bookings_occurrences_dropdown" title="'.esc_attr__('Occurrence', 'mec').'">
                        '.$to_options.'
                    </select>';
                ?>
            <h4 class="mec-meta-box-header"><?php esc_html_e('Move Bookings', 'mec'); ?></h4>
            <div class="mec-move-bookings-wrapper mec-booking-move-bookings-wrapper">
                <div class="mec-form-row mec-label">
                    <?php echo sprintf(esc_html__('Move bookings from %s to %s', 'mec'), $from, $to); ?>
                    <button id="mec_move_bookings_button" type="button" class="button button-secondary"><?php esc_html_e('Move', 'mec'); ?></button>
                </div>
                <div id="mec_move_bookings_message"></div>
            </div>
            <?php endif; ?>
            <?php if(count($booking_dates_for_manage)): ?>
                <?php
                    $manage_options = '';
                    foreach($booking_dates_for_manage as $booking_date_for_manage) $manage_options .= '<option value="'.esc_attr(strtotime($booking_date_for_manage)).'">'.esc_html(date_i18n($datetime_format, strtotime($booking_date_for_manage))).'</option>';

                    $dates_manage = '<select id="mec_manage_bookings_booking_dates_dropdown" title="'.esc_attr__('Occurrence', 'mec').'">
                        '.$manage_options.'
                    </select>';
                ?>
            <h4 class="mec-meta-box-header"><?php esc_html_e('Manage Bookings', 'mec'); ?></h4>
            <div class="mec-manage-bookings-wrapper mec-booking-manage-bookings-wrapper">
                <div class="mec-form-row mec-label">
                    <?php echo $dates_manage; ?>
                    <select id="mec_manage_bookings_booking_mode_dropdown" title="<?php esc_attr_e('Action', 'mec'); ?>">
                        <option value="">-----</option>
                        <option value="cancel"><?php esc_html_e('Cancel', 'mec'); ?></option>
                        <option value="refund"><?php esc_html_e('Cancel & Refund', 'mec'); ?></option>
                    </select>
                    <button id="mec_manage_bookings_button" type="button" class="button button-secondary"><?php esc_html_e('Send', 'mec'); ?></button>
                </div>
                <div id="mec_manage_bookings_message"></div>
            </div>
            <?php endif; ?>
        </div>
        <script>
        jQuery(document).ready(function()
        {
            mec_attendees_trigger_load_dates();
            setTimeout(function()
            {
                jQuery('#mec_att_occurrences_dropdown').trigger('change');
            }, 500);

            jQuery('#mec_move_bookings_button').on('click', function()
            {
                let $message = jQuery('#mec_move_bookings_message');
                let from = jQuery('#mec_move_bookings_booking_dates_dropdown').val();
                let to = jQuery('#mec_move_bookings_occurrences_dropdown').val();

                // Empty Message
                $message.html('');

                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: "action=mec_move_bookings&id=<?php echo esc_js($post->ID); ?>&_wpnonce=<?php echo wp_create_nonce('mec_move_bookings'); ?>&from="+from+"&to="+to,
                    dataType: "json"
                })
                .done(function(response)
                {
                    // Display Message
                    if(response.success) $message.html(response.message);
                });
            });

            jQuery('#mec_manage_bookings_button').on('click', function()
            {
                let $message = jQuery('#mec_manage_bookings_message');
                let mode = jQuery('#mec_manage_bookings_booking_mode_dropdown').val();
                let date = jQuery('#mec_manage_bookings_booking_dates_dropdown').val();

                // No Action!
                if(!mode)
                {
                    $message.html("<p class='warning-msg'><?php echo esc_js(__("Please select an action", 'mec')); ?></p>");
                    return;
                }

                // Empty Message
                $message.html('');

                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: "action=mec_manage_bookings&id=<?php echo esc_js($post->ID); ?>&_wpnonce=<?php echo wp_create_nonce('mec_manage_bookings'); ?>&date="+date+"&mode="+mode,
                    dataType: "json"
                })
                .done(function(response)
                {
                    // Display Message
                    if(response.success) $message.html(response.message);
                });
            });
        });

        function mec_attendees_trigger_load_dates()
        {
            jQuery('#mec_att_occurrences_dropdown').off('change').on('change', function()
            {
                var $dropdown = jQuery(this);
                var value = $dropdown.val();
                var $attendees = jQuery('.mec-booking-attendees-wrapper .mec-attendees-list');

                // Load Dates
                if($dropdown.find(jQuery('option[value="'+value+'"]')).hasClass('mec-load-occurrences'))
                {
                    // Disable the Form
                    $dropdown.attr('disabled', 'disabled');

                    jQuery.ajax(
                    {
                        url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                        type: "POST",
                        data: "action=mec_occurrences_dropdown&id=<?php echo esc_js($post->ID); ?>&_wpnonce=<?php echo wp_create_nonce('mec_occurrences_dropdown'); ?>&date="+value,
                        dataType: "json"
                    })
                    .done(function(response)
                    {
                        if(response.success) $dropdown.html(response.html);

                        // New Trigger
                        mec_attendees_trigger_load_dates();

                        setTimeout(function()
                        {
                            jQuery('#mec_att_occurrences_dropdown').trigger('change');
                        }, 500);

                        // Enable the Form
                        $dropdown.removeAttr('disabled');
                    });
                }
                // Load Attendees
                else
                {
                    // Disable the Form
                    $dropdown.attr('disabled', 'disabled');

                    jQuery.ajax(
                    {
                        url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                        type: "POST",
                        data: "action=mec_event_bookings&id=<?php echo esc_js($post->ID); ?>&occurrence="+value+"&backend=<?php echo (is_admin() ? 1 : 0); ?>",
                        dataType: "json"
                    })
                    .done(function(response)
                    {
                        // Display Results
                        if(response.html) $attendees.html(response.html);

                        // Enable the Form
                        $dropdown.removeAttr('disabled');
                    });
                }
            });
        }
        </script>
        <?php
        do_action('mec_events_meta_box_attendees_end', $post);
    }

    /**
     * Return tickets html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function tickets( $post, $atts = array() ){

        if( !static::booking_demo_check( $post, $atts ) ){

            return;
        }

        $FES = !is_admin();

        // MEC Main
        $main = \MEC\Base::get_main();

        // Settings
        $settings = $main->get_settings();

        $tickets = get_post_meta($post->ID, 'mec_tickets', true);
        if(!is_array($tickets)) $tickets = [];

        // Global Tickets
        $global_tickets = isset($settings['default_tickets_status']) && $settings['default_tickets_status'];
        $global_tickets_applied = (int) get_post_meta($post->ID, 'mec_global_tickets_applied', true);

        // Global Tickets
        if($global_tickets && !count($tickets) && ($post->ID == -1 || get_post_status($post->ID) === 'auto-draft' || $global_tickets_applied == 0))
        {
            $tickets = is_array($settings['tickets']) ? $settings['tickets'] : [];
        }

        // Tickets
        $ticketBuilder = $main->getTickets();
        ?>
        <div class="mec-meta-box-fields mec-booking-tab-content mec-fes-tickets" id="mec-tickets">

            <?php if(!$FES): ?>
            <div class="mec-backend-tab-wrap mec-basvanced-toggle" data-for="#mec-tickets" data-method="addition">
                <div class="mec-backend-tab">
                    <div class="mec-backend-tab-item mec-b-active-tab"><?php esc_html_e('Basic', 'mec'); ?></div>
                    <div class="mec-backend-tab-item"><?php esc_html_e('Advanced', 'mec'); ?></div>
                </div>
            </div>
            <?php endif; ?>

            <h4 class="mec-meta-box-header"><?php echo esc_html($main->m('tickets', esc_html__('Tickets', 'mec'))); ?></h4>

            <?php if($post->ID != $main->get_original_event($post->ID)): ?>
            <p class="warning-msg"><?php esc_html_e("You're translating an event so MEC will use the original event for tickets and booking. You can only translate the ticket name and description. Please define exact tickets that you defined in the original event here.", 'mec'); ?></p>
            <?php endif; ?>

            <?php $ticketBuilder->builder([
                'tickets' => $tickets,
                'object_id' => $post->ID,
            ]); ?>
        </div>
        <?php
    }

    /**
     * Return public download file html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function public_download( $post, $atts = array() ){

        // Disable For Guest
        if(!get_current_user_id()) return;

        $file_id = get_post_meta($post->ID, 'mec_public_dl_file', true);
        if(trim($file_id) == '') $file_id = '';

        $file_url = $file_id ? wp_get_attachment_url($file_id) : '';

        $title = get_post_meta($post->ID, 'mec_public_dl_title', true);
        $description = get_post_meta($post->ID, 'mec_public_dl_description', true);
        ?>
        <script>
        jQuery(document).ready(function()
        {
            jQuery("#mec_public_download_module_file_uploader").on('change', function()
            {
                var fd = new FormData();
                fd.append("action", "mec_public_download_module_file_upload");
                fd.append("_wpnonce", "<?php echo wp_create_nonce('mec_public_download_module_file_upload'); ?>");
                fd.append("file", jQuery("#mec_public_download_module_file_uploader").prop("files")[0]);

                jQuery("#mec_public_download_module_file_error").html("").addClass("mec-util-hidden");
                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: fd,
                    dataType: "json",
                    processData: false,
                    contentType: false
                })
                .done(function(response)
                {
                    if(response.success)
                    {
                        jQuery("#mec_public_download_module_file_link").html('<a href="'+response.data.url+'" target="_blank">'+response.data.url+'</a>').removeClass("mec-util-hidden");
                        jQuery("#mec_public_download_module_file").val(response.data.id);
                        jQuery("#mec_public_download_module_file_remove_image_button").removeClass("mec-util-hidden");
                    }
                    else
                    {
                        jQuery("#mec_public_download_module_file_error").html(response.message).removeClass("mec-util-hidden");
                    }

                    // Reset File Input
                    jQuery("#mec_public_download_module_file_uploader").val('');
                });

                return false;
            });

            jQuery("#mec_public_download_module_file_remove_image_button").on('click', function()
            {
                jQuery("#mec_public_download_module_file_link").html('').addClass("mec-util-hidden");
                jQuery("#mec_public_download_module_file").val('');
                jQuery("#mec_public_download_module_file_remove_image_button").addClass("mec-util-hidden");
            });
        });
        </script>
        <div class="mec-meta-box-fields mec-event-tab-content mec-form-row" id="mec-public-download-module-file">
            <h4><?php esc_html_e('Public File to Download', 'mec'); ?></h4>
            <div id="mec_meta_box_downloadable_file_options">
                <input type="hidden" id="mec_public_download_module_file" name="mec[public_download_module_file]" value="<?php echo esc_attr($file_id); ?>">
                <input type="file" id="mec_public_download_module_file_uploader">
                <p class="description"><?php esc_html_e('pdf,zip,png,jpg and gif files are allowed.', 'mec'); ?></p>
                <div id="mec_public_download_module_file_link" class="<?php echo (trim($file_id) ? '' : 'mec-util-hidden'); ?>"><?php echo ($file_id ? '<a href="'.esc_url($file_url).'" target="_blank">'.esc_html($file_url).'</a>' : ''); ?></div>
                <button type="button" id="mec_public_download_module_file_remove_image_button" class="button mec-dash-remove-btn<?php echo (trim($file_id) ? '' : 'mec-util-hidden'); ?>"><?php esc_html_e('Remove File', 'mec'); ?></button>
                <div class="mec-error mec-util-hidden" id="mec_public_download_module_file_error"></div>
            </div>
            <div class="mec-form-row" style="margin-top: 30px;">
                <label for="mec_public_download_module_title" class="mec-col-2"><?php esc_html_e('Title', 'mec'); ?></label>
                <input class="mec-col-5" type="text" id="mec_public_download_module_title" name="mec[public_download_module_title]" value="<?php echo esc_attr($title); ?>">
            </div>
            <div class="mec-form-row">
                <label for="mec_public_download_module_description" class="mec-col-2"><?php esc_html_e('Description', 'mec'); ?></label>
                <textarea class="mec-col-5" id="mec_public_download_module_description" name="mec[public_download_module_description]" rows="5"><?php echo esc_textarea($description); ?></textarea>
            </div>
        </div>
        <?php
    }

    /**
     * Return downloadable file html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function downloadable_file( $post, $atts = array() ){

        // Disable For Guest
        if(!get_current_user_id()) return;

        $file_id = get_post_meta($post->ID, 'mec_dl_file', true);
        if(trim($file_id) == '') $file_id = '';

        $file_url = $file_id ? wp_get_attachment_url($file_id) : '';
        ?>
        <script>
        jQuery(document).ready(function()
        {
            jQuery("#mec_downloadable_file_uploader").on('change', function()
            {
                var fd = new FormData();
                fd.append("action", "mec_downloadable_file_upload");
                fd.append("_wpnonce", "<?php echo wp_create_nonce('mec_downloadable_file_upload'); ?>");
                fd.append("file", jQuery("#mec_downloadable_file_uploader").prop("files")[0]);

                jQuery("#mec_downloadable_file_error").html("").addClass("mec-util-hidden");
                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: fd,
                    dataType: "json",
                    processData: false,
                    contentType: false
                })
                .done(function(response)
                {
                    if(response.success)
                    {
                        jQuery("#mec_downloadable_file_link").html('<a href="'+response.data.url+'" target="_blank">'+response.data.url+'</a>').removeClass("mec-util-hidden");
                        jQuery("#mec_downloadable_file").val(response.data.id);
                        jQuery("#mec_downloadable_file_remove_image_button").removeClass("mec-util-hidden");
                    }
                    else
                    {
                        jQuery("#mec_downloadable_file_error").html(response.message).removeClass("mec-util-hidden");
                    }

                    // Reset File Input
                    jQuery("#mec_downloadable_file_uploader").val('');
                })
                .fail(function()
                {
                    jQuery("#mec_downloadable_file_error").html("<?php echo esc_js(__('An unknown error occurred during uploading the file.', 'mec')); ?>").removeClass("mec-util-hidden");
                });

                return false;
            });

            jQuery("#mec_downloadable_file_remove_image_button").on('click', function()
            {
                jQuery("#mec_downloadable_file_link").html('').addClass("mec-util-hidden");
                jQuery("#mec_downloadable_file").val('');
                jQuery("#mec_downloadable_file_remove_image_button").addClass("mec-util-hidden");
            });
        });
        </script>
        <div class="mec-meta-box-fields mec-booking-tab-content " id="mec-downloadable-file">
            <h4><?php esc_html_e('Downloadable File', 'mec'); ?></h4>
            <div id="mec_meta_box_downloadable_file_options">
                <input type="hidden" id="mec_downloadable_file" name="mec[downloadable_file]" value="<?php echo esc_attr($file_id); ?>">
                <input type="file" id="mec_downloadable_file_uploader">
                <p class="description"><?php esc_html_e('pdf,zip,png,jpg and gif files are allowed.', 'mec'); ?></p>
                <div id="mec_downloadable_file_link" class="<?php echo (trim($file_id) ? '' : 'mec-util-hidden'); ?>"><?php echo ($file_id ? '<a href="'.esc_url($file_url).'" target="_blank">'.esc_html($file_url).'</a>' : ''); ?></div>
                <button type="button" id="mec_downloadable_file_remove_image_button" class="button mec-dash-remove-btn <?php echo (trim($file_id) ? '' : 'mec-util-hidden'); ?>"><?php esc_html_e('Remove File', 'mec'); ?></button>
                <div class="mec-error mec-util-hidden" id="mec_downloadable_file_error"></div>
            </div>
        </div>
        <?php
    }

    /**
     * Return occurrences html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function occurrences( $post, $atts = array() ){

        $occurencesClass = new \MEC_feature_occurrences();

        $draft = (isset($post->post_status) and $post->post_status != 'auto-draft') ? false : true;
        $repeat_status = get_post_meta($post->ID, 'mec_repeat_status', true);

        if($draft or !$repeat_status) return;

        $limit = 100;
        $now = current_time('timestamp');
        $_6months_ago = strtotime('-6 Months', $now);

        $occurrences = $occurencesClass->get_dates($post->ID, $now, $limit);

        $date_format = get_option('date_format');
        $time_format = get_option('time_format');
        $datetime_format = $date_format.' '.$time_format;

        $all_occurrences = $occurencesClass->get_all_occurrences($post->ID, strtotime('-1 Month'));
        ?>
        <div class="mec-meta-box-fields mec-event-tab-content" id="mec-occurrences">
            <h4><?php esc_html_e('Occurrences', 'mec'); ?></h4>
            <div class="mec-occurrences-wrapper">
                <div>
                    <select id="mec_occurrences_dropdown" title="<?php esc_attr_e('Occurrence', 'mec'); ?>">
                        <option class="mec-load-occurrences" value="<?php echo esc_attr($_6months_ago.':'.$_6months_ago); ?>"><?php esc_html_e('Previous Occurrences', 'mec'); ?></option>
                        <?php $i = 1; foreach($occurrences as $occurrence): ?>
                        <option value="<?php echo esc_attr($occurrence->tstart.':'.$occurrence->tend); ?>" <?php echo ($i === 1 ? 'selected="selected"' : ''); ?>><?php echo esc_html(date_i18n($datetime_format, $occurrence->tstart)); ?></option>
                        <?php $i++; endforeach; ?>
                        <?php if(count($occurrences) >= $limit and isset($occurrence)): ?>
                        <option class="mec-load-occurrences" value="<?php echo esc_attr($occurrence->tstart.':'.$occurrence->tend); ?>"><?php esc_html_e('Next Occurrences', 'mec'); ?></option>
                        <?php endif; ?>
                    </select>
                    <button id="mec_occurrences_add" type="button" class="button mec-button-new"><?php esc_attr_e('Add', 'mec'); ?></button>
                </div>
                <ul class="mec-occurrences-list">
                    <?php foreach($all_occurrences as $all_occurrence) echo \MEC_kses::full($occurencesClass->get_occurrence_form($all_occurrence['id'])); ?>
                </ul>
            </div>
        </div>
        <script>
        jQuery(document).ready(function()
        {
            mec_trigger_load_dates();
            mec_trigger_add_occurrence();
            mec_trigger_delete_occurrence();
            mec_trigger_occurrence_schema();
            mec_bookings_after_occurrence_cancel_listener();
        });

        function mec_trigger_load_dates()
        {
            jQuery('#mec_occurrences_dropdown').off('change').on('change', function()
            {
                var $dropdown = jQuery(this);
                var value = $dropdown.val();

                if(!$dropdown.find(jQuery('option[value="'+value+'"]')).hasClass('mec-load-occurrences')) return;

                var $button = jQuery('#mec_occurrences_add');

                // Disable the Form
                $dropdown.attr('disabled', 'disabled');
                $button.attr('disabled', 'disabled');

                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: "action=mec_occurrences_dropdown&id=<?php echo esc_js($post->ID); ?>&_wpnonce=<?php echo wp_create_nonce('mec_occurrences_dropdown'); ?>&date="+value,
                    dataType: "json"
                })
                .done(function(response)
                {
                    if(response.success) $dropdown.html(response.html);

                    // New Trigger
                    mec_trigger_load_dates();

                    // Enable the Form
                    $dropdown.removeAttr('disabled');
                    $button.removeAttr('disabled');
                });
            });
        }

        function mec_trigger_add_occurrence()
        {
            jQuery('#mec_occurrences_add').off('click').on('click', function()
            {
                var $dropdown = jQuery('#mec_occurrences_dropdown');
                var $button = jQuery(this);
                var $list = jQuery('.mec-occurrences-list');

                var value = $dropdown.val();

                // Disable the Form
                $dropdown.attr('disabled', 'disabled');
                $button.attr('disabled', 'disabled');

                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: "action=mec_occurrences_add&id=<?php echo esc_js($post->ID); ?>&_wpnonce=<?php echo wp_create_nonce('mec_occurrences_add'); ?>&date="+value,
                    dataType: "json"
                })
                .done(function(response)
                {
                    if(response.success)
                    {
                        // Prepend
                        $list.prepend(response.html);

                        mec_trigger_delete_occurrence();
                        mec_trigger_occurrence_schema();
                        mec_hourly_schedule_add_day_listener();
                        mec_bookings_after_occurrence_cancel_listener();
                    }

                    // Enable the Form
                    $dropdown.removeAttr('disabled');
                    $button.removeAttr('disabled');
                });
            });
        }

        function mec_trigger_delete_occurrence()
        {
            jQuery('.mec-occurrences-delete-button').off('click').on('click', function()
            {
                var $button = jQuery(this);
                var id = $button.data('id');

                var $occurrence = jQuery('#mec_occurrences_'+id);

                // Loading Style
                $occurrence.addClass('mec-loading');

                jQuery.ajax(
                {
                    url: "<?php echo admin_url('admin-ajax.php', NULL); ?>",
                    type: "POST",
                    data: "action=mec_occurrences_delete&id="+id+"&_wpnonce=<?php echo wp_create_nonce('mec_occurrences_delete'); ?>",
                    dataType: "json"
                })
                .done(function(response)
                {
                    if(response.success)
                    {
                        // Remove the item
                        $occurrence.remove();
                    }
                    else
                    {
                        // Loading Style
                        $occurrence.removeClass('mec-loading');
                    }
                });
            });
        }

        function mec_trigger_occurrence_schema()
        {
            jQuery('#mec-occurrences input.mec-schema-event-status').off('change').on('change', function()
            {
                var id = jQuery(this).data('id');
                var value = jQuery(this).val();

                if(value === 'EventMovedOnline')
                {
                    jQuery('#mec_occurrences_'+id+'_moved_online_link_wrapper').show();
                    jQuery('#mec_occurrences_'+id+'_cancelled_reason_wrapper').hide();
                }
                else if(value === 'EventCancelled')
                {
                    jQuery('#mec_occurrences_'+id+'_moved_online_link_wrapper').hide();
                    jQuery('#mec_occurrences_'+id+'_cancelled_reason_wrapper').show();
                }
                else
                {
                    jQuery('#mec_occurrences_'+id+'_moved_online_link_wrapper').hide();
                    jQuery('#mec_occurrences_'+id+'_cancelled_reason_wrapper').hide();
                }
            });
        }
        </script>
        <?php
    }

    /**
     * Return info html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function info( $post, $atts = array() ){

        $imported_from_google = get_post_meta( $post->ID, 'mec_imported_from_google', true );
        if( $imported_from_google ): ?>
            <p class="info-msg"><?php esc_html_e("This event is imported from Google calendar so if you modify it would overwrite in the next import from Google.", 'mec'); ?></p>
        <?php endif;
    }

    /**
     * Return actions html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function actions( $post, $atts = array() ){


        if( !is_user_logged_in() ){

            return;
        }

        $url = $atts['url'] ?? '';

        ?>
        <div class="mec-fes-form-top-actions">
            <?php do_action('mec_fes_form_top_actions'); ?>
            <a class="mec-fes-form-back-to" href="<?php echo esc_url( $url ); ?>"><?php echo esc_html__('Go back to events list', 'mec'); ?></a>

            <?php $status = \MEC\Base::get_main()->get_event_label_status(get_post_status($post->ID)); ?>
            <?php if(trim($status['label']) != "Empty"): ?>
                <span class="post-status <?php echo esc_attr($status['status_class']); ?>"><?php echo esc_html($status['label']);  ?></span>
            <?php endif; ?>
        </div>
        <?php

    }

    /**
     * Return recaptcha html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function recaptcha( $post, $atts = array() ){

        $is_edit_mode = $atts['is_edit_mode'] ?? false;
        $status = \MEC\Base::get_main()->getCaptcha()->status('fes');

        if( $is_edit_mode && !$status )
        {
            echo '<div class="mec-content-notification">
                <p>'
                    .'<span>'
                        . esc_html__('Captcha is not enabled.', 'mec')
                    .'</span>'
                    .'<a href="#" target="_blank">' . esc_html__('How to set', 'mec') . ' </a>'
                .'</p>'
            .'</div>';
        }

        if($status) echo \MEC\Base::get_main()->getCaptcha()->field();
    }

    /**
     * Return submit button html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function submit_button( $post, $atts = array() ){

        ?>
        <button class="mec-fes-sub-button" type="submit"><?php esc_html_e('Submit Event', 'mec'); ?></button>
        <div class="mec-util-hidden">
            <input type="hidden" name="mec[post_id]" value="<?php echo esc_attr($post->ID); ?>" id="mec_fes_post_id" class="mec-fes-post-id" />
            <input type="hidden" name="action" value="mec_fes_form" />
            <?php wp_nonce_field('mec_fes_form'); ?>
            <?php wp_nonce_field('mec_event_data', 'mec_event_nonce'); ?>
        </div>

        <?php
    }

    /**
     * Return virtual html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function virtual( $post, $atts = array() ){

        ?>
        <!-- Virtual Section -->
        <?php

        if($post->ID != -1 && $post == "") {

            $post = get_post_meta($post->ID, 'meta_box_virtual', true);
        }

        do_action('mec_virtual_event_form', $post);
    }

    /**
     * Return zoom html field
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function zoom( $post, $atts = array() ){

        ?>
        <!-- Zoom Event Section -->
        <?php

        if($post->ID != -1 && $post == "") {

            $post = get_post_meta($post->ID, 'meta_box_virtual', true);
        }

        do_action('mec_zoom_event_form', $post);
    }

    /**
     * Return other html fields
     *
     * @param WP_Post $post
     * @param array $atts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function other_fields( $post, $atts = array() ){

        do_action('mec_fes_metabox_details', $post);
    }

    /**
     * Register style and scripts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function register_style_and_scripts(){

        wp_register_script( 'mec-fes-form-builder', plugin_dir_url( __FILE__ ) . 'scripts.js', array( 'jquery' ), MEC_VERSION );
    }

    /**
     * Enqueue style and scripts
     *
     * @since 1.0.0
     *
     * @return void
     */
    public static function enqueue(){

        static::register_style_and_scripts();

        wp_enqueue_script( 'mec-fes-form-builder' );

        do_action( 'mec_fes_form_enqueue_scripts' );
    }

    /**
     * Return html
     *
     * @return string
     */
    public function output( $event ){

        $html = '';

        return $html;
    }
}