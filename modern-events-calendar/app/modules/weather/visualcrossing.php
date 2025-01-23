<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_main $this */
/** @var stdClass $event */
/** @var string $visual_crossing */
/** @var float $lat */
/** @var float $lng */

$occurrence = isset($_GET['occurrence']) ? sanitize_text_field($_GET['occurrence']) : '';
$date = (trim($occurrence) ? $occurrence : $event->date['start']['date']).' '.sprintf("%02d", $event->date['start']['hour']).':'.sprintf("%02d", $event->date['start']['minutes']).' '.$event->date['start']['ampm'];

$weather = $this->get_weather_visualcrossing($visual_crossing, $lat, $lng, $date);
$imperial = isset($settings['weather_module_imperial_units']) && $settings['weather_module_imperial_units'];

// Weather not found!
if(!is_array($weather) || !count($weather)) return;
?>
<div class="mec-weather-details mec-frontbox" id="mec_weather_details">
    <h3 class="mec-weather mec-frontbox-title"><?php esc_html_e('Weather', 'mec'); ?></h3>

    <!-- mec weather start -->
    <div class="mec-weather-box">

        <div class="mec-weather-head">
            <div class="mec-weather-icon-box">
                <span class="mec-weather-icon <?php echo esc_attr($weather['icon']); ?>"></span>
            </div>
            <div class="mec-weather-summary">

                <?php if(isset($weather['conditions'])): ?>
                <div class="mec-weather-summary-report"><?php echo esc_html($weather['conditions']); ?></div>
                <?php endif; ?>

                <?php if(isset($weather['temp'])): ?>
                    <div class="mec-weather-summary-temp" data-c="<?php esc_html_e( ' °C', 'mec'); ?>" data-f="<?php esc_html_e( ' °F', 'mec'); ?>">
                    <?php if(!$imperial): echo round($weather['temp']); ?>
                    <var><?php esc_html_e(' °C', 'mec'); ?></var>
                    <?php else: echo esc_html($this->weather_unit_convert($weather['temp'], 'C_TO_F')); ?>
                    <var><?php esc_html_e(' °F', 'mec'); ?></var>
                    <?php endif; ?>
                    </div>
                <?php endif; ?>

            </div>
            
            <?php if(isset($settings['weather_module_change_units_button']) and $settings['weather_module_change_units_button']): ?>
            <span data-imperial="<?php esc_html_e('°Imperial', 'mec'); ?>" data-metric="<?php esc_html_e('°Metric', 'mec'); ?>" class="degrees-mode"><?php if(!$imperial) esc_html_e('°Imperial', 'mec'); else esc_html_e('°Metric', 'mec'); ?></span>
            <?php endif ?>
            
            <div class="mec-weather-extras">

                <?php if(isset($weather['windspeed'])): ?>
                <div class="mec-weather-wind" data-kph="<?php esc_html_e(' KPH', 'mec'); ?>" data-mph="<?php esc_html_e(' MPH', 'mec'); ?>"><span><?php esc_html_e('Wind', 'mec'); ?>: </span><?php if(!$imperial) echo round($weather['windspeed']); else echo esc_html($this->weather_unit_convert($weather['windspeed'], 'KM_TO_M')); ?><var><?php if(!$imperial) esc_html_e(' KPH', 'mec'); else esc_html_e(' MPH', 'mec'); ?></var></div>
                <?php endif; ?>

                <?php if(isset($weather['humidity'])): ?>
                    <div class="mec-weather-humidity"><span><?php esc_html_e('Humidity', 'mec'); ?>:</span> <?php echo round($weather['humidity']); ?><var><?php esc_html_e(' %', 'mec'); ?></var></div>
                <?php endif; ?>

                <?php if(isset($weather['visibility'])): ?>
                    <div class="mec-weather-visibility" data-kph="<?php esc_html_e(' KM', 'mec'); ?>" data-mph="<?php esc_html_e(' Miles', 'mec'); ?>"><span><?php esc_html_e('Visibility', 'mec'); ?>: </span><?php if(!$imperial) echo round($weather['visibility']); else echo esc_html($this->weather_unit_convert($weather['visibility'], 'KM_TO_M')); ?><var><?php if(!$imperial) esc_html_e(' KM', 'mec'); else esc_html_e(' Miles', 'mec'); ?></var></div>
                <?php endif; ?>
        
            </div>
        </div>

    </div><!--  mec weather end -->

</div>