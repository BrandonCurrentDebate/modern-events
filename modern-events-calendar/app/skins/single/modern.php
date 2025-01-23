<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_skin_single $this */
/** @var boolean $fes */
/** @var stdClass $event */
/** @var string $event_colorskin */
/** @var string $occurrence */
/** @var array $occurrence_full */
/** @var string $occurrence_end_date */
/** @var array $occurrence_end_full */

/**
 * TODO: Optimize
 */
wp_enqueue_style('mec-lity-style');
wp_enqueue_script('mec-lity-script');

$booking_options = get_post_meta(get_the_ID(), 'mec_booking', true);
if(!is_array($booking_options)) $booking_options = [];

// Compatibility with Rank Math
$rank_math_options = '';
include_once(ABSPATH . 'wp-admin/includes/plugin.php');
if(is_plugin_active('schema-markup-rich-snippets/schema-markup-rich-snippets.php')) $rank_math_options = get_post_meta(get_the_ID(), 'rank_math_rich_snippet', true);

$more_info = (isset($event->data->meta['mec_more_info']) and trim($event->data->meta['mec_more_info']) and $event->data->meta['mec_more_info'] != 'http://') ? $event->data->meta['mec_more_info'] : '';
if(isset($event->date) and isset($event->date['start']) and isset($event->date['start']['timestamp'])) $more_info = MEC_feature_occurrences::param($event->ID, $event->date['start']['timestamp'], 'more_info', $more_info);

$more_info_target = MEC_feature_occurrences::param($event->ID, $event->date['start']['timestamp'], 'more_info_target', $event->data->meta['mec_more_info_target'] ?? '');
if(!trim($more_info_target) && isset($settings['fes_event_link_target']) && trim($settings['fes_event_link_target'])) $more_info_target = $settings['fes_event_link_target'];

$more_info_title = MEC_feature_occurrences::param($event->ID, $event->date['start']['timestamp'], 'more_info_title', ((isset($event->data->meta['mec_more_info_title']) and trim($event->data->meta['mec_more_info_title'])) ? $event->data->meta['mec_more_info_title'] : esc_html__('Read More', 'mec')));

$location_id = $this->main->get_master_location_id($event);
$location = ($location_id ? $this->main->get_location_data($location_id) : array());

$organizer_id = $this->main->get_master_organizer_id($event);
$organizer = ($organizer_id ? $this->main->get_organizer_data($organizer_id) : array());

$sticky_sidebar = $settings['sticky_sidebar'] ?? '';
if($sticky_sidebar == 1) $sticky_sidebar = 'mec-sticky';

// Banner Image
$banner_module = $this->can_display_banner_module($event);

// Event Cost
$cost = $this->main->get_event_cost($event);
?>
<div class="mec-wrap <?php echo esc_attr($event_colorskin); ?> clearfix <?php echo esc_attr($this->html_class); ?>" id="mec_skin_<?php echo esc_attr($this->uniqueid); ?>">

    <?php if($banner_module) echo MEC_kses::element($this->display_banner_module($event, $occurrence_full, $occurrence_end_full)); ?>
    <?php do_action('mec_top_single_event', get_the_ID()); ?>
    <article class="row mec-single-event mec-single-modern <?php echo esc_attr($sticky_sidebar); ?>">

        <!-- start breadcrumbs -->
        <?php
        $breadcrumbs_settings = $settings['breadcrumbs'] ?? '';
        if($breadcrumbs_settings == '1'): $breadcrumbs = new MEC_skin_single(); ?>
            <div class="mec-breadcrumbs mec-breadcrumbs-modern">
                <?php $breadcrumbs->display_breadcrumb_widget(get_the_ID()); ?>
            </div>
        <?php endif; ?>
        <!-- end breadcrumbs -->

        <?php if(!$banner_module): ?>
        <div class="mec-events-event-image">
            <?php echo MEC_kses::element($this->display_image_module($event)); ?>
            <?php do_action('mec_custom_dev_image_section', $event); ?>
        </div>
        <?php endif; ?>

        <?php echo MEC_kses::full($this->main->display_progress_bar($event)); ?>

        <div class="col-md-4<?php if(empty($event->data->thumbnails['full'])) echo ' mec-no-image'; ?>">

            <?php do_action('mec_single_virtual_badge', $event->data); ?>
            <?php do_action('mec_single_zoom_badge', $event->data); ?>
            <?php do_action('mec_single_webex_badge', $event->data); ?>

            <?php if(is_active_sidebar('mec-single-sidebar')): ?>
                <?php
                    $GLOBALS['mec-widget-single'] = $this;
                    $GLOBALS['mec-widget-event'] = $event;
                    $GLOBALS['mec-widget-occurrence'] = $occurrence;
                    $GLOBALS['mec-widget-occurrence_full'] = $occurrence_full;
                    $GLOBALS['mec-widget-occurrence_end_date'] = $occurrence_end_date;
                    $GLOBALS['mec-widget-occurrence_end_full'] = $occurrence_end_full;
                    $GLOBALS['mec-widget-cost'] = $cost;
                    $GLOBALS['mec-widget-more_info'] = $more_info;
                    $GLOBALS['mec-widget-location_id'] = $location_id;
                    $GLOBALS['mec-widget-location'] = $location;
                    $GLOBALS['mec-widget-organizer_id'] = $organizer_id;
                    $GLOBALS['mec-widget-organizer'] = $organizer;
                    $GLOBALS['mec-widget-more_info_target'] = $more_info_target;
                    $GLOBALS['mec-widget-more_info_title'] = $more_info_title;
                    $GLOBALS['mec-banner_module'] = $banner_module;
                    $GLOBALS['mec-icons'] = $this->icons;

                    // Widgets
                    dynamic_sidebar('mec-single-sidebar');
                ?>
            <?php elseif(current_user_can('edit_theme_options')): ?>
            <p class="mec-widget-activation-guide"><?php echo sprintf(esc_html__('You should add MEC Single Sidebar Items to the MEC Single Sidebar in %s menu.', 'mec'), '<a href="'.esc_url(get_admin_url(NULL, 'widgets.php')).'" target="_blank">'.esc_html__('Widgets', 'mec').'</a>'); ?></p>
            <?php endif; ?>

        </div>
        <div class="col-md-8">
            <div class="mec-single-event-bar <?php if(($banner_module || !isset($event->data->meta['mec_date']['start'])) && !$cost && (!isset($event->data->labels) || !is_array($event->data->labels) || !count($event->data->labels))) echo 'mec-util-hidden'; ?>">
                <?php
                    // Event Date and Time
                    if(!$banner_module and isset($event->data->meta['mec_date']['start']) and !empty($event->data->meta['mec_date']['start']))
                    {
                        $this->display_datetime_widget($event, $occurrence_full, $occurrence_end_full);
                    }

                    if($cost)
                    {
                    ?>
                        <div class="mec-event-cost">
                            <?php echo $this->icons->display('wallet'); ?>
                            <h3 class="mec-cost"><?php echo esc_html($this->main->m('cost', esc_html__('Cost', 'mec'))); ?></h3>
                            <dl><dd class="mec-events-event-cost"><?php echo MEC_kses::element($cost); ?></dd></dl>
                        </div>
                    <?php
                    }

                    do_action('print_extra_costs', $event);

                    // Event labels
                    if(isset($event->data->labels) && !empty($event->data->labels))
                    {
                        $this->display_labels_widget($event);
                    }
                ?>
            </div>

            <div class="mec-event-content">
                <?php if(!$banner_module): ?>
                    <?php echo MEC_kses::element($this->main->display_cancellation_reason($event, $this->display_cancellation_reason)); ?>
                    <h1 class="mec-single-title"><?php the_title(); ?></h1>
                <?php endif; ?>

                <div class="mec-single-event-description mec-events-content"><?php the_content(); ?><?php do_action('mec_custom_dev_content_section', $event); ?></div>
                <?php echo MEC_kses::full($this->display_trailer_url($event)); ?>
                <?php echo MEC_kses::element($this->display_disclaimer($event)); ?>
            </div>

            <?php do_action('mec_single_after_content', $event); ?>

            <!-- Custom Data Fields -->
            <?php $this->display_data_fields($event); ?>

            <!-- FAQ -->
            <?php $this->display_faq($event); ?>

            <!-- Links Module -->
            <?php echo MEC_kses::full($this->main->module('links.details', array('event' => $event, 'icons' => $this->icons))); ?>

            <!-- Google Maps Module -->
            <div class="mec-events-meta-group mec-events-meta-group-gmap">
                <?php echo MEC_kses::full($this->main->module('googlemap.details', array('event' => $this->events, 'icons' => $this->icons))); ?>
            </div>

            <!-- Export Module -->
            <?php echo MEC_kses::full($this->main->module('export.details', array('event' => $event, 'icons' => $this->icons))); ?>

            <!-- Countdown module -->
            <?php if($this->main->can_show_countdown_module($event)): ?>
            <div class="mec-events-meta-group mec-events-meta-group-countdown">
                <?php echo MEC_kses::full($this->main->module('countdown.details', array('event' => $this->events, 'icons' => $this->icons))); ?>
            </div>
            <?php endif; ?>

            <!-- Hourly Schedule -->
            <?php $this->display_hourly_schedules_widget($event); ?>

            <?php do_action('mec_before_booking_form', get_the_ID()); ?>

			<!-- Booking Module -->
            <?php if($this->main->is_sold($event) and count($event->dates) <= 1): ?>
            <div id="mec-events-meta-group-booking-<?php echo esc_attr($this->uniqueid); ?>" class="mec-sold-tickets warning-msg"><?php esc_html_e('Sold out!', 'mec'); do_action( 'mec_booking_sold_out',$event, null,null,array($event->date) );?> </div>
            <?php elseif($this->main->can_show_booking_module($event)): ?>
            <?php $data_lity_class = ''; if(isset($settings['single_booking_style']) and $settings['single_booking_style'] == 'modal' ) $data_lity_class = 'lity-hide '; ?>
            <div class="mec-single-event <?php echo esc_attr($data_lity_class); ?>" id="mec-events-meta-group-booking-box-<?php echo esc_attr($this->uniqueid); ?>">
                <div id="mec-events-meta-group-booking-<?php echo esc_attr($this->uniqueid); ?>" class="mec-events-meta-group mec-events-meta-group-booking">
                    <?php
                        if(isset($settings['booking_user_login']) and $settings['booking_user_login'] == '1' and !is_user_logged_in()) echo do_shortcode('[MEC_login]');
                        elseif(isset($settings['booking_user_login']) and $settings['booking_user_login'] == '0' and !is_user_logged_in() and isset($booking_options['bookings_limit_for_users']) and $booking_options['bookings_limit_for_users'] == '1') echo do_shortcode('[MEC_login]');
                        else echo MEC_kses::full($this->main->module('booking.default', array('event' => $this->events, 'icons' => $this->icons)));
                    ?>
                </div>
            </div>
            <?php endif ?>

            <!-- Tags -->
            <div class="mec-events-meta-group mec-events-meta-group-tags">
                <?php echo get_the_term_list(get_the_ID(), apply_filters('mec_taxonomy_tag', ''), esc_html__('Tags: ', 'mec'), ', ', '<br />'); ?>
            </div>

        </div>
    </article>

    <?php $this->display_related_posts_widget($event->ID); ?>
    <?php $this->display_next_previous_events($event); ?>

</div>
<?php
    // MEC Schema
    if($rank_math_options != 'event') do_action('mec_schema', $event);
?>
<script>
jQuery(".mec-speaker-avatar-dialog a, .mec-schedule-speakers a").on('click', function(e)
{
    e.preventDefault();
    lity(jQuery(this).attr('href'));

    return false;
});

// Fix modal booking in some themes
jQuery(".mec-booking-button.mec-booking-data-lity").on('click', function(e)
{
    e.preventDefault();
    lity(jQuery(this).attr('href'));

    return false;
});
</script>
