<?php

use MEC\SingleBuilder\Widgets\EventOrganizers\EventOrganizers;

/** @var MEC_skin_single $this */
/** @var boolean $fes */
/** @var stdClass $event */
/** @var string $event_colorskin */
/** @var string $occurrence */
/** @var array $occurrence_full */
/** @var string $occurrence_end_date */
/** @var array $occurrence_end_full */

wp_enqueue_style('mec-lity-style');
wp_enqueue_script('mec-lity-script');

$booking_options = get_post_meta(get_the_ID(), 'mec_booking', true);
if(!is_array($booking_options)) $booking_options = [];

// Compatibility with Rank Math
$rank_math_options = '';
include_once(ABSPATH . 'wp-admin/includes/plugin.php');
if(is_plugin_active('schema-markup-rich-snippets/schema-markup-rich-snippets.php')) $rank_math_options = get_post_meta(get_the_ID(), 'rank_math_rich_snippet', true);

$bookings_limit_for_users = $booking_options['bookings_limit_for_users'] ?? 0;

$more_info = (isset($event->data->meta['mec_more_info']) and trim($event->data->meta['mec_more_info']) and $event->data->meta['mec_more_info'] != 'http://') ? $event->data->meta['mec_more_info'] : '';
if(isset($event->date) and isset($event->date['start']) and isset($event->date['start']['timestamp'])) $more_info = MEC_feature_occurrences::param($event->ID, $event->date['start']['timestamp'], 'more_info', $more_info);

$more_info_target = MEC_feature_occurrences::param($event->ID, $event->date['start']['timestamp'], 'more_info_target', $event->data->meta['mec_more_info_target'] ?? '');
if(!trim($more_info_target) && isset($settings['fes_event_link_target']) && trim($settings['fes_event_link_target'])) $more_info_target = $settings['fes_event_link_target'];

$more_info_title = MEC_feature_occurrences::param($event->ID, $event->date['start']['timestamp'], 'more_info_title', ((isset($event->data->meta['mec_more_info_title']) and trim($event->data->meta['mec_more_info_title'])) ? $event->data->meta['mec_more_info_title'] : esc_html__('Read More', 'mec')));

// Event Cost
$cost = $this->main->get_event_cost($event);

$location_id = $this->main->get_master_location_id($event);
$location = ($location_id ? $this->main->get_location_data($location_id) : array());

$organizer_id = $this->main->get_master_organizer_id($event);
$organizer = ($organizer_id ? $this->main->get_organizer_data($organizer_id) : array());

$sticky_sidebar = $settings['sticky_sidebar'] ?? '';
if($sticky_sidebar == 1) $sticky_sidebar = 'mec-sticky';

// Banner Image
$banner_module = $this->can_display_banner_module($event);
?>
<div class="mec-wrap <?php echo esc_attr($event_colorskin); ?> clearfix <?php echo esc_attr($this->html_class); ?>" id="mec_skin_<?php echo esc_attr($this->uniqueid); ?>">

    <?php if($banner_module) echo MEC_kses::element($this->display_banner_module($event, $occurrence_full, $occurrence_end_full)); ?>
	<?php do_action('mec_top_single_event', get_the_ID()); ?>
	<article class="row mec-single-event <?php echo esc_attr($sticky_sidebar); ?>">

		<!-- start breadcrumbs -->
		<?php
		$breadcrumbs_settings = $settings['breadcrumbs'] ?? '';
        if($breadcrumbs_settings == '1'): ?>
        <div class="mec-breadcrumbs">
            <?php $this->display_breadcrumb_widget(get_the_ID()); ?>
        </div>
		<?php endif; ?>
		<!-- end breadcrumbs -->

		<div class="col-md-8">
            <?php if(!$banner_module): ?>
			<div class="mec-events-event-image">
                <?php echo MEC_kses::element($this->display_image_module($event)); ?>
            </div>
            <?php endif; ?>
            <?php echo MEC_kses::full($this->main->display_progress_bar($event)); ?>
			<div class="mec-event-content">
                <?php if(!$banner_module): ?>
                    <?php echo MEC_kses::element($this->main->display_cancellation_reason($event, $this->display_cancellation_reason)); ?>
                    <h1 class="mec-single-title"><?php the_title(); ?></h1>
                <?php endif; ?>

				<div class="mec-single-event-description mec-events-content"><?php the_content(); ?></div>
                <?php echo MEC_kses::full($this->display_trailer_url($event)); ?>
                <?php echo MEC_kses::element($this->display_disclaimer($event)); ?>
			</div>

			<?php do_action('mec_single_after_content', $event); ?>

			<!-- Custom Data Fields -->
			<?php $this->display_data_fields($event); ?>

			<!-- FAQ -->
            <?php $this->display_faq($event); ?>

			<div class="mec-event-info-mobile"></div>

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
			<?php if(!empty($event->date)):
			   if($this->main->is_sold($event) and count($event->dates) <= 1): ?>
				  <?php
				  $event_id        = $event->ID;
				  $dates = (isset($event->dates) ? $event->dates : array($event->date));
				  $occurrence_time = ($dates[0]['start']['timestamp'] ?? strtotime($dates[0]['start']['date']));
				  $tickets         = get_post_meta( $event_id, 'mec_tickets', true );
				  $book         = $this->getBook();
				  $availability = $book->get_tickets_availability( $event_id, $occurrence_time );

				  $sales_end                   = 0;
                  $ticket_limit                = -1;
				  $ticket_sales_ended_messages = [];
				  $stop_selling                = '';
				  foreach ( $tickets as $ticket_id => $ticket ) {

					 $ticket_limit = $availability[$ticket_id] ?? -1;
					 $ticket_name  = isset( $ticket['name'] ) ? '<strong>' . esc_html($ticket['name']) . '</strong>' : '';

					 $key          = 'stop_selling_' . $ticket_id;
					 if ( !isset( $availability[ $key ] ) ) {

						continue;
					 }

					 if ( true === $availability[ $key ] ) {

						$sales_end++;
						$ticket_sales_ended_messages[ $ticket_id ] = sprintf( esc_html__( 'The %s ticket sales has ended!', 'mec'), $ticket_name );
					 }
				  }

				  $tickets_sales_end = false;
				  if(count($tickets) === $sales_end){

					 $tickets_sales_end = true;
				  }

				  if ( !empty( $ticket_sales_ended_messages ) ):

					 foreach ( $ticket_sales_ended_messages as $ticket_id => $message ) :

						?>
						<div id="mec-ticket-message-<?php echo esc_attr($ticket_id); ?>" class="mec-ticket-unavailable-spots mec-error <?php echo( $ticket_limit == '0' ? '' : 'mec-util-hidden' ); ?>"><div><?php echo MEC_kses::element($message); ?></div></div>
					 <?php
					 endforeach;
					 ?>

				  <?php else: ?>
					 <div id="mec-events-meta-group-booking-<?php echo esc_attr($this->uniqueid); ?>" class="mec-sold-tickets warning-msg"><?php esc_html_e( 'Sold out!', 'mec');do_action( 'mec_booking_sold_out', $event, null, null, array( $event->date ) ); ?> </div>
				  <?php endif; ?>
			<?php elseif($this->main->can_show_booking_module($event)): ?>
				<?php $data_lity_class = ''; if(isset($settings['single_booking_style']) and $settings['single_booking_style'] == 'modal' ) $data_lity_class = 'lity-hide '; ?>
				<div id="mec-events-meta-group-booking-<?php echo esc_attr($this->uniqueid); ?>" class="<?php echo esc_attr($data_lity_class); ?> mec-events-meta-group mec-events-meta-group-booking">
					<?php
					if(isset($settings['booking_user_login']) and $settings['booking_user_login'] == '1' and !is_user_logged_in() ) {
						echo do_shortcode('[MEC_login]');
					} elseif (!is_user_logged_in() and isset($booking_options['bookings_limit_for_users']) and $booking_options['bookings_limit_for_users'] == '1' ) {
						echo do_shortcode('[MEC_login]');
					} else {
						echo MEC_kses::full($this->main->module('booking.default', array('event' => $this->events, 'icons' => $this->icons)));
					}
					?>
				</div>
			<?php endif; endif; ?>

			<!-- Tags -->
			<div class="mec-events-meta-group mec-events-meta-group-tags">
                <?php echo get_the_term_list(get_the_ID(), apply_filters('mec_taxonomy_tag', ''), esc_html__('Tags: ', 'mec'), ', ', '<br />'); ?>
			</div>

		</div>

		<?php if(!is_active_sidebar('mec-single-sidebar')): ?>
			<div class="col-md-4">

				<div class="mec-event-info-desktop mec-event-meta mec-color-before mec-frontbox">
					<?php
					// Event Date and Time
					if(!$banner_module and isset($event->data->meta['mec_date']['start']) and !empty($event->data->meta['mec_date']['start']))
					{
						$this->display_datetime_widget($event, $occurrence_full, $occurrence_end_full);
					}
					?>

					<!-- Local Time Module -->
					<?php echo MEC_kses::full($this->main->module('local-time.details', array('event' => $event, 'icons' => $this->icons))); ?>

					<?php
					// Event Cost
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
					?>

					<?php do_action('mec_single_virtual_badge', $event->data); ?>
					<?php do_action('mec_single_zoom_badge', $event->data); ?>
					<?php do_action('mec_single_webex_badge', $event->data); ?>

					<?php
					// More Info
					if($more_info)
					{
						?>
						<div class="mec-event-more-info">
							<?php echo $this->icons->display('info'); ?>
							<h3 class="mec-cost"><?php echo esc_html($this->main->m('more_info_link', esc_html__('More Info', 'mec'))); ?></h3>
							<dl><dd class="mec-events-event-more-info"><a class="mec-more-info-button mec-color-hover" target="<?php echo esc_attr($more_info_target); ?>" href="<?php echo esc_url($more_info); ?>"><?php echo esc_html($more_info_title); ?></a></dd></dl>
						</div>
						<?php
					}
					?>

					<?php
					// Event labels
					if(isset($event->data->labels) && !empty($event->data->labels))
					{
                        $this->display_labels_widget($event);
					}
					?>

					<?php
					// Event Location
					if(!$banner_module and $location_id and count($location))
					{
						$this->display_location_widget($event); // Show Location Widget
						$this->show_other_locations($event); // Show Additional Locations
					}
					?>

					<?php
					// Event Categories
					if(isset($event->data->categories) and !empty($event->data->categories))
					{
						?>
						<div class="mec-single-event-category">
							<?php echo $this->icons->display('folder'); ?>
							<dt><?php echo esc_html($this->main->m('taxonomy_categories', esc_html__('Category', 'mec'))); ?></dt>
							<dl>
							<?php
							foreach($event->data->categories as $category)
							{
                                $color = ((isset($category['color']) and trim($category['color'])) ? $category['color'] : '');

                                $color_html = '';
                                if($color) $color_html .= '<span class="mec-event-category-color" style="--background-color: '.esc_attr($color).';background-color: '.esc_attr($color).'">&nbsp;</span>';

                                $icon = $category['icon'] ?? '';
                                $icon = isset($icon) && $icon != '' ? '<i class="' . esc_attr($icon) . ' mec-color"></i>' : '<i class="mec-fa-angle-right"></i>';

								echo '<dd class="mec-events-event-categories">
                                <a href="'.esc_url(get_term_link($category['id'], 'mec_category')).'" class="mec-color-hover" rel="tag">' . MEC_kses::element($icon . esc_html($category['name']) . $color_html) .'</a></dd>';
							}
							?>
							</dl>
						</div>
						<?php
					}
					?>
					<?php do_action('mec_single_event_under_category', $event); ?>
					<?php
					// Event Organizer
					if($organizer_id and count($organizer))
					{
						?>
						<div class="mec-single-event-organizer">
							<?php echo $this->icons->display('home'); ?>
                            <h3 class="mec-events-single-section-title"><?php echo esc_html($this->main->m('taxonomy_organizer', esc_html__('Organizer', 'mec'))); ?></h3>

							<?php if(isset($organizer['thumbnail']) and trim($organizer['thumbnail'])): ?>
								<img class="mec-img-organizer" src="<?php echo esc_url($organizer['thumbnail']); ?>" alt="<?php echo (isset($organizer['name']) ? esc_attr($organizer['name']) : ''); ?>">
							<?php endif; ?>
                            <dl>
							<?php if(isset($organizer['thumbnail'])): ?>
								<dd class="mec-organizer">
									<?php if( is_plugin_active('mec-advanced-organizer/mec-advanced-organizer.php') && ( $settings['advanced_organizer']['organizer_enable_link_section_title'] ?? false ) ): ?>
                                        <a href="<?php echo get_permalink( $settings['advanced_organizer']['single_page'] ).'?fesection=organizer&feparam='.$organizer['id']; ?>" target="<?php echo $settings['advanced_organizer']['organizer_link_target']; ?>">
                                            <i class="mec-sl-link"></i>
                                            <h6><?php echo (isset($organizer['name']) ? esc_html($organizer['name']) : ''); ?></h6>
                                        </a>
                                    <?php else: ?>
										<?php echo $this->icons->display('home'); ?>
                                        <h6><?php echo (isset($organizer['name']) ? esc_html($organizer['name']) : ''); ?></h6>
                                    <?php endif; ?>
                                </dd>
							<?php endif;
							if(isset($organizer['tel']) && !empty($organizer['tel'])): ?>
								<dd class="mec-organizer-tel">
									<?php echo $this->icons->display('phone'); ?>
									<h6><?php esc_html_e('Phone', 'mec'); ?></h6>
									<a href="tel:<?php echo esc_attr($organizer['tel']); ?>"><?php echo esc_html($organizer['tel']); ?></a>
								</dd>
							<?php endif;
							if(isset($organizer['email']) && !empty($organizer['email'])): ?>
								<dd class="mec-organizer-email">
									<?php echo $this->icons->display('envelope'); ?>
									<h6><?php esc_html_e('Email', 'mec'); ?></h6>
									<a href="mailto:<?php echo esc_attr($organizer['email']); ?>"><?php echo esc_html($organizer['email']); ?></a>
								</dd>
							<?php endif;
							if(isset($organizer['url']) && !empty($organizer['url']) and $organizer['url'] != 'http://'): ?>
								<dd class="mec-organizer-url">
									<?php echo $this->icons->display('sitemap'); ?>
									<h6><?php esc_html_e('Website', 'mec'); ?></h6>
                                    <span><a href="<?php echo esc_url($organizer['url']); ?>" class="mec-color-hover" target="<?php echo isset($settings['advanced_organizer']) ? $settings['advanced_organizer']['organizer_link_target'] : ''; ?>"><?php echo (isset($organizer['page_label']) and trim($organizer['page_label'])) ? esc_html($organizer['page_label']) : esc_html($organizer['url']); ?></a></span>
                                    <?php do_action('mec_single_default_organizer', $organizer); ?>
								</dd>
							<?php endif;
							$organizer_description_setting = isset( $settings['organizer_description'] ) ? $settings['organizer_description'] : ''; $organizer_terms = get_the_terms($event->data, 'mec_organizer'); if($organizer_description_setting == '1' and is_array($organizer_terms) and count($organizer_terms)): foreach($organizer_terms as $organizer_term) { if ($organizer_term->term_id == $organizer['id'] ) {  if(isset($organizer_term->description) && !empty($organizer_term->description)): ?>
								<dd class="mec-organizer-description">
									<p><?php echo esc_html($organizer_term->description); ?></p>
								</dd>
							<?php endif; } } endif; ?>
							</dl>
							<?php EventOrganizers::display_social_links( $organizer_id ); ?>
						</div>
						<?php
						$this->show_other_organizers($event); // Show Additional Organizers
					}
					?>

					<!-- Sponsors Module -->
					<?php echo MEC_kses::full($this->main->module('sponsors.details', array('event' => $event, 'icons' => $this->icons))); ?>

					<!-- Register Booking Button -->
					<?php if($this->main->can_show_booking_module($event)): ?>
						<?php $data_lity_class = ''; if(isset($settings['single_booking_style']) and $settings['single_booking_style'] == 'modal' ){ $data_lity_class = 'mec-booking-data-lity'; }  ?>
						<a class="mec-booking-button-register mec-booking-button mec-bg-color <?php echo esc_attr($data_lity_class); ?> <?php if(isset($settings['single_booking_style']) and $settings['single_booking_style'] != 'modal' ) echo 'simple-booking'; ?>" href="javascript:void(0)" data-bookingform="#mec-events-meta-group-booking-<?php echo esc_attr($this->uniqueid); ?>"><?php echo esc_html($this->main->m('register_button', esc_html__('REGISTER', 'mec'))); ?></a>
					<?php elseif($more_info and !$this->main->is_expired($event)): ?>
						<a class="mec-booking-button mec-bg-color" target="<?php echo esc_attr($more_info_target); ?>" href="<?php echo esc_url($more_info); ?>"><?php if($more_info_title) echo esc_html__($more_info_title, 'mec'); else echo esc_html($this->main->m('register_button', esc_html__('REGISTER', 'mec'))); ?></a>
					<?php endif; ?>

				</div>

				<?php do_action('mec_single_after_event_date', $event); ?>

				<!-- Speakers Module -->
				<?php echo MEC_kses::full($this->main->module('speakers.details', array('event' => $event, 'icons' => $this->icons))); ?>

				<!-- Attendees List Module -->
				<?php echo MEC_kses::full($this->main->module('attendees-list.details', array('event' => $event, 'icons' => $this->icons))); ?>

				<!-- Next Previous Module -->
				<?php echo MEC_kses::full($this->main->module('next-event.details', array('event' => $event, 'icons' => $this->icons))); ?>

				<!-- Links Module -->
				<?php echo MEC_kses::full($this->main->module('links.details', array('event' => $event, 'icons' => $this->icons))); ?>

				<!-- Weather Module -->
				<?php echo MEC_kses::full($this->main->module('weather.details', array('event' => $event, 'icons' => $this->icons))); ?>

				<!-- Google Maps Module -->
				<div class="mec-events-meta-group mec-events-meta-group-gmap">
					<?php echo MEC_kses::full($this->main->module('googlemap.details', array('event' => $this->events, 'icons' => $this->icons))); ?>
				</div>

				<!-- QRCode Module -->
				<?php echo MEC_kses::full($this->main->module('qrcode.details', array('event' => $event, 'icons' => $this->icons))); ?>

                <!-- Public Download Module -->
                <?php $this->display_public_download_module($event); ?>

				<!-- Widgets -->
				<?php dynamic_sidebar(); ?>

			</div>
		<?php else: ?>
			<div class="col-md-4">
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
                ?>
				<!-- Widgets -->
				<?php dynamic_sidebar('mec-single-sidebar'); ?>
			</div>
		<?php endif; ?>
	</article>

	<?php $this->display_related_posts_widget($event->ID); ?>
	<?php $this->display_next_previous_events($event); ?>

</div>
<?php
// MEC Schema
if($rank_math_options != 'event') do_action('mec_schema', $event);
?>
<script>
// Fix modal speaker in some themes
jQuery(".mec-speaker-avatar-dialog a, .mec-schedule-speakers a").on('click', function(e)
{
    e.preventDefault();
    lity(jQuery(this).attr('href'));

	return false;
});

jQuery(".mec-booking-button-register").on('click', function(e)
{
    if(jQuery(".mec-booking-button.mec-booking-data-lity").length>0){
        return false;
    }

    e.preventDefault();
    jQuery([document.documentElement, document.body]).animate({
        scrollTop: jQuery(jQuery(this).data('bookingform')).offset().top
    }, 300);

    jQuery([parent.document.documentElement, parent.document.body]).animate({
        scrollTop: jQuery(jQuery(this).data('bookingform')).offset().top
    }, 300);

    return false;
});

// Fix modal booking in some themes
jQuery(window).on('load', function()
{
    jQuery(".mec-booking-button.mec-booking-data-lity").on('click', function(e)
    {
        e.preventDefault();
        lity(jQuery(this).data('bookingform'));

		return false;
    });

    jQuery(".mec-booking-button-register").on('click', function(e)
    {
        if(jQuery(".mec-booking-button.mec-booking-data-lity").length>0){
            return false;
        }

        e.preventDefault();
        jQuery([document.documentElement, document.body]).animate({
            scrollTop: jQuery(jQuery(this).data('bookingform')).offset().top
        }, 300);

        jQuery([parent.document.documentElement, parent.document.body]).animate({
            scrollTop: jQuery(jQuery(this).data('bookingform')).offset().top
        }, 300);

        return false;
    });
});
</script>
