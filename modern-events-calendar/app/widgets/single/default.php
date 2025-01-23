<?php

use MEC\SingleBuilder\Widgets\EventOrganizers\EventOrganizers;

/** @var MEC_single_widget $this */
/** @var MEC_skin_single $single */
/** @var array $settings */
/** @var stdClass $event */
/** @var array $occurrence_full */
/** @var array $occurrence_end_full */
/** @var string $cost */
/** @var string $more_info */
/** @var string $more_info_target */
/** @var string $more_info_title */
/** @var array $location */
/** @var int $location_id */
/** @var array $organizer */
/** @var int $organizer_id */
/** @var boolean $banner_module */
/** @var MEC_icons $icons */

if($this->is_enabled('data_time') || $this->is_enabled('local_time') || $this->is_enabled('event_cost') || $this->is_enabled('more_info') || $this->is_enabled('event_label') || $this->is_enabled('event_location') || $this->is_enabled('event_categories') || $this->is_enabled('event_orgnizer') || $this->is_enabled('register_btn')): ?>
    <div class="mec-event-info-desktop mec-event-meta mec-color-before mec-frontbox">
        <?php
        // Event Date and Time
        if(!$banner_module and isset($event->data->meta['mec_date']['start']) and !empty($event->data->meta['mec_date']['start']) and $this->is_enabled('data_time'))
        {
            $single->display_datetime_widget($event, $occurrence_full, $occurrence_end_full);
        }

        // Local Time Module
        if($this->is_enabled('local_time')) echo MEC_kses::full($single->main->module('local-time.details', array('event' => $event, 'icons' => $icons)));
        ?>

        <?php
        // Event Cost
        if($cost and $this->is_enabled('event_cost'))
        {
            ?>
            <div class="mec-event-cost">
                <?php echo $icons->display('wallet'); ?>
                <h3 class="mec-cost"><?php echo esc_html($single->main->m('cost', esc_html__('Cost', 'mec'))); ?></h3>
                <dl><dd class="mec-events-event-cost"><?php echo MEC_kses::element($cost); ?></dd></dl>
            </div>
            <?php
        }
        ?>

        <?php
        // More Info
        if($more_info and $this->is_enabled('more_info'))
        {
            ?>
            <div class="mec-event-more-info">
                <?php echo $icons->display('info'); ?>
                <h3 class="mec-cost"><?php echo esc_html($single->main->m('more_info_link', esc_html__('More Info', 'mec'))); ?></h3>
                <dl><dd class="mec-events-event-more-info"><a class="mec-more-info-button mec-color-hover" target="<?php echo esc_attr($more_info_target); ?>" href="<?php echo esc_url($more_info); ?>"><?php echo esc_html($more_info_title); ?></a></dd></dl>
            </div>
            <?php
        }
        ?>

        <?php
        // Event labels
        if(isset($event->data->labels) and !empty($event->data->labels) and $this->is_enabled('event_label'))
        {
            $single->display_labels_widget($event);
        }
        ?>

        <?php do_action('mec_single_virtual_badge', $event->data ); ?>
        <?php do_action('mec_single_zoom_badge', $event->data ); ?>
        <?php do_action('mec_single_webex_badge', $event->data); ?>

        <?php
        // Event Location
        if(!$banner_module and $location_id and count($location) and $this->is_enabled('event_location'))
        {
            $single->display_location_widget($event); // Show Location Widget
            $single->show_other_locations($event); // Show Additional Locations
        }
        ?>

        <?php
        // Event Categories
        if(isset($event->data->categories) and !empty($event->data->categories) and $this->is_enabled('event_categories'))
        {
            ?>
            <div class="mec-single-event-category">
                <?php echo $icons->display('folder'); ?>
                <dt><?php echo esc_html($single->main->m('taxonomy_categories', esc_html__('Category', 'mec'))); ?></dt>
                <dl>
                <?php
                foreach($event->data->categories as $category)
                {
                    $color = ((isset($category['color']) and trim($category['color'])) ? $category['color'] : '');

                    $color_html = '';
                    if($color) $color_html .= '<span class="mec-event-category-color" style="--background-color: '.esc_attr($color).';background-color: '.esc_attr($color).'">&nbsp;</span>';

                    $icon = $category['icon'] ?? '';
                    $icon = isset($icon) && $icon != '' ? '<i class="' . esc_attr($icon) . ' mec-color"></i>' : '<i class="mec-fa-angle-right"></i>';

                    echo '<dd class="mec-events-event-categories"><a href="'.get_term_link($category['id'], 'mec_category').'" class="mec-color-hover" rel="tag">' . MEC_kses::element($icon . esc_html($category['name']) . $color_html) . '</a></dd>';
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
        if($organizer_id and count($organizer) and $this->is_enabled('event_orgnizer'))
        {
            ?>
            <div class="mec-single-event-organizer">
                <?php echo $icons->display('home'); ?>
                <h3 class="mec-events-single-section-title"><?php echo esc_html($single->main->m('taxonomy_organizer', esc_html__('Organizer', 'mec'))); ?></h3>

                <?php if(isset($organizer['thumbnail']) and trim($organizer['thumbnail'])): ?>
                    <img class="mec-img-organizer" src="<?php echo esc_url($organizer['thumbnail']); ?>" alt="<?php echo (isset($organizer['name']) ? esc_attr($organizer['name']) : ''); ?>">
                <?php endif; ?>
                <dl>
                    <?php if(isset($organizer['thumbnail'])): ?>
                        <dd class="mec-organizer">
                            <?php if( is_plugin_active('mec-advanced-organizer/mec-advanced-organizer.php') && ( $settings['advanced_organizer']['organizer_enable_link_section_title'] ?? false ) ): ?>
                                <a href="<?php echo get_permalink( $settings['advanced_organizer']['single_page'] ).'?fesection=organizer&feparam='.$organizer['id']; ?>" target="<?php echo $settings['advanced_organizer']['organizer_link_target']; ?>">
                                    <?php echo $icons->display('link'); ?>
                                    <h6><?php echo (isset($organizer['name']) ? esc_html($organizer['name']) : ''); ?></h6>
                                </a>
                            <?php else: ?>
                                <?php echo $icons->display('home'); ?>
                                <h6><?php echo (isset($organizer['name']) ? esc_html($organizer['name']) : ''); ?></h6>
                            <?php endif; ?>
                        </dd>
                    <?php endif;
                    if(isset($organizer['tel']) && !empty($organizer['tel'])): ?>
                        <dd class="mec-organizer-tel">
                            <?php echo $icons->display('phone'); ?>
                            <h6><?php esc_html_e('Phone', 'mec'); ?></h6>
                            <a href="tel:<?php echo esc_attr($organizer['tel']); ?>"><?php echo esc_html($organizer['tel']); ?></a>
                        </dd>
                    <?php endif;
                    if(isset($organizer['email']) && !empty($organizer['email'])): ?>
                        <dd class="mec-organizer-email">
                            <?php echo $icons->display('envelope'); ?>
                            <h6><?php esc_html_e('Email', 'mec'); ?></h6>
                            <a href="mailto:<?php echo esc_attr($organizer['email']); ?>"><?php echo esc_html($organizer['email']); ?></a>
                        </dd>
                    <?php endif;
                    if(isset($organizer['url']) && !empty($organizer['url'])): ?>
                        <dd class="mec-organizer-url">
                            <?php echo $icons->display('sitemap'); ?>
                            <h6><?php esc_html_e('Website', 'mec'); ?></h6>
                            <span><a href="<?php echo esc_url($organizer['url']); ?>" class="mec-color-hover" target="<?php echo $settings['advanced_organizer']['organizer_link_target']; ?>"><?php echo (isset($organizer['page_label']) and trim($organizer['page_label'])) ? esc_html($organizer['page_label']) : esc_html($organizer['url']); ?></a></span>
                            <?php do_action('mec_single_default_organizer', $organizer); ?>
                        </dd>
                    <?php endif;
                    $organizer_description_setting = isset( $settings['organizer_description'] ) ? $settings['organizer_description'] : ''; $organizer_terms = get_the_terms($event->data, 'mec_organizer'); if($organizer_description_setting == '1' and is_array($organizer_terms) and count($organizer_terms)): foreach($organizer_terms as $organizer_term) { if ($organizer_term->term_id == $organizer['id'] ) {  if(isset($organizer_term->description) && !empty($organizer_term->description)): ?>
                        <dd class="mec-organizer-description"><p><?php echo esc_html($organizer_term->description);?></p></dd>
                    <?php endif; } } endif; ?>
                </dl>
                <?php EventOrganizers::display_social_links( $organizer_id ); ?>
            </div>
            <?php
            $single->show_other_organizers($event); // Show Additional Organizers
        }
        ?>

        <!-- Register Booking Button -->
        <?php if($single->main->can_show_booking_module($event) and $this->is_enabled('register_btn')): ?>
            <?php $data_lity_class = ''; if(isset($settings['single_booking_style']) and $settings['single_booking_style'] == 'modal' ){ $data_lity_class = 'mec-booking-data-lity'; }  ?>
            <a class="mec-booking-button-register mec-booking-button mec-bg-color <?php echo esc_attr($data_lity_class); ?> <?php if(isset($settings['single_booking_style']) and $settings['single_booking_style'] != 'modal' ) echo 'simple-booking'; ?>" href="javascript:void(0)" data-bookingform="#mec-events-meta-group-booking-<?php echo esc_attr($single->uniqueid); ?>"><?php echo esc_html($single->main->m('register_button', esc_html__('REGISTER', 'mec'))); ?></a>
        <?php elseif($this->is_enabled('register_btn') == 'on' and $more_info and !$single->main->is_expired($event)): ?>
            <a class="mec-booking-button mec-bg-color" target="<?php echo esc_attr($more_info_target); ?>" href="<?php echo esc_url($more_info); ?>"><?php if($more_info_title) echo esc_html__($more_info_title, 'mec'); else echo esc_html($single->main->m('register_button', esc_html__('REGISTER', 'mec'))); ?></a>
        <?php endif; ?>
    </div>
<?php endif; ?>

<!-- Speakers Module -->
<?php if($this->is_enabled('event_speakers')) echo MEC_kses::full($single->main->module('speakers.details', array('event' => $event, 'icons' => $icons))); ?>

<!-- Sponsors Module -->
<?php if($this->is_enabled('event_sponsors')) echo MEC_kses::full($single->main->module('sponsors.details', array('event' => $event, 'icons' => $icons))); ?>

<!-- Attendees List Module -->
<?php if($this->is_enabled('attende_module')) echo MEC_kses::full($single->main->module('attendees-list.details', array('event' => $event, 'icons' => $icons))); ?>

<!-- Next Previous Module -->
<?php if($this->is_enabled('next_module')) echo MEC_kses::full($single->main->module('next-event.details', array('event' => $event, 'icons' => $icons))); ?>

<!-- Links Module -->
<?php if($this->is_enabled('links_module')) echo MEC_kses::full($single->main->module('links.details', array('event' => $event, 'icons' => $icons))); ?>

<!-- Weather Module -->
<?php if($this->is_enabled('weather_module')) echo MEC_kses::full($single->main->module('weather.details', array('event' => $event, 'icons' => $icons))); ?>

<!-- Google Maps Module -->
<?php if($this->is_enabled('google_map')): ?>
<div class="mec-events-meta-group mec-events-meta-group-gmap">
    <?php echo MEC_kses::full($single->main->module('googlemap.details', array('event' => $single->events, 'icons' => $icons))); ?>
</div>
<?php endif; ?>

<!-- QRCode Module -->
<?php if($this->is_enabled('qrcode_module')) echo MEC_kses::full($single->main->module('qrcode.details', array('event' => $event, 'icons' => $icons))); ?>

<!-- Public Download Module -->
<?php if($this->is_enabled('public_download_module')) $single->display_public_download_module($event); ?>

<!-- Custom Fields Module -->
<?php if($this->is_enabled('custom_fields_module')) $single->display_data_fields($event, true); ?>
