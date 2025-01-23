<?php

namespace MEC\SingleBuilder\Widgets\EventLocations;

use MEC\Base;
use MEC\SingleBuilder\Widgets\WidgetBase;
use MEC_kses;

class EventLocations extends WidgetBase {

	/**
	 *  Get HTML Output
	 *
	 * @param int $event_id
	 * @param array $atts
	 *
	 * @return string
	 */
	public function output( $event_id = 0, $atts = array() ){

		if( !$event_id ){

			$event_id = $this->get_event_id();
		}

		if(!$event_id){
			return '';
		}

		$settings = $this->settings;
		$event_detail = $this->get_event_detail($event_id);
		$locations    = isset($event_detail->data->locations) ? $event_detail->data->locations : [];
		$primary_location_id = \MEC\Base::get_main()->get_master_location_id( $event_detail );
		$location_term = get_term_by( 'id', $primary_location_id, 'mec_location' );

		$html = '';
		if ( true === $this->is_editor_mode && ( empty($locations) || !isset($locations[$primary_location_id]) ) ) {

			$html = '<div class="mec-content-notification"><p>'
					.'<span>'. esc_html__('This widget is displayed if location is set. In order for the widget in this page to be displayed correctly, please set location for your last event.', 'mec').'</span>'
					. '<a href="https://webnus.net/dox/modern-events-calendar/location/" target="_blank">' . esc_html__('How to set location', 'mec') . ' </a>'
				.'</p></div>';
		} elseif ( !empty($locations) && isset($locations[$primary_location_id]) and !empty($locations[$primary_location_id])) {

			$single        = new \MEC_skin_single();
			ob_start();
			$location = $locations[$primary_location_id];

			echo '<div class="mec-event-meta">';
				?>
				<div class="mec-single-event-location">
                    <?php echo $this->icons->display('location-pin'); ?>
                    <h3 class="mec-events-single-section-title mec-location"><?php echo Base::get_main()->m('taxonomy_location', esc_html__('Location', 'mec')); ?></h3>

					<?php if ($location['thumbnail']) : ?>
						<img class="mec-img-location" src="<?php echo esc_url($location['thumbnail']); ?>" alt="<?php echo (isset($location['name']) ? esc_attr($location['name']) : ''); ?>">
					<?php endif; ?>
                    <dd class="author fn org"><?php echo MEC_kses::element($this->get_location_html($location)); ?></dd>

					<dd class="location">
						<address class="mec-events-address"><span class="mec-address"><?php echo (isset($location['address']) ? esc_html($location['address']) : ''); ?></span></address>
					</dd>

					<?php if(isset($location['url']) and trim($location['url'])): ?>
						<dd class="mec-location-url">
							<i class="mec-sl-sitemap"></i>
							<h6><?php esc_html_e('Website', 'mec'); ?></h6>
							<span><a href="<?php echo esc_url($location['url']); ?>" class="mec-color-hover" target="<?php echo $this->settings['advanced_location']['location_link_target']; ?>"><?php echo esc_url( $location['url'] ); ?></a></span>
						</dd>
					<?php endif;

					$location_description_setting = $settings['location_description'] ?? '';
					if($location_description_setting == '1'):
						?>
						<dd class="mec-location-description">
							<p><?php echo esc_html( $location_term->description ); ?></p>
						</dd>
					<?php endif; ?>
				</div>
				<?php
				$single->show_other_locations($event_detail); // Show Additional Locations
			echo '</div>';

			$html = ob_get_clean();
		}

		return $html;
	}

    public function get_location_html($location)
    {
        $location_id = (isset($location['id']) ? $location['id'] : '');
        $location_name = (isset($location['name']) ? $location['name'] : '');


        if(is_plugin_active('mec-advanced-location/mec-advanced-location.php') && ( $this->settings['advanced_location']['location_enable_link_section_title'] ?? false )){
            $location_link = apply_filters('mec_location_single_page_link', '', $location_id, $location_name, $location);
        }else{
//          $location_link = (isset($location['url']) ? $location['url'] : '');
            return $location_name;
        }

        if(!empty($location_link)) $location_html ='<i class="mec-sl-link"></i><a href="'.esc_url($location_link).'" target="'.$this->settings['advanced_location']['location_link_target'].'">'.esc_html($location_name).'</a>';
        else $location_html = $location_name;

        return $location_html;
    }
}
