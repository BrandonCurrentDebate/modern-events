<?php

namespace MEC\SingleBuilder\Widgets\EventBanner;

use MEC\Base;
use MEC\SingleBuilder\Widgets\WidgetBase;
use MEC_kses;

class EventBanner extends WidgetBase {

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
		$event = $this->get_event_detail($event_id);
        $single = new \MEC_skin_single();

        $html = '';

        if ( true === $this->is_editor_mode && !$single->can_display_banner_module($event)) {
            $html = '<div class="mec-content-notification"><p>'
                .'<span>'. esc_html__('This widget is displayed if Enabled Banner is set. please set Enable Event Banner Feature for Single Event Page.', 'mec').'</span>'
                . '<a href="https://webnus.net/dox/modern-events-calendar/add-event/#Event_Banner" target="_blank">' . esc_html__('How to set Enable Event Banner Feature', 'mec') . ' </a>'
                .'</p></div>';
		} else {

            $occurrence = (isset($event->date['start']['date']) ? $event->date['start']['date'] : (isset($_GET['occurrence']) ? sanitize_text_field($_GET['occurrence']) : ''));
            $occurrence_end_date = (isset($event->date['end']['date']) ? $event->date['end']['date'] : (trim($occurrence) ? $single->main->get_end_date_by_occurrence($event->data->ID, (isset($event->date['start']['date']) ? $event->date['start']['date'] : $occurrence)) : ''));

            $occurrence_full = (isset($event->date['start']) and is_array($event->date['start'])) ? $event->date['start'] : [];
            if(!count($occurrence_full) and isset($_GET['occurrence'])) $occurrence_full = array('date' => sanitize_text_field($_GET['occurrence']));

            $occurrence_end_full = (isset($event->date['end']) and is_array($event->date['end'])) ? $event->date['end'] : [];
            if(!count($occurrence_end_full) and trim($occurrence)) $occurrence_end_full = array('date' => $single->main->get_end_date_by_occurrence($event->data->ID, $occurrence));

            ob_start();

            // Banner Options
            $banner = isset($event->data, $event->data->meta, $event->data->meta['mec_banner']) ? $event->data->meta['mec_banner'] : [];
            if(!is_array($banner)) $banner = [];

            $color = $banner['color'] ?? '';
            $image = $banner['image'] ?? '';

            $featured_image = $banner['use_featured_image'] ?? 0;

            // Force Featured Image
            if(isset($this->settings['banner_force_featured_image']) && $this->settings['banner_force_featured_image'])
            {
                $featured_image = 1;
                if(trim($color) === '') $color = '#333333';
            }

            if($featured_image) $image = (string) get_the_post_thumbnail_url($event->ID, 'full');

            $mode = 'color';
            $bg = 'background: '.$color;

            if(trim($image))
            {
                $bg = 'background: url(\''.$image.'\') no-repeat center; background-size: cover';
                $mode = trim($color) ? 'color-image' : 'image';
            }

            $location_id = $single->main->get_master_location_id($event);
            $location = $location_id ? $single->main->get_location_data($location_id) : [];

            $content = '';

            // Title
            $content .= '<div class="mec-event-banner-title">';
            $content .= MEC_kses::element($single->main->display_cancellation_reason($event, $single->display_cancellation_reason));
            $content .= '<h1 class="mec-single-title">'.get_the_title().'</h1>';
            $content .= '</div>';

            // Date & Time
            ob_start();
            $single->display_datetime_widget($event, $occurrence_full, $occurrence_end_full);
            $content .= '<div class="mec-event-banner-datetime">'.ob_get_clean().'</div>';

            // Location
            if($location_id and count($location))
            {
                ob_start();
                $single->display_location_widget($event);
                $content .= '<div class="mec-event-banner-location">'.ob_get_clean().'</div>';
            }

            echo '<div class="mec-event-banner mec-event-banner-mode-'.esc_attr($mode).'" style="'.$bg.';"> <div class="mec-event-banner-inner">'
                .$content.
                '</div>'.
                ($mode === 'color-image' ? '<div class="mec-event-banner-color" style="background: '.$color.'; opacity: 0.3;"></div>' : '').
                '</div>';

			$html = ob_get_clean();
		}

		return $html;
	}
}
