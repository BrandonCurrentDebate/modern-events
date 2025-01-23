<?php

namespace MEC\SingleBuilder\Widgets\EventTrailerUrl;

use MEC\SingleBuilder\Widgets\WidgetBase;

class EventTrailerUrl extends WidgetBase {

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

		$single         = new \MEC_skin_single();
		$event_detail = $this->get_event_detail($event_id);

		$html = '<div class="mec-single-trailer-url">'
			. $single->display_trailer_url( $event_detail ) .
		'</div>';

		return $html;
	}
}
