<?php

namespace MEC\SingleBuilder\Widgets\SimpleHeader;

use MEC\SingleBuilder\Widgets\WidgetBase;

class SimpleHeader extends WidgetBase {

	/**
	 *  Get HTML Output
	 *
	 * @param int $event_id
	 * @param array $atts
	 *
	 * @return string
	 */
	public function output( $event_id = 0, $atts = array() ){

		$html_tag = $atts['html_tag'] ?? 'h1';

		if( !$event_id ){

			$event_id = $this->get_event_id();
		}

		if(!$event_id){
			return '';
		}

		$html = '<' . $html_tag . ' class="mec-single-title">'
			.get_the_title($event_id).
		'</' . $html_tag . '>';

		return $html;
	}
}
