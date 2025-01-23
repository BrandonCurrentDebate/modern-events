<?php

namespace MEC\SingleBuilder\Widgets\FAQ;

use MEC\SingleBuilder\Widgets\WidgetBase;

class FAQ extends WidgetBase {

	/**
	 *  Get HTML Output
	 *
	 * @param int $event_id
	 * @param array $atts
	 *
	 * @return string
	 */
	public function output( $event_id = 0, $atts = array() ) {

		if( !$event_id ){

			$event_id = $this->get_event_id();
		}

		if(!$event_id){
			return '';
		}

		$single         = new \MEC_skin_single();
		$event_detail = $this->get_event_detail($event_id);

		ob_start();
			$single->display_faq( $event_detail );
		$faq_html = ob_get_clean();


		$html = '<div class="mec-single-faq">'
			. $faq_html .
		'</div>';

		return $html;
	}
}
