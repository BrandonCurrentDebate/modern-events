<?php

namespace MEC\SingleBuilder\Widgets\EventLabels;

use MEC\Base;
use MEC\SingleBuilder\Widgets\WidgetBase;

class EventLabels extends WidgetBase {

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
		$labels    = isset($event_detail->data->labels) ? $event_detail->data->labels : [];

		$html = '';
		ob_start();
		if ( empty($labels) && true === $this->is_editor_mode ) {

			echo '<div class="mec-content-notification"><p>'
					.'<span>'. esc_html__('This widget is displayed if label is set. In order for the widget in this page to be displayed correctly, please set label for your last event.', 'mec').'</span>'
					. '<a href="https://webnus.net/dox/modern-events-calendar/label/" target="_blank">' . esc_html__('How to set label', 'mec') . ' </a>'
				.'</p></div>';
		} elseif ( !empty($labels) ) {

			echo '<div class="mec-event-meta">';
			$mec_items = count($labels);
			$mec_i = 0; ?>
			<div class="mec-single-event-label">
				<?php if( isset( $atts['mec_labels_show_icon'] ) && $atts['mec_labels_show_icon'] ){ ?>
					<i class="mec-fa-bookmark-o"></i>
				<?php } ?>
				<?php if( isset( $atts['mec_labels_show_title'] ) && $atts['mec_labels_show_title'] ){ ?>
					<h3 class="mec-cost"><?php echo Base::get_main()->m('taxonomy_labels', esc_html__('Labels', 'mec')); ?></h3>
				<?php } ?>
				<?php foreach ($labels as $k => $label) :
					$seperator = (++$mec_i === $mec_items) ? '' : ',';
					echo '<dd style="color:' . esc_attr( $label['color'] ) . '">' . esc_html($label["name"] . $seperator) . '</dd>';
				endforeach; ?>
			</div>
			<?php
			echo '</div>';
		}
		$html = ob_get_clean();

		return $html;
	}
}
