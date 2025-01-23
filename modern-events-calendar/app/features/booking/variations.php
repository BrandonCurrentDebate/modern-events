<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var int $event_id */
/** @var MEC_feature_books $this */

// Variations
$variations = $this->main->ticket_variations($event_id);

// No Variations
if(!is_array($variations) || !count($variations)) return '';
?>
<div class="mec-booking-ticket-variations mec-wrap">
    <ul>
        <?php foreach($variations as $variation): ?>
        <li>
            <h5><?php echo $variation['title'] ?? 'N/A'; ?></h5>
            <p><?php echo $this->main->render_price($variation['price'], $event_id); ?></p>
        </li>
        <?php endforeach; ?>
    </ul>
</div>