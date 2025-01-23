<?php
/** no direct access **/
defined('MECEXEC') or die();
?>

<div class="wns-be-container wns-be-container-sticky">

    <div id="wns-be-infobar"></div>

    <div class="wns-be-sidebar">
        <?php $this->main->get_sidebar_menu('ie'); ?>
    </div>

    <div class="wns-be-main">

        <div id="wns-be-notification"></div>

        <div id="wns-be-content">
            <div class="wns-be-group-tab">
                <div class="mec-container">
                    <form id="ie-setting-form">
                        <div id="ie-options" class="mec-options-fields">
                            <h4 class="mec-form-subtitle"><?php esc_html_e('Import / Export', 'mec'); ?></h4>
                            <h5 class="mec-form-subtitle"><?php esc_html_e('Import', 'mec'); ?></h5>
                            <p><?php esc_html_e('Insert your backup files below and press import to restore your site\'s options to the last backup.', 'mec'); ?></p>
                            <p style="color:#d80000; margin-bottom: 25px;"><?php esc_html_e('WARNING! Restoring backup will overwrite all of your current option values. Caution Indeed.', 'mec'); ?></p>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <div class="mec-import-settings-wrap">
                                        <textarea class="mec-import-settings-content" placeholder="<?php esc_html_e('Please paste your options here', 'mec'); ?>"></textarea>
                                    </div>
                                </div>
                            </div>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <a class="mec-import-settings" href="#"><?php esc_html_e("Import Settings", 'mec'); ?></a>
                                </div>
                            </div>
                            <div class="mec-import-options-notification"></div>

                            <h5 class="mec-form-subtitle"><?php esc_html_e('Export', 'mec'); ?></h5>
                            <?php
                                $nonce = wp_create_nonce("mec_settings_download");
                                $export_link = admin_url('admin-ajax.php?action=download_settings&nonce='.$nonce);
                            ?>
                            <div class="mec-form-row">
                                <div class="mec-col-12">
                                    <a class="mec-export-settings" href="<?php echo esc_url($export_link); ?>"><?php esc_html_e("Download Settings", 'mec'); ?></a>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>

    </div>

</div>