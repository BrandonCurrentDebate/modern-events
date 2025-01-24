<?php
// File: /modern-events-calendar/includes/security-enhancements.php
if (!defined('ABSPATH')) exit;

class MEC_Security_Enhancements {
    public function __construct() {
        // Hook into WordPress for various security measures
        add_action('wp_loaded', [$this, 'secure_frontend_forms']);
        add_filter('wp_insert_post_data', [$this, 'sanitize_event_data'], 10, 2);
        add_action('wp_ajax_nopriv_mec_submit', [$this, 'validate_recaptcha']);
        add_filter('upload_mimes', [$this, 'restrict_upload_mime_types']);
        add_action('wp_ajax_upload_event_image', [$this, 'secure_file_upload']);
    }

    /**
     * Sanitize and Validate Event Data Before Saving
     */
    public function sanitize_event_data($data, $postarr) {
        if ($data['post_type'] === 'mec-events') {
            // Sanitize title and content
            $data['post_title'] = sanitize_text_field($data['post_title']);
            $data['post_content'] = wp_kses_post($data['post_content']);

            // Ensure metadata is also sanitized
            if (isset($postarr['mec_event_location'])) {
                $data['mec_event_location'] = sanitize_text_field($postarr['mec_event_location']);
            }
            if (isset($postarr['mec_event_organizer'])) {
                $data['mec_event_organizer'] = sanitize_text_field($postarr['mec_event_organizer']);
            }
        }
        return $data;
    }

    /**
     * Validate Google reCAPTCHA on Form Submissions
     */
    public function validate_recaptcha() {
        $recaptcha_response = sanitize_text_field($_POST['g-recaptcha-response']);
        $secret_key = 'YOUR_GOOGLE_RECAPTCHA_SECRET';
        $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', [
            'body' => [
                'secret' => $secret_key,
                'response' => $recaptcha_response,
            ],
        ]);
        $response_body = json_decode(wp_remote_retrieve_body($response), true);

        if (empty($response_body['success'])) {
            wp_send_json_error('CAPTCHA verification failed.', 400);
        }

        // Continue processing form
        wp_send_json_success('CAPTCHA verified.');
    }

    /**
     * Restrict Allowed MIME Types for Uploads
     */
    public function restrict_upload_mime_types($mime_types) {
        // Allow only images and PDFs
        return [
            'jpg|jpeg|jpe' => 'image/jpeg',
            'png'          => 'image/png',
            'gif'          => 'image/gif',
            'pdf'          => 'application/pdf',
        ];
    }

    /**
     * Secure File Upload for Event Images
     */
    public function secure_file_upload() {
        // Check user capability
        if (!current_user_can('edit_posts')) {
            wp_send_json_error('Unauthorized upload attempt.', 403);
        }

        // Check and sanitize file upload
        if (!isset($_FILES['event_image']) || empty($_FILES['event_image']['name'])) {
            wp_send_json_error('No file uploaded.', 400);
        }

        $file = $_FILES['event_image'];
        $file_name = sanitize_file_name($file['name']);
        $file_type = wp_check_filetype($file_name, null);

        // Check allowed MIME types
        $allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
        if (!in_array($file_type['type'], $allowed_mime_types, true)) {
            wp_send_json_error('Invalid file type.', 400);
        }

        // Move the uploaded file securely
        $upload = wp_handle_upload($file, ['test_form' => false]);
        if (isset($upload['error'])) {
            wp_send_json_error('File upload failed: ' . $upload['error'], 500);
        }

        // Return the uploaded file URL
        wp_send_json_success(['file_url' => esc_url($upload['url'])]);
    }

    /**
     * Sanitize and Validate Inputs for All Forms
     */
    public function secure_frontend_forms() {
        // Hook into booking and event submission forms
        add_filter('mec_booking_form_fields', [$this, 'sanitize_booking_form_inputs']);
    }

    public function sanitize_booking_form_inputs($form_data) {
        // Sanitize each field in the form data
        foreach ($form_data as $key => $value) {
            $form_data[$key] = is_array($value)
                ? array_map('sanitize_text_field', $value)
                : sanitize_text_field($value);
        }
        return $form_data;
    }
}

// Initialize the Security Enhancements
new MEC_Security_Enhancements();
