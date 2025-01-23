<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_main $this */
/** @var stdClass $event */

// PRO Version is required
if(!$this->getPRO()) return;

// MEC Settings
$settings = $this->get_settings();

// The module is disabled
if(!isset($settings['weather_module_status']) || !$settings['weather_module_status']) return;

$dark_sky = (isset($settings['weather_module_api_key']) and trim($settings['weather_module_api_key'])) ? $settings['weather_module_api_key'] : '';
$visual_crossing = (isset($settings['weather_module_vs_api_key']) and trim($settings['weather_module_vs_api_key'])) ? $settings['weather_module_vs_api_key'] : '';
$weather_api = (isset($settings['weather_module_wa_api_key']) and trim($settings['weather_module_wa_api_key'])) ? $settings['weather_module_wa_api_key'] : '';

// No API key
if(!trim($dark_sky) and !trim($weather_api) and !trim($visual_crossing)) return;

// Location ID
$location_id = $this->get_master_location_id($event);

// Location is not Set
if(!$location_id) return;

// Location
$location = $this->get_location_data($location_id);

$lat = $location['latitude'] ?? 0;
$lng = $location['longitude'] ?? 0;

// Cannot find the geo point
if(!$lat or !$lng) return;

if(trim($weather_api)) include MEC::import('app.modules.weather.weatherapi', true, true);
elseif(trim($visual_crossing)) include MEC::import('app.modules.weather.visualcrossing', true, true);
elseif(trim($dark_sky)) include MEC::import('app.modules.weather.darksky', true, true);
