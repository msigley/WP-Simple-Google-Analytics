[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/A0A01FORH)
# WP Simple Google Analytics
A Google Analytics 4 implementation for Wordpress that focuses on protecting visitor privacy.

* All advertising, audience, and user personalization features are disabled.
* GA client ids are generated locally on server and stored on the visitor's web browser using a first party cookie.
* Sanitizes query vars in URLs sent to Google to Wordpress's publicly allowed query vars plus: `gclid, dclid, _gl`
* Parses the following utm query vars and sets the appropriate GA campaign values: `utm_id, utm_source, utm_medium, utm_campaign, utm_source_platform, utm_term, utm_content`
* Does not track traffic in the following situations to improve data accuracy in GA:
  * Current user can edit posts.
  * In admin area or responding to an ajax request.
  * Invalid or internal IP addresses.
  * Bot traffic detected or missing User Agent.
    * Googlebot traffic is allowed for site verification, pagespeed insights, etc.

Because of the proactive privacy features and the disabling of advertising features, GA tracking does not need to be put behind a consent banner. This further improves the data accuracy in GA.

## Configuration
Configuration is done by defining PHP constants in your /wp-config.php file. Below is an example configuration:
```php
/**
 * Google Analytics Tracking
 */
define('GOOGLE_ANALYTICS_TAG_ID', 'G-XXXXXXXXXX');
define('GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS', false);
define('GOOGLE_ANALYTICS_TRACK_BOTS', false);
define('GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS',
	serialize(
		array(
			'0.0.0.0'
		)
	)
);
```
### Configuration Options
#### GOOGLE_ANALYTICS_TAG_ID
The Google Analytics Tracking ID you wish to use for this website.

https://support.google.com/analytics/answer/9539598

#### GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS
Whether or not internal IP addresses should be tracked. Defaults to false to avoid inflating the tracking with loopback requests. You may wish to turn this on to test your site while developing locally or if you have a proxy or CDN implemented on your website.

#### GOOGLE_ANALYTICS_TRACK_BOTS
Whether or not bot traffic should be tracked. Defaults to false to avoid inflating the tracking.

#### GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS
Array of IP addresses that will never be tracked. Useful to eliminate businesses from inflating the tracking with traffic coming from themseleves. IPv4 addresses, IPv6 addresses, and IPv4 CIDR blocks are supported.

## Opt out link
A link for your users to opt out of Google Analytics tracking is required by Google Analytics' terms of service. 

https://marketingplatform.google.com/about/analytics/terms/us/

The link can be added by using the ```[google_analytics_opt_out_link]``` shortcode on your privacy policy page.
