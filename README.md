[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/A0A01FORH)
# WP Simple Google Analytics
Simple Google Analytics implementation for Wordpress that avoids using cookies and external javascript. 

Localstorage is used instead of a tracking cookie if the browser implements it. If Localstorage is not available, a first party cookie is used.

A locally cached copy of analytics.js is printed using an inline script tag instead of referencing it externally from https://www.google-analytics.com/analytics.js. This copy of analytics.js is updated every 24 hours. If analytics.js is unable to be cached locally, it is referenced externally and marked as async to limit the affect on the site's first contentful paint time.

Google Analytics USER-ID tracking is implemented by anonymizing the wordpress user id for logged in users.

## Configuration
Configuration is done by defining PHP constants in your /wp-config.php file. Below is an example configuration:
```php
/**
 * Google Analytics Tracking
 */
define('GOOGLE_ANALYTICS_TRACKING_ID', 'UA-NNNNNNNN-N');
define('GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS', false);
define('GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS',
	serialize(
		array(
			'0.0.0.0'
		)
	)
);
```
### Configuration Options
#### GOOGLE_ANALYTICS_TRACKING_ID
The Google Analytics Tracking ID you wish to use for this website.
#### GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS
Whether or not internal IP addresses should be tracked. Defaults to false to avoid inflating the tracking with loopback requests. You may wish to turn this on to test your site while developing locally or if you have a proxy or CDN implemented on your website.
#### GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS
Array of IPv4 addresses that will never be tracked. Useful to eliminate businesses from inflating the tracking with traffic coming from themseleves.

## Opt out link
A link for your users to opt out of Google Analytics tracking is required by Google Analytics' terms of service. 

https://marketingplatform.google.com/about/analytics/terms/us/

The link can be added by using the ```[google_analytics_opt_out_link]``` shortcode on your privacy policy page.
