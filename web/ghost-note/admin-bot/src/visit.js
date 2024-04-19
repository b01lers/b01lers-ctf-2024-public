(async function () {
	const puppeteer = require("puppeteer");
	const config = require("./config");
	const server = require("./server");

	const sleep = (time) => new Promise((resolve) => setTimeout(resolve, time));

	const args = [
		"--js-flags=--jitless",
		"--disable-extensions-except=/app/ghostery",
		"--load-extension=/app/ghostery",
		"--no-sandbox",
	];
	const browser = await puppeteer.launch({
		headless: "new",
		pipe: true,
		dumpio: true,
		args,
	});

	// click the "Enable Ghostery" button
	const backgroundPageTarget = await browser.waitForTarget(
		(target) => target.type() === "background_page"
	);
	const backgroundPage = await backgroundPageTarget.page();
	const extensionURL = "chrome-extension://" + new URL(backgroundPage.url()).host;
	const onboardingPage = await browser.newPage();
	await onboardingPage.goto(`${extensionURL}/app/templates/onboarding.html`);
	await onboardingPage.evaluate(() =>
		document.body.querySelector('ui-button[type="success"] > a').click()
	);
	await sleep(1000);
	await onboardingPage.close();

	server.run({ subscribe: true }, async ({ message }) => {
		const { challengeId, url } = message;
		const challenge = config.challenges.get(challengeId);

		try {
			await Promise.race([
				challenge.handler(url, browser.defaultBrowserContext()),
				sleep(challenge.timeout),
			]);
		} catch (e) {
			console.error(e);
		}
		try {
			await ctx.close();
		} catch {}
	});
})();
