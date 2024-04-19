const sleep = (time) => new Promise((resolve) => setTimeout(resolve, time));

const challenges = new Map([
	[
		"ghost-note",
		{
			name: "ghost-note",
			timeout: 10000,
			urlRegex: /^http:\/\/ghost-note.hammer\.b01le\.rs\//,
			handler: async (url, ctx) => {
				const page = await ctx.newPage();
				await page.setCookie({
					name: "flag",
					value: "bctf{mayday_mayday}",
					url: "http://ghost-note.hammer.b01le.rs/",
					httpOnly: true,
				});
				await page.goto(url, { timeout: 3000, waitUntil: "domcontentloaded" });
				await sleep(5000);
			},
		},
	],
]);

module.exports = {
	challenges,
};
