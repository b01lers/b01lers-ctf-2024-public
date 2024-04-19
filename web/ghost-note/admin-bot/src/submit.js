const path = require("path");
const fs = require("fs");
const mustache = require("mustache");
const FastRateLimit = require("fast-ratelimit").FastRateLimit;
const server = require("./server");
const config = require("./config");

const submitPage = fs.readFileSync(path.join(__dirname, "submit.html")).toString();
const rateLimiter = new FastRateLimit({
	threshold: 4, // available tokens over timespan
	ttl: 60, // time-to-live value of token bucket (in seconds)
});

server.run({}, async (req) => {
	const challengeId = "ghost-note";
	const challenge = config.challenges.get(challengeId);
	if (req.method === "GET") {
		const page = mustache.render(submitPage, {
			challenge_name: challenge.name,
			recaptcha_site: process.env.APP_RECAPTCHA_SITE,
			msg: req.query.msg,
			url: req.query.url,
		});
		return {
			statusCode: 200,
			headers: { "content-type": "text/html" },
			body: page,
		};
	}
	if (req.method !== "POST") {
		return { statusCode: 405 };
	}

	const body = new URLSearchParams(req.body);
	const send = (msg) => ({
		statusCode: 302,
		headers: {
			location: `?url=${encodeURIComponent(body.get("url"))}&msg=${encodeURIComponent(msg)}`,
		},
	});

	try {
		await rateLimiter.consume(req.ip);
	} catch {
		return send("Too many requests; please slow down.");
	}

	const url = body.get("url");
	const regex = challenge.urlRegex ?? /^https?:\/\//;
	if (!regex.test(url)) {
		return send(`The URL must match ${regex.source}`);
	}
	await server.publish({ challengeId, url });
	return send("The admin will visit your URL.");
});
