const express = require("express");
const puppeteer = require("puppeteer");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

const CONFIG = {
	APPURL: process.env["APPURL"] || `http://127.0.0.1:${port}`,
	APPFLAG: process.env["APPFLAG"] || "fake{flag}",
};
console.table(CONFIG);

const limiter = rateLimit({
	windowMs: 60 * 1000, // 1 minute
	limit: 4, // Limit each IP to 4 requests per `window` (here, per minute).
	standardHeaders: "draft-7",
	legacyHeaders: false,
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("views", __dirname + "/views");
app.use(express.static("./public"));
app.engine("html", require("ejs").renderFile);
app.set("view engine", "ejs");
app.set("trust proxy", true);

function sleep(s) {
	return new Promise((resolve) => setTimeout(resolve, s));
}

app.get("/", (req, res) => {
	res.render("index.html");
});

app.get("/admin/view", (req, res) => {
	if (req.cookies.flag === CONFIG.APPFLAG) {
		res.send(req.query.content);
	} else {
		res.send("You are not Walter White!");
	}
});

app.post("/review", limiter, async (req, res) => {
	const initBrowser = puppeteer.launch({
		executablePath: "/usr/bin/chromium-browser",
		headless: true,
		args: [
			"--disable-dev-shm-usage",
			"--no-sandbox",
			"--disable-setuid-sandbox",
			"--disable-gpu",
			"--no-gpu",
			"--disable-default-apps",
			"--disable-translate",
			"--disable-device-discovery-notifications",
			"--disable-software-rasterizer",
			"--disable-xss-auditor",
		],
		ignoreHTTPSErrors: true,
	});
	const browser = await initBrowser;
	const context = await browser.createBrowserContext();
	try {
		const content = req.body.content.replace("'", "").replace('"', "").replace("`", "");
		const urlToVisit = CONFIG.APPURL + "/admin/view/?content=" + content;

		const page = await context.newPage();
		await page.setCookie({
			name: "flag",
			httpOnly: false,
			value: CONFIG.APPFLAG,
			url: CONFIG.APPURL,
		});
		await page.goto(urlToVisit, {
			waitUntil: "networkidle2",
		});
		console.log("Visited: " + urlToVisit);
		await sleep(1000);
		// Close
		await context.close();
		console.log("Closed...");
		res.redirect("/");
	} catch (e) {
		console.error(e);
		await context.close();
		res.redirect("/");
	}
});

app.listen(port, () => {
	console.log(`Purdue winning on port ${port}`);
});
